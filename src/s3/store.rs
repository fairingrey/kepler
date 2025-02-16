use crate::s3::{IpfsReadStream, IpfsWriteStream, Object, ObjectBuilder, Service};
use anyhow::Result;
use async_recursion::async_recursion;
use ipfs_embed::TempPin;
use libipld::{cbor::DagCborCodec, cid::Cid, DagCbor};
use rocket::{futures::future::try_join_all, tokio::io::AsyncRead};
use sled::{Batch, Db, IVec, Tree};
use std::{
    collections::BTreeMap,
    convert::{TryFrom, TryInto},
};
use tracing::{debug, error};

use super::{to_block, Block, Ipfs, KVMessage};

#[derive(DagCbor)]
struct Delta {
    // max depth
    pub priority: u64,
    pub add: Vec<Cid>,
    pub rmv: Vec<Cid>,
}

impl Delta {
    pub fn new(priority: u64, add: Vec<Cid>, rmv: Vec<Cid>) -> Self {
        Self { priority, add, rmv }
    }

    pub fn _merge(self, other: Self) -> Self {
        let mut add = self.add;
        let mut other_add = other.add;
        add.append(&mut other_add);

        let mut rmv = self.rmv;
        let mut other_rmv = other.rmv;
        rmv.append(&mut other_rmv);

        Self {
            add,
            rmv,
            priority: u64::max(self.priority, other.priority),
        }
    }
}

#[derive(DagCbor)]
struct LinkedDelta {
    // previous heads
    pub prev: Vec<Cid>,
    pub delta: Delta,
}

impl LinkedDelta {
    pub fn new(prev: Vec<Cid>, delta: Delta) -> Self {
        Self { prev, delta }
    }

    pub fn to_block(&self) -> Result<Block> {
        to_block(self)
    }
}

#[derive(Clone)]
pub struct Store {
    pub id: String,
    pub ipfs: Ipfs,
    elements: Tree,
    tombs: Tree,
    priorities: Tree,
    heads: Heads,
}

impl Store {
    pub fn new(id: String, ipfs: Ipfs, db: Db) -> Result<Self> {
        // map key to element cid
        let elements = db.open_tree("elements")?;
        // map key to element cid
        let tombs = db.open_tree("tombs")?;
        // map key to current max priority for key
        let priorities = db.open_tree("priorities")?;
        // map current DAG head cids to their priority
        let heads = Heads::new(db)?;
        Ok(Self {
            id,
            ipfs,
            elements,
            tombs,
            priorities,
            heads,
        })
    }
    pub fn list(&self) -> impl DoubleEndedIterator<Item = Result<IVec>> + Send + Sync + '_ {
        self.elements
            .iter()
            .map(|r| match r {
                Ok((key, value)) => Ok((key, Cid::try_from(value.as_ref())?)),
                Err(e) => Err(anyhow!(e)),
            })
            .filter_map(move |r| match r {
                Err(e) => Some(Err(e)),
                Ok((key, cid)) => match self.is_tombstoned(key.as_ref(), &cid) {
                    Ok(false) => Some(Ok(key)),
                    Ok(true) => None,
                    Err(e) => Some(Err(e)),
                },
            })
    }
    pub fn get<N: AsRef<[u8]>>(&self, name: N) -> Result<Option<Object>> {
        let key = name;
        match self
            .elements
            .get(&key)?
            .map(|b| Cid::try_from(b.as_ref()))
            .transpose()?
        {
            Some(cid) => {
                if !self.is_tombstoned(key.as_ref(), &cid)? {
                    Ok(Some(self.ipfs.get(&cid)?.decode()?))
                } else {
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }

    pub fn read<N>(&self, key: N) -> Result<Option<(BTreeMap<String, String>, IpfsReadStream)>>
    where
        N: AsRef<[u8]>,
    {
        let s3_obj = match self.get(key) {
            Ok(Some(content)) => content,
            _ => return Ok(None),
        };
        match self
            .ipfs
            .get(&s3_obj.value)?
            .decode::<DagCborCodec, Vec<(Cid, u32)>>()
        {
            Ok(content) => Ok(Some((
                s3_obj.metadata,
                IpfsReadStream::new(self.ipfs.clone(), content)?,
            ))),
            Err(_) => Ok(None),
        }
    }

    pub async fn write<N, R>(
        &self,
        add: impl IntoIterator<Item = (ObjectBuilder, R)>,
        remove: impl IntoIterator<Item = (N, Option<(u64, Cid)>)>,
    ) -> Result<()>
    where
        N: AsRef<[u8]>,
        R: AsyncRead + Unpin,
    {
        tracing::debug!("writing tx");
        let (indexes, _pins): (Vec<(Vec<u8>, Cid)>, Vec<TempPin>) =
            try_join_all(add.into_iter().map(|(o, r)| async {
                // tracing::debug!("adding {:#?}", &o.key);
                let (cid, pin) = IpfsWriteStream::new(&self.ipfs)?.write(r).await?;
                let obj = o.add_content(cid);
                let block = obj.to_block()?;
                self.ipfs.insert(&block)?;
                self.ipfs.temp_pin(&pin, block.cid())?;
                Ok(((obj.key, *block.cid()), pin)) as Result<((Vec<u8>, Cid), TempPin)>
            }))
            .await?
            .into_iter()
            .unzip();
        self.index(indexes, remove)
    }

    pub fn index<N, M>(
        &self,
        // tuples of (obj-data, content bytes)
        add: impl IntoIterator<Item = (N, Cid)>,
        // tuples of (key, opt (priority, obj-cid))
        remove: impl IntoIterator<Item = (M, Option<(u64, Cid)>)>,
    ) -> Result<()>
    where
        N: AsRef<[u8]>,
        M: AsRef<[u8]>,
    {
        let (heads, height) = self.heads.state()?;
        let height = if heads.is_empty() && height == 0 {
            0
        } else {
            height + 1
        };
        let adds: (Vec<(N, Cid)>, Vec<Cid>) =
            add.into_iter().map(|(key, cid)| ((key, cid), cid)).unzip();
        let rmvs: Vec<(M, Cid)> = remove
            .into_iter()
            .map(|(key, version)| {
                Ok(match version {
                    Some((_, cid)) => (key, cid),
                    None => {
                        let cid = self
                            .elements
                            .get(&key)?
                            .map(|b| Cid::try_from(b.as_ref()))
                            .transpose()?
                            .ok_or_else(|| anyhow!("Failed to find Object ID for key"))?;
                        (key, cid)
                    }
                })
            })
            .collect::<Result<Vec<(M, Cid)>>>()?;
        let delta = LinkedDelta::new(
            heads,
            Delta::new(height, adds.1, rmvs.iter().map(|(_, c)| *c).collect()),
        );
        let block = delta.to_block()?;
        // apply/pin root/update heads
        self.apply(&(block, delta), adds.0, rmvs)?;

        // broadcast
        self.broadcast_heads()?;
        Ok(())
    }

    pub(crate) fn broadcast_heads(&self) -> Result<()> {
        let (heads, height) = self.heads.state()?;
        if !heads.is_empty() {
            debug!("broadcasting {} heads at maxheight {}", heads.len(), height);
            self.ipfs
                .publish(&self.id, bincode::serialize(&KVMessage::Heads(heads))?)?;
        }
        Ok(())
    }

    fn apply<N, M>(
        &self,
        (block, delta): &(Block, LinkedDelta),
        // tuples of (obj-cid, obj)
        adds: impl IntoIterator<Item = (N, Cid)>,
        // tuples of (key, obj-cid)
        removes: impl IntoIterator<Item = (M, Cid)>,
    ) -> Result<()>
    where
        N: AsRef<[u8]>,
        M: AsRef<[u8]>,
    {
        // TODO update tables atomically with transaction
        // tombstone removed elements
        for (key, cid) in removes.into_iter() {
            self.tombs.insert(Self::get_key_id(&key, &cid), &[])?;
        }
        for (key, cid) in adds.into_iter() {
            // ensure dont double add or remove
            if self.tombs.contains_key(Self::get_key_id(&key, &cid))? {
                continue;
            };
            // current element priority
            let prio = self
                .priorities
                .get(&key)?
                .map(v2u64)
                .transpose()?
                .unwrap_or(0);
            // current element CID at key
            let curr = self
                .elements
                .get(&key)?
                .map(|b| Cid::try_from(b.as_ref()))
                .transpose()?;
            // order by priority, fall back to CID value ordering if priority equal
            if delta.delta.priority > prio
                || (delta.delta.priority == prio
                    && match curr {
                        Some(c) => c > cid,
                        _ => true,
                    })
            {
                self.elements.insert(&key, cid.to_bytes())?;
                self.priorities.insert(&key, &u642v(delta.delta.priority))?;
            }
        }
        // find redundant heads and remove them
        // add new head
        self.heads.set(vec![(*block.cid(), delta.delta.priority)])?;
        self.heads.new_head(block.cid(), delta.prev.clone())?;
        self.ipfs.alias(block.cid().to_bytes(), Some(block.cid()))?;
        self.ipfs.insert(block)?;

        Ok(())
    }

    #[async_recursion]
    pub(crate) async fn try_merge_heads(
        &self,
        heads: impl Iterator<Item = Cid> + Send + 'async_recursion,
    ) -> Result<()> {
        try_join_all(heads.map(|head| async move {
            // fetch head block check block is an event
            let delta_block = self.ipfs.fetch(&head, self.ipfs.peers()).await?;
            let delta: LinkedDelta = delta_block.decode()?;

            // recurse through unseen prevs first
            self.try_merge_heads(
                delta
                    .prev
                    .iter()
                    .filter_map(|p| {
                        self.heads
                            .get(p)
                            .map(|o| match o {
                                Some(_) => None,
                                None => Some(*p),
                            })
                            .transpose()
                    })
                    .collect::<Result<Vec<Cid>>>()?
                    .into_iter(),
            )
            .await?;

            let adds: Vec<(Vec<u8>, Cid)> =
                try_join_all(delta.delta.add.iter().map(|c| async move {
                    let obj: Object = self.ipfs.fetch(c, self.ipfs.peers()).await?.decode()?;
                    Ok((obj.key, *c)) as Result<(Vec<u8>, Cid)>
                }))
                .await?;

            let removes: Vec<(Vec<u8>, Cid)> =
                try_join_all(delta.delta.rmv.iter().map(|c| async move {
                    let obj: Object = self.ipfs.fetch(c, self.ipfs.peers()).await?.decode()?;
                    Ok((obj.key, *c)) as Result<(Vec<u8>, Cid)>
                }))
                .await?;

            self.apply(&(delta_block, delta), adds, removes)?;

            // dispatch ipfs::sync
            debug!("syncing head {}", head);
            match self.ipfs.sync(&head, self.ipfs.peers()).await {
                Ok(_) => {
                    debug!("synced head {}", head);
                    Ok(())
                }
                Err(e) => {
                    error!("failed sync head {}", e);
                    Err(anyhow!(e))
                }
            }
        }))
        .await?;
        Ok(())
    }

    pub(crate) fn request_heads(&self) -> Result<()> {
        debug!("requesting heads");
        self.ipfs
            .publish(&self.id, bincode::serialize(&KVMessage::StateReq)?)?;
        Ok(())
    }

    fn get_key_id<K: AsRef<[u8]>>(key: K, cid: &Cid) -> Vec<u8> {
        [key.as_ref(), &cid.to_bytes()].concat()
    }

    pub fn start_service(self) -> Result<Service> {
        Service::start(self)
    }

    fn is_tombstoned(&self, key: &[u8], cid: &Cid) -> Result<bool> {
        Ok(self.tombs.contains_key([key, &cid.to_bytes()].concat())?)
    }
}

#[derive(Clone)]
pub struct Heads {
    heights: Tree,
    heads: Tree,
}

impl Heads {
    pub fn new(db: Db) -> Result<Self> {
        Ok(Self {
            heights: db.open_tree("heights")?,
            heads: db.open_tree("heads")?,
        })
    }

    pub fn state(&self) -> Result<(Vec<Cid>, u64)> {
        self.heads.iter().try_fold(
            (vec![], 0),
            |(mut heads, max_height), r| -> Result<(Vec<Cid>, u64)> {
                let (head, _) = r?;
                let height = v2u64(
                    self.heights
                        .get(&head)?
                        .ok_or_else(|| anyhow!("Failed to find head height"))?,
                )?;
                heads.push(head[..].try_into()?);
                Ok((heads, u64::max(max_height, height)))
            },
        )
    }

    pub fn get(&self, head: &Cid) -> Result<Option<u64>> {
        self.heights.get(head.to_bytes())?.map(v2u64).transpose()
    }

    pub fn set(&self, heights: impl IntoIterator<Item = (Cid, u64)>) -> Result<()> {
        let mut batch = Batch::default();
        for (op, height) in heights.into_iter() {
            if !self.heights.contains_key(op.to_bytes())? {
                debug!("setting head height {} {}", op, height);
                batch.insert(op.to_bytes(), &u642v(height));
            }
        }
        self.heights.apply_batch(batch)?;
        Ok(())
    }

    pub fn new_head(&self, head: &Cid, prev: impl IntoIterator<Item = Cid>) -> Result<()> {
        let mut batch = Batch::default();
        batch.insert(head.to_bytes(), &[]);
        for p in prev {
            batch.remove(p.to_bytes());
        }
        self.heads.apply_batch(batch)?;
        Ok(())
    }
}

fn v2u64<V: AsRef<[u8]>>(v: V) -> Result<u64> {
    Ok(u64::from_be_bytes(v.as_ref().try_into()?))
}

fn u642v(n: u64) -> [u8; 8] {
    n.to_be_bytes()
}
