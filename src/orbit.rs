use crate::{
    auth::{cid_serde, Action, AuthorizationPolicy, AuthorizationToken},
    cas::ContentAddressedStorage,
    codec::SupportedCodecs,
    s3::{Service, Store},
    tz::TezosAuthorizationString,
    tz_orbit::params_to_tz_orbit,
    zcap::ZCAPTokens,
};
use anyhow::{anyhow, Result};
use ipfs_embed::{multiaddr::multiaddr, Config, Ipfs, Keypair, Multiaddr, PeerId};
use libipld::{
    cid::{
        multibase::Base,
        multihash::{Code, MultihashDigest},
        Cid,
    },
    store::DefaultParams,
};
use rocket::{
    futures::StreamExt,
    http::Status,
    request::{FromRequest, Outcome, Request},
    tokio::{fs, task::JoinHandle},
};

use cached::proc_macro::cached;
use serde::{Deserialize, Serialize};
use ssi::did::DIDURL;
use std::{
    collections::HashMap as Map, convert::TryFrom, hash::Hash, ops::Deref, path::PathBuf,
    str::FromStr, sync::Arc,
};

#[derive(Serialize, Deserialize, Clone)]
pub struct OrbitMetadata {
    // NOTE This will always serialize in b58check
    #[serde(with = "cid_serde")]
    pub id: Cid,
    pub controllers: Vec<DIDURL>,
    pub read_delegators: Vec<DIDURL>,
    pub write_delegators: Vec<DIDURL>,
    #[serde(default)]
    pub hosts: Map<PID, Vec<Multiaddr>>,
    // TODO placeholder type
    pub revocations: Vec<String>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Hash, Debug)]
#[serde(try_from = "&str", into = "String")]
pub struct PID(pub PeerId);

impl Deref for PID {
    type Target = PeerId;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<&str> for PID {
    type Error = <PeerId as FromStr>::Err;
    fn try_from(v: &str) -> Result<Self, Self::Error> {
        Ok(Self(PeerId::from_str(v)?))
    }
}

impl From<PID> for String {
    fn from(pid: PID) -> Self {
        pid.to_base58()
    }
}

#[derive(Clone)]
pub enum AuthTokens {
    Tezos(TezosAuthorizationString),
    ZCAP(ZCAPTokens),
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthTokens {
    type Error = anyhow::Error;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        if let Outcome::Success(tz) = TezosAuthorizationString::from_request(request).await {
            Outcome::Success(Self::Tezos(tz))
        } else if let Outcome::Success(zcap) = ZCAPTokens::from_request(request).await {
            Outcome::Success(Self::ZCAP(zcap))
        } else {
            Outcome::Failure((
                Status::Unauthorized,
                anyhow!("No valid authorization headers"),
            ))
        }
    }
}

impl AuthorizationToken for AuthTokens {
    fn action(&self) -> &Action {
        match self {
            Self::Tezos(token) => token.action(),
            Self::ZCAP(token) => token.action(),
        }
    }
    fn target_orbit(&self) -> &Cid {
        match self {
            Self::Tezos(token) => token.target_orbit(),
            Self::ZCAP(token) => token.target_orbit(),
        }
    }
}
#[rocket::async_trait]
impl AuthorizationPolicy<AuthTokens> for Orbit {
    async fn authorize(&self, auth_token: &AuthTokens) -> Result<()> {
        match auth_token {
            AuthTokens::Tezos(token) => self.metadata.authorize(token).await,
            AuthTokens::ZCAP(token) => self.metadata.authorize(token).await,
        }
    }
}

struct AbortOnDrop<T>(JoinHandle<T>);

impl<T> AbortOnDrop<T> {
    pub fn new(h: JoinHandle<T>) -> Self {
        Self(h)
    }
}

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl<T> Deref for AbortOnDrop<T> {
    type Target = JoinHandle<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone)]
pub struct Orbit {
    task: Arc<AbortOnDrop<()>>,
    pub service: Service,
    metadata: OrbitMetadata,
}

// Using Option to distinguish when the orbit already exists from a hard error
pub async fn create_orbit(
    oid: Cid,
    path: PathBuf,
    controllers: Vec<DIDURL>,
    auth: &[u8],
    uri: &str,
    key_pair: &Keypair,
    tzkt_api: &str,
    relay: (PeerId, Multiaddr),
    peers: Map<PID, Vec<Multiaddr>>,
) -> Result<Option<Orbit>> {
    let dir = path.join(oid.to_string_of_base(Base::Base58Btc)?);

    // fails if DIR exists, this is Create, not Open
    if dir.exists() {
        return Ok(None);
    }
    fs::create_dir(&dir)
        .await
        .map_err(|e| anyhow!("Couldn't create dir: {}", e))?;

    let (method, params) = verify_oid(&oid, uri)?;

    let md = match method {
        "tz" => params_to_tz_orbit(oid, &params, tzkt_api).await?,
        _ => OrbitMetadata {
            id: oid.clone(),
            controllers,
            read_delegators: vec![],
            write_delegators: vec![],
            revocations: vec![],
            hosts: peers,
        },
    };

    fs::write(dir.join("metadata"), serde_json::to_vec_pretty(&md)?).await?;
    fs::write(dir.join("access_log"), auth).await?;
    fs::write(dir.join("kp"), key_pair.to_bytes()).await?;

    Ok(Some(load_orbit(oid, path, relay).await.map(|o| {
        o.ok_or_else(|| anyhow!("Couldn't find newly created orbit"))
    })??))
}

pub async fn load_orbit(
    oid: Cid,
    path: PathBuf,
    relay: (PeerId, Multiaddr),
) -> Result<Option<Orbit>> {
    let dir = path.join(oid.to_string_of_base(Base::Base58Btc)?);
    if !dir.exists() {
        return Ok(None);
    }
    load_orbit_(dir, relay).await.map(|o| Some(o))
}

// Not using this function directly because cached cannot handle Result<Option<>> well.
// 100 orbits => 600 FDs
// 1min timeout to evict orbits that might have been deleted
#[cached(size = 100, time = 60, result = true)]
async fn load_orbit_(dir: PathBuf, relay: (PeerId, Multiaddr)) -> Result<Orbit> {
    let md: OrbitMetadata = serde_json::from_slice(&fs::read(dir.join("metadata")).await?)?;
    let id = md.id.to_string_of_base(Base::Base58Btc)?;
    let kp = Keypair::from_bytes(&fs::read(dir.join("kp")).await?)?;
    let db = sled::open(dir.join("s3index").with_extension("db"))?;

    let ipfs = Ipfs::<DefaultParams>::new(Config::new(&dir.join("block_store"), kp)).await?;

    // listen for any relayed messages
    ipfs.listen_on(multiaddr!(P2pCircuit))?.next().await;
    // establish a connection to the relay
    ipfs.dial_address(&relay.0, relay.1);

    for (id, addrs) in md.hosts.iter() {
        if id.0 != ipfs.local_peer_id() {
            for addr in addrs {
                ipfs.dial_address(&id.0, addr.clone());
            }
        }
    }

    let task_ipfs = ipfs.clone();
    let task = Arc::new(AbortOnDrop::new(tokio::spawn(async move {
        let mut events = task_ipfs.swarm_events();
        loop {
            match events.next().await {
                Some(ipfs_embed::Event::Discovered(p)) => {
                    tracing::debug!("dialing peer {}", p);
                    // task_ipfs.dial(&p);
                }
                None => return,
                _ => continue,
            }
        }
    })));

    let service_store = Store::new(id, ipfs, db)?;
    let service = Service::start(service_store)?;

    Ok(Orbit {
        service,
        task,
        metadata: md,
    })
}

pub fn get_params<'a>(matrix_params: &'a str) -> Map<&'a str, &'a str> {
    matrix_params
        .split(";")
        .fold(Map::new(), |mut acc, pair_str| {
            let mut ps = pair_str.split("=");
            match (ps.next(), ps.next(), ps.next()) {
                (Some(key), Some(value), None) => acc.insert(key, value),
                _ => None,
            };
            acc
        })
}

pub fn verify_oid<'a>(oid: &Cid, uri_str: &'a str) -> Result<(&'a str, Map<&'a str, &'a str>)> {
    // try to parse as a URI with matrix params
    if &Code::try_from(oid.hash().code())?.digest(uri_str.as_bytes()) == oid.hash()
        && oid.codec() == 0x55
    {
        let first_sc = uri_str.find(";").unwrap_or(uri_str.len());
        Ok((
            // method name
            uri_str
                .get(..first_sc)
                .ok_or(anyhow!("Missing Orbit Method"))?,
            // matrix parameters
            get_params(uri_str.get(first_sc..).unwrap_or("")),
        ))
    } else {
        Err(anyhow!("Failed to verify Orbit ID"))
    }
}

#[rocket::async_trait]
impl ContentAddressedStorage for Orbit {
    type Error = anyhow::Error;
    async fn put(
        &self,
        content: &[u8],
        codec: SupportedCodecs,
    ) -> Result<Cid, <Self as ContentAddressedStorage>::Error> {
        self.service.ipfs.put(content, codec).await
    }
    async fn get(
        &self,
        address: &Cid,
    ) -> Result<Option<Vec<u8>>, <Self as ContentAddressedStorage>::Error> {
        ContentAddressedStorage::get(&self.service.ipfs, address).await
    }
    async fn delete(&self, address: &Cid) -> Result<(), <Self as ContentAddressedStorage>::Error> {
        self.service.ipfs.delete(address).await
    }
    async fn list(&self) -> Result<Vec<Cid>, <Self as ContentAddressedStorage>::Error> {
        self.service.ipfs.list().await
    }
}

impl Orbit {
    pub fn id(&self) -> &Cid {
        &self.metadata.id
    }

    pub fn hosts<'a>(&'a self) -> Vec<&PeerId> {
        self.metadata.hosts.iter().map(|(id, _)| &id.0).collect()
    }

    pub fn controllers(&self) -> &[DIDURL] {
        &self.metadata.controllers
    }

    pub fn read_delegators(&self) -> &[DIDURL] {
        &self.metadata.read_delegators
    }

    pub fn write_delegators(&self) -> &[DIDURL] {
        &self.metadata.write_delegators
    }

    pub fn make_uri(&self, cid: &Cid) -> Result<String> {
        Ok(format!(
            "kepler://{}/{}",
            self.id().to_string_of_base(Base::Base58Btc)?,
            cid.to_string_of_base(Base::Base58Btc)?
        ))
    }

    // async fn update(&self, _update: Self::UpdateMessage) -> Result<(), <Self as Orbit>::Error> {
    //     todo!()
    // }
}

#[test]
async fn oid_verification() {
    let oid: Cid = "zCT5htkeBtA6Qu5YF4vPkQcfeqy3pY4m8zxGdUKUiPgtPEbY3rHy"
        .parse()
        .unwrap();
    let pkh = "tz1YSb7gXhgBw46nSXthhoSzhJdbQf9h92Gy";
    let domain = "kepler.tzprofiles.com";
    let index = 0;
    let uri = format!("tz;address={};domain={};index={}", pkh, domain, index);
    let (method, params) = verify_oid(&oid, &uri).unwrap();
    assert_eq!(method, "tz");
    assert_eq!(params.get("address"), Some(&pkh));
    assert_eq!(params.get("domain"), Some(&domain));
    assert_eq!(params.get("index"), Some(&"0"));
}
