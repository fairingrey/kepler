use anyhow::Result;
use ipfs_embed::{generate_keypair, multiaddr::Protocol, Keypair, PeerId, ToLibp2p};
use rocket::{http::Status, State};
use std::{collections::HashMap, path::PathBuf, sync::RwLock};

use crate::allow_list::OrbitAllowList;
use crate::auth::CreateAuthWrapper;
use crate::cas::CidWrap;
use crate::config;
use crate::orbit::{create_orbit, get_metadata};
use crate::relay::RelayNode;

#[post("/")]
pub async fn open_orbit_authz(authz: CreateAuthWrapper) -> Result<String, (Status, &'static str)> {
    // create auth success, return OK
    Ok(authz.0.id().to_string())
}

#[post(
    "/al/<orbit_id>",
    format = "text/plain",
    data = "<params_str>",
    rank = 2
)]
pub async fn open_orbit_allowlist(
    orbit_id: CidWrap,
    params_str: &str,
    config: &State<config::Config>,
    relay: &State<RelayNode>,
    keys: &State<RwLock<HashMap<PeerId, Keypair>>>,
) -> Result<(), (Status, &'static str)> {
    // no auth token, use allowlist
    match (
        get_metadata(&orbit_id.0, params_str, &config.chains).await,
        config.orbits.allowlist.as_ref(),
    ) {
        (_, None) => Err((Status::InternalServerError, "Allowlist Not Configured")),
        (Ok(md), Some(list)) => match list.is_allowed(&orbit_id.0).await {
            Ok(_controllers) => {
                create_orbit(
                    &md,
                    config.database.path.clone(),
                    &[],
                    (relay.id, relay.internal()),
                    keys,
                )
                .await
                .map_err(|_| (Status::InternalServerError, "Failed to create Orbit"))?;
                Ok(())
            }
            _ => Err((Status::Unauthorized, "Orbit not allowed")),
        },
        (Err(_), _) => Err((Status::BadRequest, "Invalid Orbit Params")),
    }
}

#[options("/<_s..>")]
pub async fn cors(_s: PathBuf) -> () {
    ()
}

#[get("/relay")]
pub fn relay_addr(relay: &State<RelayNode>) -> String {
    relay
        .external()
        .with(Protocol::P2p(relay.id.into()))
        .to_string()
}

#[get("/new_id")]
pub fn open_host_key(
    s: &State<RwLock<HashMap<PeerId, Keypair>>>,
) -> Result<String, (Status, &'static str)> {
    let keypair = generate_keypair();
    let id = keypair.to_peer_id();
    s.write()
        .map_err(|_| (Status::InternalServerError, "cant read keys"))?
        .insert(id, keypair);
    Ok(id.to_base58())
}
