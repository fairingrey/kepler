use anyhow::Result;
use libipld::Cid;
use rocket::{
    data::{Data, ToByteUnit},
    form::Form,
    http::Status,
    request::{FromRequest, Outcome, Request},
    serde::json::Json,
    State,
};

use crate::auth::{DelAuthWrapper, GetAuthWrapper, ListAuthWrapper, PutAuthWrapper};
use crate::cas::{CidWrap, ContentAddressedStorage};
use crate::codec::{PutContent, SupportedCodecs};
use crate::config;
use crate::orbit::{load_orbit, Orbit};
use crate::relay::RelayNode;

pub struct IpfsApi(Cid);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for IpfsApi {
    type Error = anyhow::Error;
    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        if let Some(host) = request.headers().get_one("Host") {
            let mut domains = host.split(".");
            match (
                domains.next().map(|s| s.parse()),
                domains.next(),
                domains.next(),
            ) {
                (Some(Ok(oid)), Some("ipfs"), Some(_)) => Outcome::Success(Self(oid)),
                _ => Outcome::Forward(()),
            }
        } else {
            Outcome::Forward(())
        }
    }
}

// TODO need to check for every relevant endpoint that the orbit ID in the URL matches the one in the auth token
async fn uri_listing(orbit: Orbit) -> Result<Json<Vec<String>>, (Status, String)> {
    orbit
        .list()
        .await
        .map_err(|_| {
            (
                Status::InternalServerError,
                "Failed to list Orbit contents".to_string(),
            )
        })
        .and_then(|l| {
            l.into_iter()
                .map(|c| {
                    orbit.make_uri(&c).map_err(|_| {
                        (
                            Status::InternalServerError,
                            "Failed to serialize CID".to_string(),
                        )
                    })
                })
                .collect::<Result<Vec<String>, (Status, String)>>()
                .map(|v| Json(v))
        })
}

#[get("/")]
pub async fn list_content(
    _orbit_id: IpfsApi,
    orbit: ListAuthWrapper,
) -> Result<Json<Vec<String>>, (Status, String)> {
    uri_listing(orbit.0).await
}

#[get("/", rank = 2)]
pub async fn list_content_no_auth(
    orbit_id: IpfsApi,
    config: &State<config::Config>,
    relay: &State<RelayNode>,
) -> Result<Json<Vec<String>>, (Status, String)> {
    let orbit = match load_orbit(
        orbit_id.0,
        config.database.path.clone(),
        (relay.id, relay.internal()),
    )
    .await
    {
        Ok(Some(o)) => o,
        Ok(None) => return Err((Status::NotFound, anyhow!("Orbit not found").to_string())),
        Err(e) => return Err((Status::InternalServerError, e.to_string())),
    };
    uri_listing(orbit).await
}

#[get("/<hash>")]
pub async fn get_content(
    _orbit_id: IpfsApi,
    hash: CidWrap,
    orbit: GetAuthWrapper,
) -> Result<Option<Vec<u8>>, (Status, String)> {
    match orbit.0.get(&hash.0).await {
        Ok(Some(content)) => Ok(Some(content.to_vec())),
        Ok(None) => Ok(None),
        Err(_) => Ok(None),
    }
}

#[get("/<hash>", rank = 2)]
pub async fn get_content_no_auth(
    orbit_id: IpfsApi,
    hash: CidWrap,
    config: &State<config::Config>,
    relay: &State<RelayNode>,
) -> Result<Option<Vec<u8>>, (Status, String)> {
    let orbit = match load_orbit(
        orbit_id.0,
        config.database.path.clone(),
        (relay.id, relay.internal()),
    )
    .await
    {
        Ok(Some(o)) => o,
        Ok(None) => return Err((Status::NotFound, anyhow!("Orbit not found").to_string())),
        Err(e) => return Err((Status::InternalServerError, e.to_string())),
    };
    match orbit.get(&hash.0).await {
        Ok(Some(content)) => Ok(Some(content.to_vec())),
        Ok(None) => Ok(None),
        Err(_) => Ok(None),
    }
}

#[put("/", data = "<data>")]
pub async fn put_content(
    _orbit_id: IpfsApi,
    data: Data<'_>,
    codec: SupportedCodecs,
    orbit: PutAuthWrapper,
) -> Result<String, (Status, String)> {
    match orbit
        .0
        .put(
            &data
                .open(1u8.megabytes())
                .into_bytes()
                .await
                .map_err(|_| (Status::BadRequest, "Failed to stream content".to_string()))?,
            codec,
        )
        .await
    {
        Ok(cid) => Ok(orbit.0.make_uri(&cid).map_err(|_| {
            (
                Status::InternalServerError,
                "Failed to generate URI".to_string(),
            )
        })?),
        Err(_) => Err((
            Status::InternalServerError,
            "Failed to store content".to_string(),
        )),
    }
}

#[put("/", format = "multipart/form-data", data = "<batch>", rank = 2)]
pub async fn batch_put_content(
    _orbit_id: IpfsApi,
    orbit: PutAuthWrapper,
    batch: Form<Vec<PutContent>>,
) -> Result<String, (Status, &'static str)> {
    let mut uris = Vec::<String>::new();
    for content in batch.into_inner().into_iter() {
        uris.push(
            orbit
                .0
                .put(&content.content, content.codec)
                .await
                .map_or("".into(), |cid| {
                    orbit.0.make_uri(&cid).map_or("".into(), |s| s)
                }),
        );
    }
    Ok(uris.join("\n"))
}

#[delete("/<hash>")]
pub async fn delete_content(
    _orbit_id: IpfsApi,
    orbit: DelAuthWrapper,
    hash: CidWrap,
) -> Result<(), (Status, &'static str)> {
    Ok(orbit
        .0
        .delete(&hash.0)
        .await
        .map_err(|_| (Status::InternalServerError, "Failed to delete content"))?)
}
