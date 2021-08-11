use crate::cas::CidWrap;
use crate::config;
use crate::orbit::{create_orbit, load_orbit, verify_oid, AuthTokens, AuthTypes, Orbit};
use crate::tz::{TezosAuthorizationString, TezosBasicAuthorization};
use crate::zcap::ZCAPTokens;
use anyhow::Result;
use ipfs_embed::Keypair;
use libipld::cid::Cid;
use rocket::{
    http::Status,
    request::{FromRequest, Outcome, Request},
};
use serde::{Deserialize, Serialize};
use ssi::did::DIDURL;
use std::str::FromStr;

pub mod cid_serde {
    use libipld::cid::{multibase::Base, Cid};
    use serde::{de::Error as SError, ser::Error as DError, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(cid: &Cid, ser: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ser.serialize_str(
            &cid.to_string_of_base(Base::Base58Btc)
                .map_err(S::Error::custom)?,
        )
    }

    pub fn deserialize<'de, D>(deser: D) -> Result<Cid, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: &str = Deserialize::deserialize(deser)?;
        s.parse().map_err(D::Error::custom)
    }
}
pub mod vec_cid_serde {
    use libipld::cid::{
        multibase::{decode, Base},
        Cid,
    };
    use serde::{
        de::Error as SError, ser::Error as DError, ser::SerializeSeq, Deserialize, Deserializer,
        Serializer,
    };

    pub fn serialize<S>(vec: &Vec<Cid>, ser: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = ser.serialize_seq(Some(vec.len()))?;
        for cid in vec {
            seq.serialize_element(
                &cid.to_string_of_base(Base::Base58Btc)
                    .map_err(S::Error::custom)?,
            )?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D>(deser: D) -> Result<Vec<Cid>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: Vec<&str> = Deserialize::deserialize(deser)?;
        s.iter()
            .map(|sc| {
                decode(sc).map_err(D::Error::custom).and_then(|(_, bytes)| {
                    Cid::read_bytes(bytes.as_slice()).map_err(D::Error::custom)
                })
            })
            .collect()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Action {
    Put(#[serde(with = "vec_cid_serde")] Vec<Cid>),
    Get(#[serde(with = "vec_cid_serde")] Vec<Cid>),
    Del(#[serde(with = "vec_cid_serde")] Vec<Cid>),
    Create {
        parameters: String,
        #[serde(with = "vec_cid_serde")]
        content: Vec<Cid>,
    },
    List,
}

pub trait AuthorizationToken {
    fn action(&self) -> Action;
    fn target_orbit(&self) -> &Cid;
}

#[rocket::async_trait]
pub trait AuthorizationPolicy {
    type Token: AuthorizationToken;
    async fn authorize<'a>(&self, auth_token: &'a Self::Token) -> Result<()>;
}

pub struct PutAuthWrapper(pub Orbit);
pub struct GetAuthWrapper(pub Orbit);
pub struct DelAuthWrapper(pub Orbit);
pub struct CreateAuthWrapper(pub Orbit);
pub struct ListAuthWrapper(pub Orbit);

async fn extract_info<'a, T>(
    req: &'a Request<'_>,
) -> Result<(AuthTokens, config::Config, &'a Keypair, Cid), Outcome<T, anyhow::Error>> {
    let config = match req.rocket().state::<config::Config>() {
        Some(c) => c,
        None => {
            return Err(Outcome::Failure((
                Status::InternalServerError,
                anyhow!("Could not retrieve config"),
            )));
        }
    };
    let kp = match req.rocket().state::<Keypair>() {
        Some(kp) => kp,
        None => {
            return Err(Outcome::Failure((
                Status::InternalServerError,
                anyhow!("Could not retrieve key pair"),
            )))
        }
    };
    let oid: Cid = match req.param::<CidWrap>(0) {
        Some(Ok(o)) => o.0,
        _ => {
            return Err(Outcome::Failure((
                Status::InternalServerError,
                anyhow!("Could not retrieve config"),
            )));
        }
    };
    match AuthTokens::from_request(req).await {
        Outcome::Success(token) => Ok((token, config.clone(), kp, oid)),
        Outcome::Failure(e) => Err(Outcome::Failure(e)),
        Outcome::Forward(_) => Err(Outcome::Failure((
            Status::Unauthorized,
            anyhow!("No valid authorization headers"),
        ))),
    }
}

// TODO some APIs prefer to return 404 when the authentication fails to avoid leaking information about content

macro_rules! impl_fromreq {
    ($type:ident, $method:tt) => {
        #[rocket::async_trait]
        impl<'r> FromRequest<'r> for $type {
            type Error = anyhow::Error;

            async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
                let (token, config, kp, oid) = match extract_info(req).await {
                    Ok(i) => i,
                    Err(o) => return o,
                };
                match (token.action(), &oid == token.target_orbit()) {
                    (_, false) => Outcome::Failure((
                        Status::BadRequest,
                        anyhow!("Token target orbit not matching endpoint"),
                    )),
                    (Action::$method { .. }, true) => {
                        let orbit = match load_orbit(
                            *token.target_orbit(),
                            config.database.path.clone(),
                            kp,
                        )
                        .await
                        {
                            Ok(Some(o)) => o,
                            Ok(None) => {
                                return Outcome::Failure((
                                    Status::NotFound,
                                    anyhow!("No Orbit found"),
                                ))
                            }
                            Err(e) => return Outcome::Failure((Status::InternalServerError, e)),
                        };
                        match orbit.auth().authorize(token).await {
                            Ok(_) => Outcome::Success(Self(orbit)),
                            Err(e) => Outcome::Failure((Status::Unauthorized, e)),
                        }
                    }
                    _ => Outcome::Failure((
                        Status::BadRequest,
                        anyhow!("Token action not matching endpoint"),
                    )),
                }
            }
        }
    };
}

impl_fromreq!(PutAuthWrapper, Put);
impl_fromreq!(GetAuthWrapper, Get);
impl_fromreq!(DelAuthWrapper, Del);
impl_fromreq!(ListAuthWrapper, List);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for CreateAuthWrapper {
    type Error = anyhow::Error;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let (token, config, kp, oid) = match extract_info(req).await {
            Ok(i) => i,
            Err(o) => return o,
        };
        // TODO remove clone, or refactor the order of validations/actions
        match (&token.action(), &oid == token.target_orbit()) {
            (_, false) => Outcome::Failure((
                Status::BadRequest,
                anyhow!("Token target orbit not matching endpoint"),
            )),
            // Create actions dont have an existing orbit to authorize against, it's a node policy
            // TODO have policy config, for now just be very permissive :shrug:
            (Action::Create { parameters, .. }, true) => {
                let (method, params) = match verify_oid(&token.target_orbit(), &parameters) {
                    Ok(r) => r,
                    _ => {
                        return Outcome::Failure((
                            Status::BadRequest,
                            anyhow!("Incorrect Orbit ID"),
                        ))
                    }
                };
                let (controllers, auth_data, auth_type) = match &token {
                    AuthTokens::Tezos(token_tz) => {
                        match method {
                            "tz" => {}
                            _ => {
                                return Outcome::Failure((
                                    Status::BadRequest,
                                    anyhow!("Incorrect Orbit ID"),
                                ))
                            }
                        };
                        if params.get("address") != Some(&token_tz.pkh.as_str()) {
                            return Outcome::Failure((
                                Status::Unauthorized,
                                anyhow!("Incorrect PKH param"),
                            ));
                        };
                        let vm = DIDURL {
                            did: format!("did:pkh:tz:{}", &token_tz.pkh),
                            fragment: Some("TezosMethod2021".to_string()),
                            ..Default::default()
                        };
                        (
                            vec![vm],
                            match token_tz.serialize() {
                                Ok(t) => t.into(),
                                Err(_) => {
                                    return Outcome::Failure((
                                        Status::Unauthorized,
                                        anyhow!("Invalid Tz Signed String Params"),
                                    ))
                                }
                            },
                            AuthTypes::Tezos,
                        )
                    }
                    AuthTokens::ZCAP(ZCAPTokens { invocation, .. }) => {
                        let vm = match invocation.proof.as_ref().and_then(|p| {
                            p.verification_method.as_ref().map(|v| DIDURL::from_str(&v))
                        }) {
                            Some(Ok(v)) => v,
                            _ => {
                                return Outcome::Failure((
                                    Status::Unauthorized,
                                    anyhow!("Invalid Delegation Verification Method"),
                                ))
                            }
                        };
                        (
                            vec![vm],
                            match serde_json::to_vec(&invocation) {
                                Ok(t) => t,
                                Err(_) => {
                                    return Outcome::Failure((
                                        Status::Unauthorized,
                                        anyhow!("Invalid ZCAP Invocation Params"),
                                    ))
                                }
                            },
                            AuthTypes::ZCAP,
                        )
                    }
                    _ => {
                        return Outcome::Failure((
                            Status::Unauthorized,
                            anyhow!("Missing Authorization"),
                        ))
                    }
                };
                match create_orbit(
                    *token.target_orbit(),
                    config.database.path.clone(),
                    controllers,
                    &auth_data,
                    auth_type,
                    &parameters,
                    kp,
                    &config.tzkt.api,
                )
                .await
                {
                    Ok(Some(orbit)) => Outcome::Success(Self(orbit)),
                    Ok(None) => {
                        return Outcome::Failure((
                            Status::Conflict,
                            anyhow!("Orbit already exists"),
                        ))
                    }
                    Err(e) => Outcome::Failure((Status::InternalServerError, e)),
                }
            }
            _ => Outcome::Failure((
                Status::BadRequest,
                anyhow!("Token action not matching endpoint"),
            )),
        }
    }
}
