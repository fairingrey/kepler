use kepler::{app, config};
use rocket::figment::providers::{Env, Format, Serialized, Toml};

#[rocket::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init()
        .ok();
    let config = rocket::figment::Figment::from(rocket::Config::default())
        .merge(Serialized::defaults(config::Config::default()))
        .merge(Toml::file("kepler.toml").nested())
        .merge(Env::prefixed("KEPLER_").split("_").global())
        .merge(Env::prefixed("ROCKET_").global()); // That's just for easy access to ROCKET_LOG_LEVEL

    app(&config).await.unwrap().launch().await.unwrap();
}
