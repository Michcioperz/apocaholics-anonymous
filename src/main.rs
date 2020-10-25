use actix_web::{
    get, post,
    web::{Data, Json, Path},
    HttpResponse, Responder,
};
use deadpool_postgres::Pool;
use hmac::{Hmac, Mac, NewMac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Deserialize)]
struct HttpConfig {
    address: String,
}

#[derive(Debug, Deserialize, Clone)]
struct AuthConfig {
    magic_key: String,
}

#[derive(Debug, Deserialize)]
struct SentryConfig {
    dsn: sentry::internals::Dsn,
}

#[derive(Debug, Deserialize)]
struct Config {
    pg: deadpool_postgres::Config,
    http: HttpConfig,
    auth: Option<AuthConfig>,
    sentry: Option<SentryConfig>,
}

impl Config {
    pub fn from_env() -> Result<Self, config::ConfigError> {
        let mut cfg = config::Config::new();
        cfg.merge(config::File::with_name("apocaholics").required(false))?;
        cfg.merge(config::Environment::new())?;
        cfg.try_into()
    }
}

#[derive(thiserror::Error, Debug)]
enum MyBad {
    #[error("database pool failure")]
    DatabasePoolFailure(#[from] deadpool_postgres::PoolError),
    #[error("database failure")]
    DatabaseFailure(#[from] tokio_postgres::Error),
    #[error("provided user is not authorized in this session. ask for genuine sio2 software")]
    Unauthorized,
}

impl From<hmac::crypto_mac::MacError> for MyBad {
    fn from(_: hmac::crypto_mac::MacError) -> Self {
        Self::Unauthorized
    }
}

impl actix_web::ResponseError for MyBad {
    fn error_response(&self) -> HttpResponse {
        match *self {
            MyBad::DatabaseFailure(_) | MyBad::DatabasePoolFailure(_) => {
                HttpResponse::InternalServerError().body(format!("{}", self))
            }
            MyBad::Unauthorized => HttpResponse::Forbidden().body(format!("{}", self)),
        }
    }
}

type AppCtx = (Pool, Option<AuthConfig>);

#[get("/")]
async fn hello() -> impl Responder {
    HttpResponse::Ok().body("apocaholics anonymous v0.1.0")
}

fn authorize_user(cfg: &Option<AuthConfig>, token: &str) -> Result<String, MyBad> {
    let mut parts = token.splitn(2, ':');
    let user = parts.next().expect("splitn produced empty iterator");
    if let Some(cfg) = cfg {
        let sig = parts.next().ok_or(MyBad::Unauthorized)?;
        let sig = base64::decode_config(sig, base64::URL_SAFE).map_err(|_| MyBad::Unauthorized)?;
        let mut mac =
            HmacSha256::new_varkey(cfg.magic_key.as_bytes()).expect("HMAC didn't like key size");
        mac.update(user.as_bytes());
        mac.verify(&sig)?;
    };
    Ok(user.to_string())
}

#[derive(Debug, Deserialize)]
struct IngestElem {
    key: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct IngestData {
    user: String,
    data: Vec<IngestElem>,
}

#[post("/api/v1/ingest")]
async fn ingest(data: Json<IngestData>, ctx: Data<AppCtx>) -> Result<HttpResponse, MyBad> {
    let data = data.into_inner();
    let (db_pool, authcfg) = ctx.get_ref();
    let user = authorize_user(authcfg, &data.user)?;
    let mut client = db_pool.get().await?;
    let client = client.transaction().await?;
    let stmt = client.prepare("INSERT INTO apocalypse (username, key, value, stamp) VALUES ($1, $2, $3, NOW()) ON CONFLICT (username, key) DO UPDATE SET value = EXCLUDED.value, stamp = EXCLUDED.stamp").await?;
    for elem in data.data {
        client
            .execute(&stmt, &[&user, &elem.key, &elem.value])
            .await?;
    }
    client.commit().await?;
    Ok(HttpResponse::Created().json(()))
}

#[derive(Debug, Serialize)]
struct DumpData {
    key: String,
    value: String,
    stamp: String,
}

#[get("/api/v1/dump/{username}")]
async fn dump(username: Path<String>, ctx: Data<AppCtx>) -> Result<HttpResponse, MyBad> {
    let (db_pool, authcfg) = ctx.get_ref();
    let user = authorize_user(authcfg, &username.0)?;
    let client = db_pool.get().await?;
    let data: Vec<DumpData> = client
        .query(
            "SELECT key, value, stamp::TEXT FROM apocalypse WHERE username = $1",
            &[&user],
        )
        .await?
        .into_iter()
        .map(|row| DumpData {
            key: row.get(0),
            value: row.get(1),
            stamp: row.get(2),
        })
        .collect();
    Ok(HttpResponse::Ok().json(data))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    pretty_env_logger::init();
    better_panic::install();
    let cfg = Config::from_env().expect("failed to parse configuration");
    let _guard = {
        let mut options = sentry::ClientOptions::default();
        options.dsn = cfg.sentry.map(|o| o.dsn);
        sentry::init(options)
    };

    let pool = cfg
        .pg
        .create_pool(tokio_postgres::NoTls)
        .expect("failed to create db pool");
    {
        let _test_client = pool.get().await.expect("database pool self-test failed");
    }

    let authcfg = cfg.auth;

    actix_web::HttpServer::new(move || {
        actix_web::App::new()
            .data((pool.clone(), authcfg.clone()))
            .service(hello)
            .service(ingest)
            .service(dump)
    })
    .bind(cfg.http.address.clone())?
    .run()
    .await
}
