use actix_web::{
    get, post,
    web::{Data, Json, Path},
    HttpResponse, Responder,
};
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
struct HttpConfig {
    address: String,
}

#[derive(Debug, Deserialize)]
struct SentryConfig {
    dsn: sentry::internals::Dsn,
}

#[derive(Debug, Deserialize)]
struct Config {
    pg: deadpool_postgres::Config,
    http: HttpConfig,
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

#[get("/")]
async fn hello() -> impl Responder {
    HttpResponse::Ok().body("apocaholics anonymous v0.1.0")
}

fn authorize_user(user: &str) -> Result<(), MyBad> {
    // TODO!!!
    Ok(())
}

#[derive(Debug, Deserialize)]
struct IngestData {
    user: String,
    key: String,
    value: String,
}

#[post("/api/v1/ingest")]
async fn ingest(data: Json<IngestData>, db_pool: Data<Pool>) -> Result<HttpResponse, MyBad> {
    let data = data.into_inner();
    authorize_user(&data.user)?;
    let client = db_pool.get().await.map_err::<MyBad, _>(Into::into)?;
    client.execute("INSERT INTO apocalypse (username, key, value, stamp) VALUES ($1, $2, $3, NOW()) ON CONFLICT (username, key) DO UPDATE SET value = EXCLUDED.value, stamp = EXCLUDED.stamp", &[&data.user, &data.key, &data.value]).await.map_err::<MyBad, _>(Into::into)?;
    Ok(HttpResponse::Created().json(()))
}

#[derive(Debug, Serialize)]
struct DumpData {
    key: String,
    value: String,
    stamp: String,
}

#[get("/api/v1/dump/{username}")]
async fn dump(username: Path<String>, db_pool: Data<Pool>) -> Result<HttpResponse, MyBad> {
    authorize_user(&username.0)?;
    let client = db_pool.get().await.map_err::<MyBad, _>(Into::into)?;
    let data: Vec<DumpData> = client
        .query(
            "SELECT key, value, stamp::TEXT FROM apocalypse WHERE username = $1",
            &[&username.0],
        )
        .await
        .map_err::<MyBad, _>(Into::into)?
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

    actix_web::HttpServer::new(move || {
        actix_web::App::new()
            .data(pool.clone())
            .service(hello)
            .service(ingest)
            .service(dump)
    })
    .bind(cfg.http.address.clone())?
    .run()
    .await
}
