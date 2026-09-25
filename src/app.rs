use crate::{
    auth, client_ip,
    config::{Config, OIDC_CALLBACK_PATH},
    galaxy,
    storage::{self, Record, Storage},
    upload::{read_small_multipart_field, write_multipart_file, UploadReadError},
};
use anyhow::{Context, Result};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    PasswordVerifier,
};
use axum::{
    extract::{ConnectInfo, DefaultBodyLimit, Form, Multipart, Path, Query, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Json, Redirect, Response},
    routing::{get, post},
    Router,
};
use base64::Engine;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use prometheus_client::{encoding::text::encode, metrics::counter::Counter, registry::Registry};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tokio::sync::{Mutex, RwLock, Semaphore};
use tokio_util::task::TaskTracker;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::{
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    timeout::TimeoutLayer,
    trace::TraceLayer,
};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<RwLock<Config>>,
    pub storage: Arc<dyn Storage>,
    pub ready: Arc<AtomicBool>,
    pub requests: Counter,
    pub registry: Arc<RwLock<Registry>>,
    pub tasks: Arc<Mutex<HashMap<String, ImportTask>>>,
    pub catalog: Arc<RwLock<Vec<Record>>>,
    pub sessions: Arc<Mutex<HashMap<String, Session>>>,
    pub oidc_pending: Arc<Mutex<HashMap<String, OidcPending>>>,
    pub upload_slots: Arc<Semaphore>,
    pub auth_slots: Arc<Semaphore>,
    pub failed_logins: Arc<Mutex<HashMap<IpAddr, VecDeque<std::time::Instant>>>>,
    pub auth_gate: Arc<RwLock<u64>>,
    pub refresh_slots: Arc<Semaphore>,
    pub publications: TaskTracker,
}

#[derive(Clone)]
pub struct Session {
    pub username: String,
    pub auth_source: String,
    pub admin: bool,
    pub namespaces: HashSet<String>,
    pub expires_at: u64,
    oidc_refresh: Option<OidcRefresh>,
    oidc_checked_at: u64,
    refresh_lock: Arc<Mutex<()>>,
}

#[derive(Clone)]
struct OidcRefresh {
    token: String,
    subject: String,
}

#[derive(Clone)]
pub struct OidcPending {
    pub verifier: String,
    pub nonce: String,
    pub return_to: Option<String>,
    pub expires_at: u64,
    pub generation: u64,
}

#[derive(Clone)]
struct CspNonce(String);

#[derive(Clone, Serialize, Deserialize)]
pub struct ImportTask {
    pub namespace: String,
    #[serde(default)]
    pub collection: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub sha256: Option<String>,
    pub state: String,
    pub finished: bool,
    pub started_at: u64,
    pub finished_at: Option<u64>,
}

async fn reconcile_tasks(
    storage: &Arc<dyn Storage>,
    catalog: &[Record],
) -> Result<HashMap<String, ImportTask>> {
    let mut loaded = Vec::new();
    for (id, bytes) in storage.tasks().await? {
        match serde_json::from_slice::<ImportTask>(&bytes) {
            Ok(mut task) => {
                let was_running = !task.finished && task.state == "running";
                if was_running {
                    let published = task
                        .collection
                        .as_deref()
                        .zip(task.version.as_deref())
                        .zip(task.sha256.as_deref())
                        .is_some_and(|((collection, version), sha256)| {
                            catalog.iter().any(|record| {
                                record.meta.namespace == task.namespace
                                    && record.meta.name == collection
                                    && record.meta.version == version
                                    && record.sha256 == sha256
                            })
                        });
                    task.state = if published { "completed" } else { "failed" }.into();
                    task.finished = true;
                    task.finished_at = Some(now());
                    storage.put_task(&id, &serde_json::to_vec(&task)?).await?;
                }
                loaded.push((id, task));
            }
            Err(error) => tracing::warn!(%id, error=%error, "ignoring invalid import task"),
        }
    }
    loaded.sort_by_key(|(_, task)| std::cmp::Reverse(task.started_at));
    loaded.truncate(4096);
    Ok(loaded.into_iter().collect())
}

pub async fn run(config_path: PathBuf) -> Result<()> {
    let cfg = Config::load(&config_path)?;
    let storage = storage::build(&cfg.storage).await?;
    let catalog = storage.records().await?;
    if let Err(error) = storage.reconcile(&catalog).await {
        tracing::warn!(error=%error, "storage reconciliation failed");
    }
    let tasks = reconcile_tasks(&storage, &catalog).await?;
    let ready = Arc::new(AtomicBool::new(storage.ready().await));
    tracing::info!(config=%config_path.display(), "starting galaxyd");
    let mut registry = Registry::default();
    let requests = Counter::default();
    registry.register("http_requests", "HTTP requests", requests.clone());
    let state = AppState {
        config: Arc::new(RwLock::new(cfg)),
        storage,
        ready: ready.clone(),
        requests,
        registry: Arc::new(RwLock::new(registry)),
        tasks: Arc::new(Mutex::new(tasks)),
        catalog: Arc::new(RwLock::new(catalog)),
        sessions: Arc::new(Mutex::new(HashMap::new())),
        oidc_pending: Arc::new(Mutex::new(HashMap::new())),
        upload_slots: Arc::new(Semaphore::new(2)),
        auth_slots: Arc::new(Semaphore::new(16)),
        failed_logins: Arc::new(Mutex::new(HashMap::new())),
        auth_gate: Arc::new(RwLock::new(0)),
        refresh_slots: Arc::new(Semaphore::new(8)),
        publications: TaskTracker::new(),
    };
    let readiness = state.ready.clone();
    let readiness_storage = state.storage.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
        loop {
            interval.tick().await;
            let is_ready =
                tokio::time::timeout(std::time::Duration::from_secs(5), readiness_storage.ready())
                    .await
                    .unwrap_or(false);
            readiness.store(is_ready, Ordering::Relaxed);
        }
    });
    let ui_enabled = state.config.read().await.server.ui_enabled;
    let max_upload_bytes = state.config.read().await.network.max_upload_bytes;
    let public = public_router(state.clone(), ui_enabled, max_upload_bytes);
    let observability = observability_router(state.clone());
    let public_listener =
        tokio::net::TcpListener::bind(state.config.read().await.server.listen).await?;
    let obs_listener =
        tokio::net::TcpListener::bind(state.config.read().await.server.observability_listen)
            .await?;
    tracing::info!(public=%public_listener.local_addr()?, observability=%obs_listener.local_addr()?, ready=%ready.load(Ordering::Relaxed), "listeners ready");
    let reload_state = state.clone();
    let reload_path = config_path.clone();
    tokio::spawn(async move {
        let mut sig =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).expect("SIGHUP");
        while sig.recv().await.is_some() {
            match Config::load(&reload_path) {
                Ok(new) => match apply_reload(&reload_state, new).await {
                    Ok(()) => tracing::info!("configuration reloaded"),
                    Err(error) => tracing::error!(%error, "configuration reload rejected"),
                },
                Err(e) => tracing::error!(error=%e, "configuration reload failed"),
            }
        }
    });
    let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);
    let mut public_shutdown = shutdown_tx.subscribe();
    let mut observability_shutdown = shutdown_tx.subscribe();
    let signal_tx = shutdown_tx.clone();
    tokio::spawn(async move {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("SIGTERM");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = terminate.recv() => {},
        }
        let _ = signal_tx.send(());
    });
    let result = tokio::try_join!(
        axum::serve(
            public_listener,
            public.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = public_shutdown.recv().await;
        }),
        axum::serve(obs_listener, observability).with_graceful_shutdown(async move {
            let _ = observability_shutdown.recv().await;
        })
    );
    state.publications.close();
    state.publications.wait().await;
    result?;
    Ok(())
}

async fn apply_reload(state: &AppState, new: Config) -> Result<()> {
    let mut generation = state.auth_gate.write().await;
    let old = state.config.read().await.clone();
    if new.server.listen != old.server.listen
        || new.server.observability_listen != old.server.observability_listen
        || new.storage != old.storage
        || new.token_dir != old.token_dir
        || new.server.public_url != old.server.public_url
        || new.network.max_upload_bytes != old.network.max_upload_bytes
    {
        anyhow::bail!(
            "listener, public_url, storage, token_dir, or upload-limit changes require restart"
        )
    }
    *state.config.write().await = new;
    *generation = generation.wrapping_add(1);
    state.sessions.lock().await.clear();
    state.oidc_pending.lock().await.clear();
    Ok(())
}

pub fn public_router(state: AppState, ui_enabled: bool, max_upload_bytes: usize) -> Router {
    let router = Router::new()
        .route("/api/galaxy/", get(discovery))
        .route(
            "/api/galaxy/v3/artifacts/collections/",
            post(upload).layer(DefaultBodyLimit::max(
                max_upload_bytes
                    .saturating_mul(2)
                    .saturating_add(1024 * 1024),
            )),
        )
        .route(
            "/api/galaxy/v3/artifacts/{namespace}/{name}/{version}/",
            get(download),
        )
        .route("/api/galaxy/v3/collections", get(list_collections))
        .route("/api/galaxy/v3/collections/", get(list_collections))
        .route("/api/galaxy/v3/namespaces", get(list_namespaces))
        .route("/api/galaxy/v3/namespaces/", get(list_namespaces))
        .route(
            "/api/galaxy/v3/imports/collections/{task_id}/",
            get(task_status),
        )
        .route(
            "/api/galaxy/v3/collections/{namespace}/{name}/",
            get(collection),
        )
        .route(
            "/api/galaxy/v3/collections/{namespace}/{name}/versions/",
            get(collection_versions),
        )
        .route(
            "/api/galaxy/v3/collections/{namespace}/{name}/versions/{version}/",
            get(collection_version),
        )
        .route("/", get(ui));
    let router = router
        .route("/auth/status", get(auth_status))
        .route("/auth/logout", post(logout))
        .route(
            "/auth/local/login",
            get(local_login)
                .post(local_login_submit)
                .layer(DefaultBodyLimit::max(16 * 1024)),
        )
        .route("/auth/oidc/login", get(oidc_login))
        .route(OIDC_CALLBACK_PATH, get(oidc_callback));
    let _ = ui_enabled;
    router
        .layer(ConcurrencyLimitLayer::new(8))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            std::time::Duration::from_secs(60),
        ))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .layer(middleware::from_fn_with_state(state.clone(), count_request))
        .layer(middleware::from_fn(server_header))
        .layer(middleware::from_fn(no_store))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn no_store(request: axum::extract::Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}
fn observability_router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .layer(middleware::from_fn(server_header))
        .layer(middleware::from_fn(no_store))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn server_header(mut request: axum::extract::Request, next: Next) -> Response {
    let nonce = uuid::Uuid::new_v4().simple().to_string();
    request.extensions_mut().insert(CspNonce(nonce.clone()));
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        "server",
        axum::http::HeaderValue::from_static(concat!("galaxyd/", env!("CARGO_PKG_VERSION"))),
    );
    response.headers_mut().insert(
        "x-content-type-options",
        axum::http::HeaderValue::from_static("nosniff"),
    );
    let policy = format!(
        "default-src 'self'; script-src 'self' 'nonce-{nonce}'; style-src 'self' 'nonce-{nonce}'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    );
    if let Ok(value) = axum::http::HeaderValue::from_str(&policy) {
        response
            .headers_mut()
            .insert("content-security-policy", value);
    }
    response
}

async fn count_request(
    State(state): State<AppState>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    state.requests.inc();
    next.run(request).await
}

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
    return_to: Option<String>,
}

#[derive(Deserialize, Default)]
struct ReturnToQuery {
    return_to: Option<String>,
}

#[derive(Deserialize, Default)]
struct UiQuery {
    namespace: Option<String>,
    collection: Option<String>,
}

#[derive(Deserialize)]
struct OidcQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

async fn auth_status(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let cfg = state.config.read().await.clone();
    if !cfg.auth.enabled {
        return Json(serde_json::json!({"enabled":false,"authenticated":false})).into_response();
    }
    match session_from_headers(&state, &headers).await {
        Ok(Some((_, session))) => Json(
            serde_json::json!({"enabled":true,"authenticated":true,"username":session.username,"auth_source":session.auth_source,"admin":session.admin,"namespaces":session.namespaces}),
        ).into_response(),
        Ok(None) => Json(
            serde_json::json!({"enabled":true,"authenticated":false,"local":cfg.auth.local.enabled,"oidc":cfg.auth.oidc.enabled}),
        ).into_response(),
        Err(status) => status.into_response(),
    }
}

async fn local_login(
    State(state): State<AppState>,
    axum::Extension(nonce): axum::Extension<CspNonce>,
    Query(query): Query<ReturnToQuery>,
) -> Response {
    let cfg = state.config.read().await.clone();
    if !cfg.auth.local.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    Html(login_page(
        &cfg,
        "",
        None,
        query.return_to.as_deref(),
        &nonce.0,
    ))
    .into_response()
}

fn login_page(
    cfg: &Config,
    username: &str,
    error: Option<&str>,
    return_to: Option<&str>,
    nonce: &str,
) -> String {
    let return_to = safe_return_to(return_to);
    let hidden_return_to = return_to
        .as_deref()
        .map(|value| {
            format!(
                r#"<input type="hidden" name="return_to" value="{}">"#,
                html_escape(value)
            )
        })
        .unwrap_or_default();
    let oidc = if cfg.auth.oidc.enabled {
        let display_name = html_escape(&cfg.auth.oidc.display_name);
        let oidc_href = return_to
            .as_deref()
            .map(|value| {
                let encoded = url::form_urlencoded::Serializer::new(String::new())
                    .append_pair("return_to", value)
                    .finish();
                format!("/auth/oidc/login?{encoded}")
            })
            .unwrap_or_else(|| "/auth/oidc/login".into());
        format!(
            r#"<div class="divider">or</div><a class="oidc" href="{oidc_href}">Login via {display_name}</a>"#
        )
    } else {
        String::new()
    };
    let error = error
        .map(|message| {
            format!(
                r#"<div class="error" role="alert">{}</div>"#,
                html_escape(message)
            )
        })
        .unwrap_or_default();
    include_str!("../static/login.html")
        .replace("<!-- OIDC_OPTION -->", &oidc)
        .replace("<!-- LOGIN_ERROR -->", &error)
        .replace("<!-- RETURN_TO -->", &hidden_return_to)
        .replace("<!-- USERNAME -->", &html_escape(username))
        .replace("<!-- CSP_NONCE -->", nonce)
}

fn safe_return_to(value: Option<&str>) -> Option<String> {
    let value = value?.trim();
    if value.starts_with('/')
        && !value.starts_with("//")
        && !value.contains('\\')
        && !value.chars().any(char::is_control)
    {
        Some(value.to_owned())
    } else {
        None
    }
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

async fn local_login_submit(
    State(state): State<AppState>,
    axum::Extension(nonce): axum::Extension<CspNonce>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let auth_slot = match state.auth_slots.clone().try_acquire_owned() {
        Ok(slot) => slot,
        Err(_) => return StatusCode::TOO_MANY_REQUESTS.into_response(),
    };
    let generation = *state.auth_gate.read().await;
    let cfg = state.config.read().await.clone();
    if !cfg.auth.local.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    if !same_origin(&headers, &cfg) {
        tracing::warn!(origin=?headers.get(axum::http::header::ORIGIN), expected=%cfg.server.public_url, "local login rejected: origin mismatch");
        return StatusCode::FORBIDDEN.into_response();
    }
    let ip = log_ip(peer, &headers, &cfg);
    let client_ip = client_ip::effective_ip(
        peer.ip(),
        single_forwarded_for(&headers).ok().flatten(),
        &cfg.network.set_real_ip_from,
        cfg.network.max_forwarded_for_hops,
    )
    .unwrap_or(peer.ip());
    if login_limited(&state, client_ip).await {
        tracing::warn!(ip=%client_ip, "local login rate limited");
        return (StatusCode::TOO_MANY_REQUESTS, [("retry-after", "600")]).into_response();
    }
    if form.username.len() > 256 || form.password.len() > 4096 {
        record_login_failure(&state, client_ip).await;
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let users_file = cfg.auth.local.users_file.clone();
    let username = form.username.clone();
    let password = form.password.clone();
    let valid = match tokio::task::spawn_blocking(move || {
        let _auth_slot = auth_slot;
        verify_local_password(&users_file, &username, &password)
    })
    .await
    {
        Ok(Ok(valid)) => valid,
        Ok(Err(error)) => {
            tracing::error!(error=%error, "local login unavailable: users file or password hash");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        Err(error) => {
            tracing::error!(error=%error, "password verification task failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    if !valid {
        record_login_failure(&state, client_ip).await;
        tracing::warn!(ip=%ip, user=%form.username, "web login failed");
        return (
            StatusCode::UNAUTHORIZED,
            Html(login_page(
                &cfg,
                &form.username,
                Some("Invalid credentials. Please try again."),
                form.return_to.as_deref(),
                &nonce.0,
            )),
        )
            .into_response();
    }
    state.failed_logins.lock().await.remove(&client_ip);
    let id = uuid::Uuid::new_v4().to_string();
    let session = Session {
        username: form.username.clone(),
        auth_source: "local".into(),
        admin: true,
        namespaces: cfg
            .namespaces
            .iter()
            .map(|namespace| namespace.name.clone())
            .collect(),
        expires_at: now().saturating_add(cfg.auth.session_ttl_seconds),
        oidc_refresh: None,
        oidc_checked_at: 0,
        refresh_lock: Arc::new(Mutex::new(())),
    };
    if !remember_session_if_current(&state, id.clone(), session, generation).await {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    tracing::info!(ip=%ip, user=%form.username, "web login succeeded");
    let cookie = session_cookie(
        &id,
        cfg.auth.session_ttl_seconds,
        cfg.server.public_url.starts_with("https://"),
    );
    let location = safe_return_to(form.return_to.as_deref()).unwrap_or_else(|| "/".into());
    (
        StatusCode::SEE_OTHER,
        [
            ("location", location.as_str()),
            ("set-cookie", cookie.as_str()),
        ],
    )
        .into_response()
}

async fn logout(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let cfg = state.config.read().await.clone();
    if !same_origin(&headers, &cfg) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let ip = log_ip(peer, &headers, &cfg);
    if let Some(id) = cookie_value(&headers, "galaxyd_session") {
        if let Some(session) = state.sessions.lock().await.remove(&id) {
            tracing::info!(ip=%ip, user=%session.username, "web logout");
        } else {
            tracing::info!(ip=%ip, user="unknown", "web logout");
        }
    } else {
        tracing::info!(ip=%ip, user="anonymous", "web logout");
    }
    (
        StatusCode::SEE_OTHER,
        [
            ("location", "/"),
            (
                "set-cookie",
                "galaxyd_session=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax",
            ),
        ],
    )
        .into_response()
}

fn same_origin(headers: &HeaderMap, cfg: &Config) -> bool {
    let Some(origin) = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let (Ok(origin), Ok(public)) = (
        url::Url::parse(origin),
        url::Url::parse(&cfg.server.public_url),
    ) else {
        return false;
    };
    origin.scheme() == public.scheme()
        && origin.host_str() == public.host_str()
        && origin.port_or_known_default() == public.port_or_known_default()
}

async fn login_limited(state: &AppState, ip: IpAddr) -> bool {
    const WINDOW: std::time::Duration = std::time::Duration::from_secs(600);
    let mut attempts = state.failed_logins.lock().await;
    let now = std::time::Instant::now();
    attempts.retain(|_, values| {
        values.retain(|time| now.duration_since(*time) < WINDOW);
        !values.is_empty()
    });
    attempts.get(&ip).is_some_and(|values| values.len() >= 5)
}

async fn record_login_failure(state: &AppState, ip: IpAddr) {
    let mut attempts = state.failed_logins.lock().await;
    if attempts.len() >= 4096 && !attempts.contains_key(&ip) {
        if let Some(key) = attempts.keys().next().copied() {
            attempts.remove(&key);
        }
    }
    attempts
        .entry(ip)
        .or_default()
        .push_back(std::time::Instant::now());
}

async fn oidc_login(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<ReturnToQuery>,
) -> Response {
    let _auth_slot = match state.auth_slots.clone().try_acquire_owned() {
        Ok(slot) => slot,
        Err(_) => return StatusCode::TOO_MANY_REQUESTS.into_response(),
    };
    let generation = *state.auth_gate.read().await;
    let cfg = state.config.read().await.clone();
    if !cfg.auth.oidc.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    if cfg.auth.oidc.debug {
        tracing::debug!(oidc_event="discovery_request", issuer=%cfg.auth.oidc.issuer_url, "OIDC request sent");
    }
    tracing::info!(ip=%log_ip(peer, &headers, &cfg), provider=%cfg.auth.oidc.display_name, "OIDC login started");
    let discovery = match oidc_discovery(&cfg.auth.oidc.issuer_url).await {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(error=%error, "OIDC discovery failed");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    if cfg.auth.oidc.debug {
        tracing::debug!(oidc_event="discovery_response", payload=%discovery, "OIDC response received");
    }
    let authorization_endpoint = match discovery
        .get("authorization_endpoint")
        .and_then(|v| v.as_str())
    {
        Some(value) if valid_oidc_endpoint(value) => value,
        None => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        Some(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let state_id = uuid::Uuid::new_v4().to_string();
    // RFC 7636 permits URL-safe unreserved characters. Two UUIDv4 values give
    // a 72-character verifier with 244 bits of entropy.
    let verifier = format!("{}{}", uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
    let nonce = uuid::Uuid::new_v4().to_string();
    let mut pending = state.oidc_pending.lock().await;
    pending.retain(|_, transaction| transaction.expires_at >= now());
    if pending.len() >= 4096 {
        if let Some(oldest) = pending
            .iter()
            .min_by_key(|(_, transaction)| transaction.expires_at)
            .map(|(key, _)| key.clone())
        {
            pending.remove(&oldest);
        }
    }
    pending.insert(
        state_id.clone(),
        OidcPending {
            verifier: verifier.clone(),
            nonce: nonce.clone(),
            return_to: safe_return_to(query.return_to.as_deref()),
            expires_at: now().saturating_add(300),
            generation,
        },
    );
    drop(pending);
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(sha2::Sha256::digest(verifier.as_bytes()));
    let scope = if cfg.auth.oidc.request_offline_access {
        "openid profile email groups offline_access"
    } else {
        "openid profile email groups"
    };
    let redirect_url = cfg.oidc_redirect_url();
    let url = url::Url::parse_with_params(
        authorization_endpoint,
        &[
            ("response_type", "code"),
            ("client_id", cfg.auth.oidc.client_id.as_str()),
            ("redirect_uri", redirect_url.as_str()),
            ("scope", scope),
            ("state", state_id.as_str()),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
            ("nonce", nonce.as_str()),
        ],
    )
    .map(|url| url.to_string());
    if cfg.auth.oidc.debug {
        tracing::debug!(oidc_event="authorization_request", endpoint=%authorization_endpoint, client_id=%cfg.auth.oidc.client_id, redirect_uri=%redirect_url, scope=%scope, state=%state_id, code_challenge_method="S256", "OIDC request sent");
    }
    match url {
        Ok(url) => {
            let mut response = Redirect::temporary(&url).into_response();
            response.headers_mut().append(
                axum::http::header::SET_COOKIE,
                axum::http::HeaderValue::from_str(&oidc_state_cookie(
                    &state_id,
                    cfg.server.public_url.starts_with("https://"),
                ))
                .expect("valid OIDC state cookie"),
            );
            response
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn oidc_callback(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<OidcQuery>,
) -> Response {
    let _auth_slot = match state.auth_slots.clone().try_acquire_owned() {
        Ok(slot) => slot,
        Err(_) => return StatusCode::TOO_MANY_REQUESTS.into_response(),
    };
    let generation = *state.auth_gate.read().await;
    let cfg = state.config.read().await.clone();
    let ip = log_ip(peer, &headers, &cfg);
    if !cfg.auth.oidc.enabled || query.error.is_some() {
        tracing::warn!(ip=%ip, user="unknown", error=?query.error.as_deref(), "OIDC login failed");
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let state_id = match query.state {
        Some(value) => value,
        None => {
            tracing::warn!(ip=%ip, user="unknown", "OIDC login failed: missing state");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };
    if cookie_value(&headers, "galaxyd_oidc_state").as_deref() != Some(state_id.as_str()) {
        tracing::warn!(ip=%ip, user="unknown", "OIDC login failed: state cookie mismatch");
        return StatusCode::BAD_REQUEST.into_response();
    }
    let pending = match state.oidc_pending.lock().await.remove(&state_id) {
        Some(value) if value.expires_at >= now() && value.generation == generation => value,
        _ => {
            tracing::warn!(ip=%ip, user="unknown", "OIDC login failed: invalid state");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };
    let code = match query.code {
        Some(value) => value,
        None => {
            tracing::warn!(ip=%ip, user="unknown", "OIDC login failed: missing code");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };
    if cfg.auth.oidc.debug {
        tracing::debug!(oidc_event="discovery_request", issuer=%cfg.auth.oidc.issuer_url, "OIDC request sent");
    }
    let discovery = match oidc_discovery(&cfg.auth.oidc.issuer_url).await {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(ip=%ip, user="unknown", error=%error, "OIDC login failed: discovery");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    if cfg.auth.oidc.debug {
        tracing::debug!(oidc_event="discovery_response", payload=%discovery, "OIDC response received");
    }
    let token_endpoint = match discovery.get("token_endpoint").and_then(|v| v.as_str()) {
        Some(value) if valid_oidc_endpoint(value) => value,
        _ => {
            tracing::warn!(ip=%ip, user="unknown", "OIDC login failed: missing token endpoint");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let userinfo_endpoint = match discovery.get("userinfo_endpoint").and_then(|v| v.as_str()) {
        Some(value) if valid_oidc_endpoint(value) => value,
        _ => {
            tracing::warn!(ip=%ip, user="unknown", "OIDC login failed: missing userinfo endpoint");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let secret = match bounded_file(&cfg.auth.oidc.client_secret_file, 16 * 1024) {
        Ok(value) => value.trim().to_owned(),
        Err(error) => {
            tracing::warn!(ip=%ip, user="unknown", error=%error, "OIDC login failed: client secret");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let redirect_url = cfg.oidc_redirect_url();
    let token_response = match oidc_client()
        .post(token_endpoint)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", redirect_url.as_str()),
            ("client_id", cfg.auth.oidc.client_id.as_str()),
            ("client_secret", secret.as_str()),
            ("code_verifier", pending.verifier.as_str()),
        ])
        .send()
        .await
    {
        Ok(response) => match response.error_for_status() {
            Ok(response) => {
                match bounded_response_json::<serde_json::Value>(response, 64 * 1024).await {
                    Ok(value) => value,
                    Err(error) => {
                        tracing::warn!(ip=%ip, user="unknown", error=%error, "OIDC login failed: token response");
                        return StatusCode::UNAUTHORIZED.into_response();
                    }
                }
            }
            Err(error) => {
                tracing::warn!(ip=%ip, user="unknown", error=%error, "OIDC login failed: token status");
                return StatusCode::UNAUTHORIZED.into_response();
            }
        },
        Err(error) => {
            tracing::warn!(ip=%ip, user="unknown", error=%error, "OIDC login failed: token request");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    if cfg.auth.oidc.debug {
        tracing::debug!(oidc_event="token_response", payload=%redact_oidc_value(&token_response), "OIDC response received");
        tracing::debug!(oidc_event="token_request", endpoint=%token_endpoint, client_id=%cfg.auth.oidc.client_id, redirect_uri=%redirect_url, grant_type="authorization_code", code_verifier="[redacted]", client_secret="[redacted]", authorization_code="[redacted]", "OIDC request sent");
    }
    let access_token = match token_response.get("access_token").and_then(|v| v.as_str()) {
        Some(value) => value,
        None => {
            tracing::warn!(ip=%ip, user="unknown", "OIDC login failed: missing access token");
            return StatusCode::UNAUTHORIZED.into_response();
        }
    };
    let id_token = match token_response.get("id_token").and_then(|v| v.as_str()) {
        Some(value) => value,
        None => {
            tracing::warn!(ip=%ip, user="unknown", "OIDC login failed: missing ID token");
            return StatusCode::UNAUTHORIZED.into_response();
        }
    };
    let id_claims = match validate_oidc_id_token(id_token, &discovery, &cfg, &pending.nonce).await {
        Ok(claims) => claims,
        Err(error) => {
            tracing::warn!(ip=%ip, user="unknown", error=%error, "OIDC login failed: invalid ID token");
            return StatusCode::UNAUTHORIZED.into_response();
        }
    };
    let user = match oidc_client()
        .get(userinfo_endpoint)
        .bearer_auth(access_token)
        .send()
        .await
    {
        Ok(response) => match response.error_for_status() {
            Ok(response) => {
                match bounded_response_json::<serde_json::Value>(response, 256 * 1024).await {
                    Ok(value) => value,
                    Err(error) => {
                        tracing::warn!(ip=%ip, user="unknown", error=%error, "OIDC login failed: userinfo response");
                        return StatusCode::UNAUTHORIZED.into_response();
                    }
                }
            }
            Err(error) => {
                tracing::warn!(ip=%ip, user="unknown", error=%error, "OIDC login failed: userinfo status");
                return StatusCode::UNAUTHORIZED.into_response();
            }
        },
        Err(error) => {
            tracing::warn!(ip=%ip, user="unknown", error=%error, "OIDC login failed: userinfo request");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    if id_claims.get("sub").and_then(|value| value.as_str())
        != user.get("sub").and_then(|value| value.as_str())
    {
        tracing::warn!(ip=%ip, user="unknown", "OIDC login failed: ID token and UserInfo subject mismatch");
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if cfg.auth.oidc.debug {
        tracing::debug!(oidc_event="userinfo_response", payload=%user, "OIDC response received");
        tracing::debug!(oidc_event="userinfo_request", endpoint=%userinfo_endpoint, access_token="[redacted]", "OIDC request sent");
    }
    let groups: HashSet<String> = user
        .get(&cfg.auth.oidc.groups_claim)
        .and_then(|v| v.as_array())
        .map(|values| {
            values
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let username = user
        .get("preferred_username")
        .or_else(|| user.get("email"))
        .or_else(|| user.get("sub"))
        .and_then(|value| value.as_str())
        .unwrap_or("OIDC user")
        .to_owned();
    let (admin, namespaces) = oidc_permissions(&cfg, &groups);
    let id = uuid::Uuid::new_v4().to_string();
    if token_response
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .is_none()
    {
        tracing::warn!(user=%username, "OIDC provider did not issue a refresh token; session will require re-login after the refresh interval");
    }
    let login_user = username.clone();
    let login_namespaces = namespaces.clone();
    if !remember_session_if_current(
        &state,
        id.clone(),
        Session {
            username,
            auth_source: "oidc".into(),
            admin,
            namespaces,
            expires_at: now().saturating_add(cfg.auth.session_ttl_seconds),
            oidc_refresh: token_response
                .get("refresh_token")
                .and_then(|v| v.as_str())
                .map(|token| OidcRefresh {
                    token: token.to_owned(),
                    subject: user
                        .get("sub")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_owned(),
                }),
            oidc_checked_at: now(),
            refresh_lock: Arc::new(Mutex::new(())),
        },
        generation,
    )
    .await
    {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    tracing::info!(ip=%ip, user=%login_user, namespaces=?login_namespaces, "OIDC login succeeded");
    let cookie = session_cookie(
        &id,
        cfg.auth.session_ttl_seconds,
        cfg.server.public_url.starts_with("https://"),
    );
    let mut response = (
        StatusCode::SEE_OTHER,
        [
            ("location", pending.return_to.as_deref().unwrap_or("/")),
            ("set-cookie", cookie.as_str()),
        ],
    )
        .into_response();
    response.headers_mut().append(
        axum::http::header::SET_COOKIE,
        axum::http::HeaderValue::from_static(
            "galaxyd_oidc_state=; Max-Age=0; Path=/auth/oidc; HttpOnly; SameSite=Lax",
        ),
    );
    response
}

async fn oidc_discovery(issuer: &str) -> anyhow::Result<serde_json::Value> {
    let response = oidc_client()
        .get(format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        ))
        .send()
        .await?;
    bounded_response_json(response, 256 * 1024).await
}

async fn validate_oidc_id_token(
    token: &str,
    discovery: &serde_json::Value,
    cfg: &Config,
    nonce: &str,
) -> anyhow::Result<serde_json::Value> {
    let issuer = discovery
        .get("issuer")
        .and_then(|value| value.as_str())
        .context("OIDC discovery has no issuer")?;
    if issuer != cfg.auth.oidc.issuer_url {
        anyhow::bail!("OIDC discovery issuer mismatch")
    }
    let jwks_uri = discovery
        .get("jwks_uri")
        .and_then(|value| value.as_str())
        .context("OIDC discovery has no jwks_uri")?;
    if !valid_oidc_endpoint(jwks_uri) {
        anyhow::bail!("OIDC discovery has an invalid jwks_uri")
    }
    let header = decode_header(token).context("invalid ID token header")?;
    if !matches!(
        header.alg,
        Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512
            | Algorithm::ES256
            | Algorithm::ES384
            | Algorithm::EdDSA
    ) {
        anyhow::bail!("unsupported ID token algorithm")
    }
    let response = oidc_client().get(jwks_uri).send().await?;
    let keys = bounded_response_json::<jsonwebtoken::jwk::JwkSet>(response, 1024 * 1024).await?;
    let key = match header.kid.as_deref() {
        Some(kid) => keys.find(kid).context("ID token key not found")?,
        None if keys.keys.len() == 1 => &keys.keys[0],
        None => anyhow::bail!("ID token has no key id"),
    };
    let decoding_key = DecodingKey::from_jwk(key).context("unsupported ID token key")?;
    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[cfg.auth.oidc.issuer_url.as_str()]);
    validation.set_audience(&[cfg.auth.oidc.client_id.as_str()]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    let claims = decode::<serde_json::Value>(token, &decoding_key, &validation)?.claims;
    let audience_count = claims
        .get("aud")
        .and_then(|value| value.as_array().map(Vec::len).or(Some(1)))
        .unwrap_or_default();
    if (audience_count > 1
        && claims.get("azp").and_then(|value| value.as_str())
            != Some(cfg.auth.oidc.client_id.as_str()))
        || claims
            .get("azp")
            .and_then(|value| value.as_str())
            .is_some_and(|azp| azp != cfg.auth.oidc.client_id)
    {
        anyhow::bail!("ID token authorized party mismatch")
    }
    if claims.get("nonce").and_then(|value| value.as_str()) != Some(nonce) {
        anyhow::bail!("ID token nonce mismatch")
    }
    Ok(claims)
}

fn oidc_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("valid OIDC HTTP client configuration")
}

fn valid_oidc_endpoint(value: &str) -> bool {
    url::Url::parse(value).is_ok_and(|url| {
        (url.scheme() == "https" || (url.scheme() == "http" && loopback_host(&url)))
            && url.host().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
    })
}

fn loopback_host(url: &url::Url) -> bool {
    url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    })
}

async fn bounded_response_json<T: DeserializeOwned>(
    response: reqwest::Response,
    limit: usize,
) -> anyhow::Result<T> {
    bounded_json_body(response.error_for_status()?, limit).await
}

async fn bounded_json_body<T: DeserializeOwned>(
    mut response: reqwest::Response,
    limit: usize,
) -> anyhow::Result<T> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        anyhow::bail!("HTTP response exceeds size limit")
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len().saturating_add(chunk.len()) > limit {
            anyhow::bail!("HTTP response exceeds size limit")
        }
        body.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice(&body)?)
}

fn verify_local_password(path: &std::path::Path, username: &str, password: &str) -> Result<bool> {
    let text = bounded_file(path, 64 * 1024)
        .with_context(|| format!("reading local users file {}", path.display()))?;
    let stored = text
        .lines()
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| *name == username)
        .map(|(_, encoded)| encoded)
        .next_back();
    let (encoded, user_exists) = match stored {
        Some(encoded) => (encoded, true),
        None => (dummy_password_hash(), false),
    };
    let hash = argon2::PasswordHash::new(encoded)
        .map_err(|error| anyhow::anyhow!("invalid local password hash for {username}: {error}"))?;
    Ok(argon2::Argon2::default()
        .verify_password(password.as_bytes(), &hash)
        .is_ok()
        && user_exists)
}

fn dummy_password_hash() -> &'static str {
    static HASH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    HASH.get_or_init(|| {
        let salt = SaltString::generate(&mut OsRng);
        argon2::Argon2::default()
            .hash_password(b"not-a-real-user-password", &salt)
            .expect("dummy Argon2 hash can be generated")
            .to_string()
    })
}

fn bounded_file(path: &std::path::Path, limit: usize) -> anyhow::Result<String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        anyhow::bail!("file is too large")
    }
    Ok(String::from_utf8(bytes)?)
}

fn oidc_permissions(cfg: &Config, groups: &HashSet<String>) -> (bool, HashSet<String>) {
    let admin = cfg
        .auth
        .oidc
        .group_mappings
        .iter()
        .any(|mapping| mapping.admin && groups.contains(&mapping.group));
    let namespaces = cfg
        .auth
        .oidc
        .group_mappings
        .iter()
        .filter(|mapping| groups.contains(&mapping.group))
        .flat_map(|mapping| mapping.namespaces.iter().cloned())
        .collect();
    (admin, namespaces)
}

#[derive(Debug)]
enum RefreshFailure {
    Revoked(&'static str),
    Unavailable(&'static str),
}

fn session_expired(session: &Session) -> bool {
    session.expires_at <= now()
}

async fn session_from_headers(
    state: &AppState,
    headers: &HeaderMap,
) -> std::result::Result<Option<(String, Session)>, StatusCode> {
    let Some(id) = cookie_value(headers, "galaxyd_session") else {
        return Ok(None);
    };
    let Some(session) = state.sessions.lock().await.get(&id).cloned() else {
        return Ok(None);
    };
    if session_expired(&session) {
        state.sessions.lock().await.remove(&id);
        return Ok(None);
    }
    let interval = state.config.read().await.auth.oidc.refresh_interval_seconds;
    if session.auth_source == "oidc" && now().saturating_sub(session.oidc_checked_at) >= interval {
        let state = state.clone();
        let refresh_id = id.clone();
        let result = tokio::spawn(async move {
            let _guard = session.refresh_lock.lock().await;
            let Some(current) = state.sessions.lock().await.get(&refresh_id).cloned() else {
                return Ok(());
            };
            if session_expired(&current) {
                state.sessions.lock().await.remove(&refresh_id);
                return Ok(());
            }
            let interval = state.config.read().await.auth.oidc.refresh_interval_seconds;
            if now().saturating_sub(current.oidc_checked_at) < interval {
                return Ok(());
            }
            let _slot = state
                .refresh_slots
                .acquire()
                .await
                .map_err(|_| RefreshFailure::Unavailable("refresh concurrency limit closed"))?;
            match refresh_oidc_session(&state, &refresh_id, &current).await {
                Err(RefreshFailure::Revoked(reason)) => {
                    tracing::info!(reason, "OIDC session revoked");
                    state.sessions.lock().await.remove(&refresh_id);
                    Ok(())
                }
                result => result,
            }
        })
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        if let Err(RefreshFailure::Unavailable(reason)) = result {
            tracing::warn!(reason, "OIDC session revalidation temporarily unavailable");
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
    }
    let current = state.sessions.lock().await.get(&id).cloned();
    match current {
        Some(current) if !session_expired(&current) => Ok(Some((id, current))),
        Some(_) => {
            state.sessions.lock().await.remove(&id);
            Ok(None)
        }
        None => Ok(None),
    }
}

async fn refresh_oidc_session(
    state: &AppState,
    id: &str,
    session: &Session,
) -> std::result::Result<(), RefreshFailure> {
    let Some(refresh) = session.oidc_refresh.as_ref() else {
        return Err(RefreshFailure::Revoked("refresh token unavailable"));
    };
    let generation = *state.auth_gate.read().await;
    let cfg = state.config.read().await.clone();
    let secret = bounded_file(&cfg.auth.oidc.client_secret_file, 16 * 1024)
        .map_err(|_| RefreshFailure::Unavailable("client secret unavailable"))?;
    let discovery = oidc_discovery(&cfg.auth.oidc.issuer_url)
        .await
        .map_err(|_| RefreshFailure::Unavailable("discovery unavailable"))?;
    let token_endpoint = discovery
        .get("token_endpoint")
        .and_then(|v| v.as_str())
        .filter(|v| valid_oidc_endpoint(v))
        .ok_or(RefreshFailure::Unavailable("invalid token endpoint"))?;
    let userinfo_endpoint = discovery
        .get("userinfo_endpoint")
        .and_then(|v| v.as_str())
        .filter(|v| valid_oidc_endpoint(v))
        .ok_or(RefreshFailure::Unavailable("invalid UserInfo endpoint"))?;
    let response = oidc_client()
        .post(token_endpoint)
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh.token.as_str()),
            ("client_id", cfg.auth.oidc.client_id.as_str()),
            ("client_secret", secret.trim()),
        ])
        .send()
        .await
        .map_err(|_| RefreshFailure::Unavailable("token endpoint request failed"))?;
    if response.status().is_client_error() {
        let error = bounded_json_body::<serde_json::Value>(response, 64 * 1024)
            .await
            .ok();
        return if error
            .as_ref()
            .and_then(|v| v.get("error"))
            .and_then(|v| v.as_str())
            == Some("invalid_grant")
        {
            Err(RefreshFailure::Revoked("refresh grant rejected"))
        } else {
            Err(RefreshFailure::Unavailable(
                "token endpoint rejected refresh",
            ))
        };
    }
    let response = response
        .error_for_status()
        .map_err(|_| RefreshFailure::Unavailable("token endpoint unavailable"))?;
    let tokens = bounded_response_json::<serde_json::Value>(response, 64 * 1024)
        .await
        .map_err(|_| RefreshFailure::Unavailable("invalid token response"))?;
    let access = tokens
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or(RefreshFailure::Unavailable("access token missing"))?;
    if let Some(rotated) = tokens.get("refresh_token").and_then(|v| v.as_str()) {
        let gate = state.auth_gate.read().await;
        if *gate != generation {
            return Err(RefreshFailure::Revoked("configuration changed"));
        }
        if let Some(current) = state.sessions.lock().await.get_mut(id) {
            if let Some(saved) = current.oidc_refresh.as_mut() {
                saved.token = rotated.to_owned();
            }
        }
    }
    let response = oidc_client()
        .get(userinfo_endpoint)
        .bearer_auth(access)
        .send()
        .await
        .map_err(|_| RefreshFailure::Unavailable("UserInfo request failed"))?;
    let response = response
        .error_for_status()
        .map_err(|_| RefreshFailure::Unavailable("UserInfo unavailable"))?;
    let user = bounded_response_json::<serde_json::Value>(response, 256 * 1024)
        .await
        .map_err(|_| RefreshFailure::Unavailable("invalid UserInfo response"))?;
    if user.get("sub").and_then(|v| v.as_str()) != Some(refresh.subject.as_str()) {
        return Err(RefreshFailure::Revoked("UserInfo subject changed"));
    }
    let groups: HashSet<String> = user
        .get(&cfg.auth.oidc.groups_claim)
        .and_then(|v| v.as_array())
        .map(|values| {
            values
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let (admin, namespaces) = oidc_permissions(&cfg, &groups);
    let gate = state.auth_gate.read().await;
    if *gate != generation {
        return Err(RefreshFailure::Revoked("configuration changed"));
    }
    let mut sessions = state.sessions.lock().await;
    let current = sessions
        .get_mut(id)
        .ok_or(RefreshFailure::Revoked("session removed"))?;
    if session_expired(current) {
        return Err(RefreshFailure::Revoked("session expired"));
    }
    current.admin = admin;
    current.namespaces = namespaces;
    current.oidc_checked_at = now();
    Ok(())
}

async fn remember_session(state: &AppState, id: String, session: Session) {
    let mut sessions = state.sessions.lock().await;
    if sessions.len() >= 4096 {
        let expired = sessions
            .iter()
            .filter(|(_, value)| value.expires_at <= now())
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        for key in expired {
            sessions.remove(&key);
        }
    }
    if sessions.len() >= 4096 {
        if let Some(key) = sessions.keys().next().cloned() {
            sessions.remove(&key);
        }
    }
    sessions.insert(id, session);
}

async fn remember_session_if_current(
    state: &AppState,
    id: String,
    session: Session,
    generation: u64,
) -> bool {
    let guard = state.auth_gate.read().await;
    if *guard != generation {
        return false;
    }
    remember_session(state, id, session).await;
    true
}

async fn remember_task(state: &AppState, id: String, task: ImportTask) {
    let mut tasks = state.tasks.lock().await;
    if tasks.len() >= 4096 {
        if let Some(key) = tasks
            .iter()
            .filter(|(_, value)| value.finished)
            .min_by_key(|(_, value)| value.finished_at.unwrap_or(value.started_at))
            .map(|(key, _)| key.clone())
        {
            tasks.remove(&key);
        }
    }
    if tasks.len() >= 4096 {
        if let Some(key) = tasks.keys().next().cloned() {
            tasks.remove(&key);
        }
    }
    tasks.insert(id, task);
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get("cookie")?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.to_owned())
}
fn session_cookie(id: &str, ttl: u64, secure: bool) -> String {
    format!(
        "galaxyd_session={id}; Max-Age={ttl}; Path=/; HttpOnly; SameSite=Lax{}",
        if secure { "; Secure" } else { "" }
    )
}
fn oidc_state_cookie(state: &str, secure: bool) -> String {
    format!(
        "galaxyd_oidc_state={state}; Max-Age=300; Path=/auth/oidc; HttpOnly; SameSite=Lax{}",
        if secure { "; Secure" } else { "" }
    )
}
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn rfc3339(timestamp: u64) -> String {
    i64::try_from(timestamp)
        .ok()
        .and_then(|value| time::OffsetDateTime::from_unix_timestamp(value).ok())
        .and_then(|value| {
            value
                .format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".into())
}

async fn discovery(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let cfg = state.config.read().await.clone();
    if cfg.auth.enabled {
        let session_valid = match session_from_headers(&state, &headers).await {
            Ok(value) => value.is_some(),
            Err(status) => return status.into_response(),
        };
        let token_valid = auth::bearer(&headers).is_ok_and(|token| {
            cfg.namespaces
                .iter()
                .any(|namespace| auth::authorize_read(&cfg.token_dir, namespace, token).is_ok())
        });
        if !session_valid && !token_valid {
            return StatusCode::UNAUTHORIZED.into_response();
        }
    }
    Json(serde_json::json!({"available_versions":{"v3":"v3/"}})).into_response()
}
async fn healthz() -> &'static str {
    "ok\n"
}
async fn readyz(State(state): State<AppState>) -> Response {
    if state.ready.load(Ordering::Relaxed) {
        "ready\n".into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not ready\n").into_response()
    }
}
async fn metrics(State(state): State<AppState>) -> Response {
    let mut out = String::new();
    encode(&mut out, &*state.registry.read().await).unwrap();
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        out,
    )
        .into_response()
}

async fn list_namespaces(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let cfg = state.config.read().await.clone();
    let session = if cfg.auth.enabled {
        match session_from_headers(&state, &headers).await {
            Ok(value) => value,
            Err(status) => return status.into_response(),
        }
    } else {
        None
    };
    if cfg.auth.enabled && session.is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let data: Vec<_> = cfg
        .namespaces
        .iter()
        .filter(|namespace| !cfg.auth.enabled || session.as_ref().is_some_and(|(_, session)| session.admin || session.namespaces.contains(&namespace.name)))
        .map(|namespace| {
            serde_json::json!({
                "name": namespace.name,
                "collections_url": public_link(&cfg.server.public_url, &format!("/api/galaxy/v3/collections?namespace={}", namespace.name)),
            })
        })
        .collect();
    Json(serde_json::json!({"data": data, "links": {"next": null}})).into_response()
}

#[derive(Deserialize)]
struct Search {
    search: Option<String>,
    page: Option<usize>,
    namespace: Option<String>,
    collection: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
}
async fn list_collections(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<Search>,
) -> Response {
    let cfg = state.config.read().await.clone();
    let session = if cfg.auth.enabled {
        match session_from_headers(&state, &headers).await {
            Ok(value) => value,
            Err(status) => return status.into_response(),
        }
    } else {
        None
    };
    if cfg.auth.enabled && q.namespace.is_some() {
        if let Err(status) =
            require_read_access(&state, &cfg, &headers, q.namespace.as_deref().unwrap()).await
        {
            return status.into_response();
        }
    } else if cfg.auth.enabled {
        let Some((_, session_value)) = session else {
            return StatusCode::UNAUTHORIZED.into_response();
        };
        if !session_value.admin {
            let allowed = session_value.namespaces;
            let mut records = visible_records(&cfg, state.catalog.read().await.clone());
            records.retain(|record| allowed.contains(&record.meta.namespace));
            return list_collection_records(&q, &cfg.server.public_url, records);
        }
    }
    list_collection_records(
        &q,
        &cfg.server.public_url,
        visible_records(&cfg, state.catalog.read().await.clone()),
    )
}

fn list_collection_records(q: &Search, public_url: &str, mut records: Vec<Record>) -> Response {
    if let Some(namespace) = q.namespace.as_deref() {
        records.retain(|r| r.meta.namespace == namespace);
    }
    if let Some(collection) = q.collection.as_deref() {
        records.retain(|r| r.meta.name == collection);
    }
    if let Some(s) = q.search.as_deref() {
        let needle = s.to_ascii_lowercase();
        records.retain(|r| {
            format!("{}.{}", r.meta.namespace, r.meta.name)
                .to_ascii_lowercase()
                .contains(&needle)
        });
    }
    records.sort_by(|a, b| {
        (&a.meta.namespace, &a.meta.name, &a.meta.version).cmp(&(
            &b.meta.namespace,
            &b.meta.name,
            &b.meta.version,
        ))
    });
    let limit = q.limit.unwrap_or(100).clamp(1, 100);
    let offset = q
        .offset
        .unwrap_or_else(|| q.page.unwrap_or(1).saturating_sub(1).saturating_mul(limit));
    let total = records.len();
    let next = offset
        .checked_add(limit)
        .filter(|next| *next < total)
        .map(|next| collection_next_link(q, limit, next));
    Json(serde_json::json!({"data":records.into_iter().skip(offset).take(limit).map(|r| serde_json::json!({"namespace":r.meta.namespace,"name":r.meta.name,"version":r.meta.version,"published_at":rfc3339(r.published_at),"download_url":public_link(public_url, &format!("/api/galaxy/v3/artifacts/{}/{}/{}/",r.meta.namespace,r.meta.name,r.meta.version))})).collect::<Vec<_>>(),"meta":{"count":total},"links":{"next":next},"page":offset / limit + 1})).into_response()
}

fn collection_next_link(q: &Search, limit: usize, offset: usize) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query
        .append_pair("limit", &limit.to_string())
        .append_pair("offset", &offset.to_string());
    if let Some(value) = q.search.as_deref() {
        query.append_pair("search", value);
    }
    if let Some(value) = q.namespace.as_deref() {
        query.append_pair("namespace", value);
    }
    if let Some(value) = q.collection.as_deref() {
        query.append_pair("collection", value);
    }
    format!("?{}", query.finish())
}
async fn collection(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((namespace, name)): Path<(String, String)>,
) -> Response {
    let cfg = state.config.read().await.clone();
    if let Err(status) = require_read_access(&state, &cfg, &headers, &namespace).await {
        return status.into_response();
    }
    if !namespace_visible(&cfg, &namespace) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let public_url = cfg.server.public_url.clone();
    let records = state.catalog.read().await.clone();
    let versions:Vec<_>=records.into_iter().filter(|r|r.meta.namespace==namespace&&r.meta.name==name).map(|r|serde_json::json!({"version":r.meta.version,"published_at":rfc3339(r.published_at),"download_url":public_link(&public_url, &format!("/api/galaxy/v3/artifacts/{}/{}/{}/",namespace,name,r.meta.version))})).collect();
    if versions.is_empty() {
        return StatusCode::NOT_FOUND.into_response();
    }
    Json(serde_json::json!({"namespace":{"name":namespace},"name":name,"created_at":null,"updated_at":null,"versions":versions})).into_response()
}

async fn collection_versions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((namespace, name)): Path<(String, String)>,
) -> Response {
    let cfg = state.config.read().await.clone();
    if let Err(status) = require_read_access(&state, &cfg, &headers, &namespace).await {
        return status.into_response();
    }
    if !namespace_visible(&cfg, &namespace) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let mut records = state.catalog.read().await.clone();
    records.retain(|r| r.meta.namespace == namespace && r.meta.name == name);
    records.sort_by(|a, b| {
        let a = semver::Version::parse(&a.meta.version).ok();
        let b = semver::Version::parse(&b.meta.version).ok();
        b.cmp(&a)
    });
    let data: Vec<_> = records.into_iter().map(|r| serde_json::json!({"version": r.meta.version, "href": format!("/api/galaxy/v3/collections/{namespace}/{name}/versions/{}/", r.meta.version)})).collect();
    Json(serde_json::json!({"data":data,"links":{"next":null},"meta":{"count":data.len()}}))
        .into_response()
}

async fn collection_version(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((namespace, name, version)): Path<(String, String, String)>,
) -> Response {
    let cfg = state.config.read().await.clone();
    if let Err(status) = require_read_access(&state, &cfg, &headers, &namespace).await {
        return status.into_response();
    }
    if !namespace_visible(&cfg, &namespace) {
        return StatusCode::NOT_FOUND.into_response();
    }
    match state.storage.record(&namespace, &name, &version).await {
        Ok(r) => Json(serde_json::json!({
            "namespace":{"name":namespace}, "collection":{"name":name}, "version":version,
            "href":format!("/api/galaxy/v3/collections/{namespace}/{name}/versions/{version}/"),
            "download_url":public_link(&cfg.server.public_url, &format!("/api/galaxy/v3/artifacts/{namespace}/{name}/{version}/")),
            "artifact":{"sha256":r.sha256,"size":r.size}, "metadata":{"dependencies":r.meta.dependencies}, "signatures":[]
        })).into_response(),
        Err(error) => storage_status(&error).into_response(),
    }
}

fn namespace_visible(cfg: &Config, namespace: &str) -> bool {
    cfg.namespaces.iter().any(|item| item.name == namespace)
}

fn visible_records(cfg: &Config, records: Vec<Record>) -> Vec<Record> {
    records
        .into_iter()
        .filter(|r| namespace_visible(cfg, &r.meta.namespace))
        .collect()
}

async fn require_read_access(
    state: &AppState,
    cfg: &Config,
    headers: &HeaderMap,
    namespace: &str,
) -> Result<(), StatusCode> {
    if !cfg.auth.enabled {
        return Ok(());
    }
    if let Some((_, session)) = session_from_headers(state, headers).await? {
        if session.admin || session.namespaces.contains(namespace) {
            return Ok(());
        }
        return Err(StatusCode::NOT_FOUND);
    }
    let token = auth::bearer(headers).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let namespace_config = cfg
        .namespaces
        .iter()
        .find(|item| item.name == namespace)
        .ok_or(StatusCode::NOT_FOUND)?;
    auth::authorize_read(&cfg.token_dir, namespace_config, token)
        .map_err(|_| StatusCode::UNAUTHORIZED)
}

fn public_link(base: &str, path: &str) -> String {
    format!("{}{}", base.trim_end_matches('/'), path)
}

fn storage_status(error: &anyhow::Error) -> StatusCode {
    if error.downcast_ref::<storage::StorageError>() == Some(&storage::StorageError::NotFound) {
        StatusCode::NOT_FOUND
    } else {
        tracing::error!(error=%error, "storage operation failed");
        StatusCode::SERVICE_UNAVAILABLE
    }
}

async fn task_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(task_id): Path<String>,
) -> Response {
    let cached = state.tasks.lock().await.get(&task_id).cloned();
    let task = match cached {
        Some(task) => Some(task),
        None => match state.storage.get_task(&task_id).await {
            Ok(bytes) => match serde_json::from_slice(&bytes) {
                Ok(task) => Some(task),
                Err(error) => {
                    tracing::error!(error=%error, %task_id, "invalid stored import task");
                    return StatusCode::SERVICE_UNAVAILABLE.into_response();
                }
            },
            Err(error)
                if error.downcast_ref::<storage::StorageError>()
                    == Some(&storage::StorageError::NotFound) =>
            {
                None
            }
            Err(error) => {
                tracing::error!(error=%error, %task_id, "import task lookup failed");
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
        },
    };
    match task {
        Some(task) => {
            let cfg = state.config.read().await.clone();
            let namespace_config = match cfg
                .namespaces
                .iter()
                .find(|item| item.name == task.namespace)
            {
                Some(namespace) => namespace,
                None => return StatusCode::NOT_FOUND.into_response(),
            };
            if cfg.auth.enabled {
                let token = match auth::bearer(&headers) {
                    Ok(token) => token,
                    Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
                };
                if auth::authorize_read(&cfg.token_dir, namespace_config, token).is_err() {
                    return StatusCode::FORBIDDEN.into_response();
                }
            }
            Json(serde_json::json!({
                "state": task.state,
                "started_at": rfc3339(task.started_at),
                "finished_at": task.finished_at.map(rfc3339),
                "messages": []
            }))
            .into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
async fn download(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path((namespace, name, version)): Path<(String, String, String)>,
) -> Response {
    let cfg = state.config.read().await.clone();
    let ip = log_ip(peer, &headers, &cfg);
    if let Err(status) = require_read_access(&state, &cfg, &headers, &namespace).await {
        if is_browser_navigation(&headers) {
            tracing::debug!(ip=%ip, namespace=%namespace, collection=%name, version=%version, "collection download unauthorized for browser");
        } else {
            tracing::warn!(ip=%ip, namespace=%namespace, collection=%name, version=%version, "collection download unauthorized");
        }
        return status.into_response();
    }
    if !namespace_visible(&cfg, &namespace) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let actor = if let Ok(Some((_, session))) = session_from_headers(&state, &headers).await {
        session.username
    } else if let Ok(token) = auth::bearer(&headers) {
        format!("token:{}", token_hint(token))
    } else {
        "anonymous".into()
    };
    drop(cfg);
    match state.storage.stream(&namespace, &name, &version).await {
        Ok((record, stream)) => {
            tracing::info!(ip=%ip, user=%actor, namespace=%namespace, collection=%name, version=%version, bytes=record.size, "collection download started");
            let mut response = axum::body::Body::from_stream(stream).into_response();
            response.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                axum::http::HeaderValue::from_static("application/octet-stream"),
            );
            if let Ok(value) = axum::http::HeaderValue::from_str(&record.size.to_string()) {
                response
                    .headers_mut()
                    .insert(axum::http::header::CONTENT_LENGTH, value);
            }
            let filename = format!(
                "{}-{}-{}.tar.gz",
                record.meta.namespace, record.meta.name, record.meta.version
            );
            if let Ok(value) =
                axum::http::HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
            {
                response
                    .headers_mut()
                    .insert(axum::http::header::CONTENT_DISPOSITION, value);
            }
            response
        }
        Err(error) => {
            tracing::warn!(ip=%ip, user=%actor, namespace=%namespace, collection=%name, version=%version, error=%error, "artifact lookup failed");
            storage_status(&error).into_response()
        }
    }
}

fn is_browser_navigation(headers: &HeaderMap) -> bool {
    headers
        .get("sec-fetch-mode")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("navigate"))
        || headers
            .get(axum::http::header::ACCEPT)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value.split(',').any(|part| {
                    part.trim()
                        .split(';')
                        .next()
                        .is_some_and(|media| media.trim().eq_ignore_ascii_case("text/html"))
                })
            })
}

async fn upload(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    let upload_slot = match state.upload_slots.clone().acquire_owned().await {
        Ok(slot) => slot,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let cfg = state.config.read().await.clone();
    let log_ip = log_ip(peer, &headers, &cfg);
    let token = match auth::bearer(&headers) {
        Ok(t) => t.to_owned(),
        Err(error) => {
            tracing::warn!(ip=%log_ip, error=%error, "collection upload missing token");
            return StatusCode::UNAUTHORIZED.into_response();
        }
    };
    let forwarded = match single_forwarded_for(&headers) {
        Ok(value) => value.map(str::to_owned),
        Err(error) => {
            tracing::warn!(ip=%log_ip, token=%token_hint(&token), error=%error, "collection upload rejected: invalid forwarding header");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };
    let ip = match client_ip::effective_ip(
        peer.ip(),
        forwarded.as_deref(),
        &cfg.network.set_real_ip_from,
        cfg.network.max_forwarded_for_hops,
    ) {
        Ok(i) => i,
        Err(error) => {
            tracing::warn!(ip=%log_ip, token=%token_hint(&token), error=%error, "collection upload rejected: invalid client address");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };
    if !cfg
        .namespaces
        .iter()
        .any(|namespace| auth::authorize(&cfg.token_dir, namespace, &token, ip).is_ok())
    {
        tracing::warn!(ip=%ip, token=%token_hint(&token), "collection upload unauthorized before body processing");
        return StatusCode::FORBIDDEN.into_response();
    }
    let mut archive = None;
    let mut checksum = None;
    loop {
        let field = match multipart.next_field().await {
            Ok(Some(field)) => field,
            Ok(None) => break,
            Err(error) => {
                tracing::warn!(ip=%ip, token=%token_hint(&token), error=%error, "collection upload rejected: invalid multipart body");
                return error.status().into_response();
            }
        };
        match field.name() {
            Some("file") if archive.is_none() => {
                match write_multipart_file(field, cfg.network.max_upload_bytes).await {
                    Ok(file) => archive = Some(file),
                    Err(UploadReadError::TooLarge) => {
                        tracing::warn!(ip=%ip, token=%token_hint(&token), "collection upload rejected: file is missing or too large");
                        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
                    }
                    Err(UploadReadError::Invalid(error)) => {
                        tracing::warn!(ip=%ip, token=%token_hint(&token), error=%error, "collection upload rejected: invalid file field");
                        return StatusCode::BAD_REQUEST.into_response();
                    }
                    Err(UploadReadError::Multipart(error)) => {
                        return error.status().into_response();
                    }
                }
            }
            Some("sha256") if checksum.is_none() => {
                checksum = match read_small_multipart_field(field, 256).await {
                    Ok(value) => String::from_utf8(value)
                        .ok()
                        .map(|value| value.trim().to_owned()),
                    Err(UploadReadError::TooLarge) => {
                        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
                    }
                    Err(UploadReadError::Invalid(_)) => {
                        return StatusCode::BAD_REQUEST.into_response();
                    }
                    Err(UploadReadError::Multipart(error)) => {
                        return error.status().into_response();
                    }
                }
            }
            Some("file" | "sha256") => {
                tracing::warn!(ip=%ip, token=%token_hint(&token), field=?field.name(), "collection upload rejected: duplicate multipart field");
                return StatusCode::BAD_REQUEST.into_response();
            }
            _ => return StatusCode::BAD_REQUEST.into_response(),
        }
    }
    let archive = match archive {
        Some(file) => file,
        None => {
            tracing::warn!(ip=%ip, token=%token_hint(&token), "collection upload rejected: missing file field");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };
    let checksum = match checksum {
        Some(value) if value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()) => value,
        _ => {
            tracing::warn!(ip=%ip, token=%token_hint(&token), "collection upload rejected: missing or invalid sha256 field");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };
    let archive_path = archive.path().to_owned();
    let inspect_checksum = checksum.clone();
    let inspection = tokio::task::spawn_blocking(move || {
        galaxy::inspect_path(&archive_path, Some(&inspect_checksum))
    })
    .await;
    let (meta, digest) = match inspection {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => {
            tracing::warn!(ip=%ip, token=%token_hint(&token), error=%error, "collection archive rejected");
            return StatusCode::UNPROCESSABLE_ENTITY.into_response();
        }
        Err(error) => {
            tracing::error!(ip=%ip, error=%error, "collection archive inspection task failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let namespace_config = match cfg
        .namespaces
        .iter()
        .find(|item| item.name == meta.namespace)
    {
        Some(namespace) => namespace,
        None => {
            tracing::warn!(ip=%ip, token=%token_hint(&token), namespace=%meta.namespace, "upload rejected for unknown namespace");
            return StatusCode::FORBIDDEN.into_response();
        }
    };
    if let Err(error) = auth::authorize(&cfg.token_dir, namespace_config, &token, ip) {
        tracing::warn!(ip=%ip, token=%token_hint(&token), namespace=%namespace_config.name, error=%error, "collection upload unauthorized");
        return StatusCode::FORBIDDEN.into_response();
    };
    let artifact_size = match archive.as_file().metadata() {
        Ok(metadata) => metadata.len() as usize,
        Err(error) => {
            tracing::error!(error=%error, "failed to read temporary artifact metadata");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let record = Record {
        meta: meta.clone(),
        sha256: galaxy::hex(&digest),
        size: artifact_size,
        artifact: format!("{}.tar.gz", uuid::Uuid::new_v4()),
        published_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };
    if let Err(error) = storage::validate_record(&record) {
        tracing::warn!(ip=%ip, namespace=%meta.namespace, collection=%meta.name, version=%meta.version, error=%error, "collection metadata rejected");
        return StatusCode::UNPROCESSABLE_ENTITY.into_response();
    }
    let current = state.config.read().await.clone();
    let current_ip = match client_ip::effective_ip(
        peer.ip(),
        forwarded.as_deref(),
        &current.network.set_real_ip_from,
        current.network.max_forwarded_for_hops,
    ) {
        Ok(ip) => ip,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let current_namespace = match current
        .namespaces
        .iter()
        .find(|namespace| namespace.name == meta.namespace)
    {
        Some(namespace) => namespace,
        None => return StatusCode::FORBIDDEN.into_response(),
    };
    if auth::authorize(&current.token_dir, current_namespace, &token, current_ip).is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }
    let task_id = uuid::Uuid::new_v4().to_string();
    let started_at = now();
    let task = ImportTask {
        namespace: meta.namespace.clone(),
        collection: Some(meta.name.clone()),
        version: Some(meta.version.clone()),
        sha256: Some(galaxy::hex(&digest)),
        state: "running".into(),
        finished: false,
        started_at,
        finished_at: None,
    };
    let task_bytes = match serde_json::to_vec(&task) {
        Ok(bytes) => bytes,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let (result_tx, result_rx) = tokio::sync::oneshot::channel();
    let worker_state = state.clone();
    let worker_id = task_id.clone();
    let worker_ip = ip;
    let worker_token_hint = token_hint(&token);
    state.publications.spawn(async move {
        let _upload_slot = upload_slot;
        let mut task = task;
        if let Err(error) = worker_state.storage.put_task(&worker_id, &task_bytes).await {
            tracing::error!(error=%error, task_id=%worker_id, "failed to create import task");
            let _ = result_tx.send(Err(error));
            return;
        }
        let result = worker_state
            .storage
            .publish_file(&record, archive.path())
            .await;
        task.state = if result.is_ok() {
            "completed"
        } else {
            "failed"
        }
        .into();
        task.finished = true;
        task.finished_at = Some(now());
        if result.is_ok() {
            worker_state.catalog.write().await.push(record);
            tracing::info!(ip=%worker_ip, token=%worker_token_hint, namespace=%meta.namespace, collection=%meta.name, version=%meta.version, bytes=artifact_size, "collection published");
        } else if let Err(ref error) = result {
            tracing::warn!(namespace=%meta.namespace, collection=%meta.name, version=%meta.version, error=%error, "collection publication rejected");
        }
        match serde_json::to_vec(&task) {
            Ok(bytes) => {
                if let Err(error) = worker_state.storage.put_task(&worker_id, &bytes).await {
                    tracing::error!(error=%error, task_id=%worker_id, "failed to finish import task");
                }
            }
            Err(error) => {
                tracing::error!(error=%error, task_id=%worker_id, "failed to encode import task")
            }
        }
        remember_task(&worker_state, worker_id, task).await;
        let _ = result_tx.send(result);
    });
    match result_rx.await {
        Ok(Ok(())) => {
            let public_url = current.server.public_url.clone();
            (StatusCode::ACCEPTED, Json(serde_json::json!({"state":"completed","task":public_link(&public_url, &format!("/api/galaxy/v3/imports/collections/{task_id}/"))}))).into_response()
        }
        Ok(Err(error)) if matches!(error.downcast_ref::<storage::StorageError>(), Some(storage::StorageError::AlreadyExists)) => {
            (StatusCode::CONFLICT, Json(serde_json::json!({"state":"failed","error":{"code":"CONFLICT","description":"collection version already exists"}}))).into_response()
        }
        Ok(Err(_)) | Err(_) => {
            (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"state":"failed","error":{"code":"STORAGE_UNAVAILABLE","description":"storage operation failed"}}))).into_response()
        }
    }
}

async fn ui(
    State(state): State<AppState>,
    axum::Extension(nonce): axum::Extension<CspNonce>,
    headers: HeaderMap,
    Query(query): Query<UiQuery>,
) -> Response {
    let cfg = state.config.read().await.clone();
    if !cfg.server.ui_enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    let session = if cfg.auth.enabled {
        match session_from_headers(&state, &headers).await {
            Ok(value) => value,
            Err(status) => return status.into_response(),
        }
    } else {
        None
    };
    if cfg.auth.enabled && session.is_none() {
        let mut return_url = url::Url::parse("http://localhost/").expect("static URL");
        if let Some(value) = query.namespace.as_deref() {
            return_url.query_pairs_mut().append_pair("namespace", value);
        }
        if let Some(value) = query.collection.as_deref() {
            return_url
                .query_pairs_mut()
                .append_pair("collection", value);
        }
        let return_to = format!(
            "{}{}",
            return_url.path(),
            return_url
                .query()
                .map(|value| format!("?{value}"))
                .unwrap_or_default()
        );
        if cfg.auth.local.enabled {
            let target = url::form_urlencoded::Serializer::new(String::new())
                .append_pair(
                    "return_to",
                    &safe_return_to(Some(return_to.as_str())).unwrap_or_else(|| "/".into()),
                )
                .finish();
            return Redirect::temporary(&format!("/auth/local/login?{target}")).into_response();
        }
        if cfg.auth.oidc.enabled {
            let target = url::form_urlencoded::Serializer::new(String::new())
                .append_pair(
                    "return_to",
                    &safe_return_to(Some(return_to.as_str())).unwrap_or_else(|| "/".into()),
                )
                .finish();
            return Redirect::temporary(&format!("/auth/oidc/login?{target}")).into_response();
        }
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if cfg.server.ui_enabled {
        Html(include_str!("../static/index.html").replace("<!-- CSP_NONCE -->", &nonce.0))
            .into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

fn single_forwarded_for(headers: &HeaderMap) -> Result<Option<&str>> {
    let mut values = headers.get_all("x-forwarded-for").iter();
    let first = values.next();
    if values.next().is_some() {
        anyhow::bail!("duplicate X-Forwarded-For")
    }
    first
        .map(|value| value.to_str().map_err(Into::into))
        .transpose()
}

fn log_ip(peer: SocketAddr, headers: &HeaderMap, cfg: &Config) -> String {
    let peer_ip = peer.ip();
    let forwarded = single_forwarded_for(headers).ok().flatten();
    client_ip::effective_ip(
        peer_ip,
        forwarded,
        &cfg.network.set_real_ip_from,
        cfg.network.max_forwarded_for_hops,
    )
    .map(|ip| ip.to_string())
    .unwrap_or_else(|_| peer_ip.to_string())
}

fn token_hint(token: &str) -> String {
    let digest = sha2::Sha256::digest(token.as_bytes());
    format!("sha256:{}", galaxy::hex(&digest[..8]))
}

fn redact_oidc_value(value: &serde_json::Value) -> serde_json::Value {
    let mut redacted = value.clone();
    if let Some(object) = redacted.as_object_mut() {
        for key in [
            "access_token",
            "refresh_token",
            "id_token",
            "token_type",
            "client_secret",
            "code",
            "code_verifier",
        ] {
            if object.contains_key(key) {
                object.insert(key.into(), serde_json::Value::String("[redacted]".into()));
            }
        }
    }
    redacted
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    struct PausedPublishStorage {
        inner: storage::LocalStorage,
        published: Arc<tokio::sync::Notify>,
        resume: Arc<tokio::sync::Notify>,
        pause_on_create: bool,
    }

    #[async_trait::async_trait]
    impl Storage for PausedPublishStorage {
        async fn publish(&self, record: &Record, bytes: &[u8]) -> Result<()> {
            self.inner.publish(record, bytes).await
        }
        async fn publish_file(&self, record: &Record, path: &std::path::Path) -> Result<()> {
            self.inner.publish_file(record, path).await?;
            if !self.pause_on_create {
                self.published.notify_one();
                self.resume.notified().await;
            }
            Ok(())
        }
        async fn get(
            &self,
            namespace: &str,
            name: &str,
            version: &str,
        ) -> Result<(Record, Vec<u8>)> {
            self.inner.get(namespace, name, version).await
        }
        async fn record(&self, namespace: &str, name: &str, version: &str) -> Result<Record> {
            self.inner.record(namespace, name, version).await
        }
        async fn stream(
            &self,
            namespace: &str,
            name: &str,
            version: &str,
        ) -> Result<(Record, storage::ArtifactStream)> {
            self.inner.stream(namespace, name, version).await
        }
        async fn records(&self) -> Result<Vec<Record>> {
            self.inner.records().await
        }
        async fn ready(&self) -> bool {
            self.inner.ready().await
        }
        async fn put_task(&self, id: &str, bytes: &[u8]) -> Result<()> {
            self.inner.put_task(id, bytes).await?;
            if self.pause_on_create
                && serde_json::from_slice::<ImportTask>(bytes)?.state == "running"
            {
                self.published.notify_one();
                self.resume.notified().await;
            }
            Ok(())
        }
        async fn get_task(&self, id: &str) -> Result<Vec<u8>> {
            self.inner.get_task(id).await
        }
        async fn tasks(&self) -> Result<Vec<(String, Vec<u8>)>> {
            self.inner.tasks().await
        }
        async fn reconcile(&self, records: &[Record]) -> Result<()> {
            self.inner.reconcile(records).await
        }
    }

    async fn http_request(
        app: Router,
        method: &str,
        uri: &str,
        credential: Option<(&str, &str)>,
    ) -> Response {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some((name, value)) = credential {
            builder = builder.header(name, value);
        }
        if method == "POST" {
            builder = builder.header("content-type", "multipart/form-data; boundary=demo");
        }
        let mut request = builder.body(Body::empty()).unwrap();
        request.extensions_mut().insert(ConnectInfo(
            "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
        ));
        app.oneshot(request).await.unwrap()
    }

    fn test_session(admin: bool, namespaces: &[&str]) -> Session {
        Session {
            username: "test".into(),
            auth_source: "local".into(),
            admin,
            namespaces: namespaces.iter().map(|v| (*v).to_owned()).collect(),
            expires_at: now() + 3600,
            oidc_refresh: None,
            oidc_checked_at: 0,
            refresh_lock: Arc::new(Mutex::new(())),
        }
    }

    fn upload_body(namespace: &str, version: &str) -> (Vec<u8>, Vec<u8>) {
        use flate2::{write::GzEncoder, Compression};
        let files = br#"{"files":[]}"#;
        let manifest = serde_json::to_vec(&serde_json::json!({
            "collection_info": {"namespace":namespace,"name":"common","version":version,"dependencies":{}},
            "file_manifest_file": {"chksum_sha256":galaxy::hex(&sha2::Sha256::digest(files))},
        })).unwrap();
        let mut gzip = GzEncoder::new(Vec::new(), Compression::default());
        {
            let mut tar = tar::Builder::new(&mut gzip);
            for (name, data) in [
                ("MANIFEST.json", manifest.as_slice()),
                ("FILES.json", files.as_slice()),
            ] {
                let mut header = tar::Header::new_gnu();
                header.set_path(name).unwrap();
                header.set_size(data.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                tar.append(&header, data).unwrap();
            }
            tar.finish().unwrap();
        }
        let archive = gzip.finish().unwrap();
        let checksum = galaxy::hex(&sha2::Sha256::digest(&archive));
        let mut body = format!("--security-boundary\r\nContent-Disposition: form-data; name=\"sha256\"\r\n\r\n{checksum}\r\n--security-boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"collection.tar.gz\"\r\nContent-Type: application/gzip\r\n\r\n").into_bytes();
        body.extend_from_slice(&archive);
        body.extend_from_slice(b"\r\n--security-boundary--\r\n");
        (body, archive)
    }

    async fn state() -> AppState {
        let cfg = Config::default();
        let storage = storage::LocalStorage::new(tempfile::tempdir().unwrap().keep());
        AppState {
            config: Arc::new(RwLock::new(cfg)),
            storage: Arc::new(storage),
            ready: Arc::new(AtomicBool::new(true)),
            requests: Counter::default(),
            registry: Arc::new(RwLock::new(Registry::default())),
            tasks: Arc::new(Mutex::new(HashMap::new())),
            catalog: Arc::new(RwLock::new(Vec::new())),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            oidc_pending: Arc::new(Mutex::new(HashMap::new())),
            upload_slots: Arc::new(Semaphore::new(2)),
            auth_slots: Arc::new(Semaphore::new(16)),
            failed_logins: Arc::new(Mutex::new(HashMap::new())),
            auth_gate: Arc::new(RwLock::new(0)),
            refresh_slots: Arc::new(Semaphore::new(8)),
            publications: TaskTracker::new(),
        }
    }

    #[tokio::test]
    async fn namespaces_are_read_from_configuration() {
        let state = state().await;
        state
            .config
            .write()
            .await
            .namespaces
            .push(crate::config::NamespaceConfig {
                name: "engineering".into(),
                push_networks: vec![],
            });
        let response = public_router(state, true, 128 * 1024 * 1024)
            .oneshot(
                Request::get("/api/galaxy/v3/namespaces")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["data"][0]["name"], "engineering");
    }

    #[tokio::test]
    async fn ui_is_embedded() {
        let response = public_router(state().await, true, 128 * 1024 * 1024)
            .oneshot(Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(String::from_utf8_lossy(&body).contains("<title>galaxyd</title>"));
    }

    #[test]
    fn formats_rfc3339_without_fractional_seconds() {
        assert_eq!(rfc3339(1_600_000_000), "2020-09-13T12:26:40Z");
        assert!(!rfc3339(1_600_000_000).contains('.'));
    }

    #[test]
    fn validates_oidc_endpoints() {
        assert!(valid_oidc_endpoint("https://id.example.test/jwks"));
        assert!(!valid_oidc_endpoint("file:///etc/passwd"));
        assert!(!valid_oidc_endpoint(
            "https://user:pass@id.example.test/jwks"
        ));
        assert!(!valid_oidc_endpoint(
            "https://id.example.test/jwks#fragment"
        ));
    }

    #[tokio::test]
    async fn reconciles_running_task_with_published_record() {
        let directory = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> =
            Arc::new(storage::LocalStorage::new(directory.path().to_path_buf()));
        let bytes = b"artifact";
        let record = Record {
            meta: galaxy::CollectionMeta {
                namespace: "engineering".into(),
                name: "common".into(),
                version: "1.0.0".into(),
                dependencies: serde_json::json!({}),
            },
            sha256: galaxy::hex(&sha2::Sha256::digest(bytes)),
            size: bytes.len(),
            artifact: "artifact.tar.gz".into(),
            published_at: now(),
        };
        storage.publish(&record, bytes).await.unwrap();
        let task_id = uuid::Uuid::new_v4().to_string();
        let task = ImportTask {
            namespace: "engineering".into(),
            collection: Some("common".into()),
            version: Some("1.0.0".into()),
            sha256: Some(record.sha256.clone()),
            state: "running".into(),
            finished: false,
            started_at: now(),
            finished_at: None,
        };
        storage
            .put_task(&task_id, &serde_json::to_vec(&task).unwrap())
            .await
            .unwrap();

        let reconciled = reconcile_tasks(&storage, std::slice::from_ref(&record))
            .await
            .unwrap();
        assert_eq!(reconciled[&task_id].state, "completed");
        assert!(reconciled[&task_id].finished);

        let incomplete_id = uuid::Uuid::new_v4().to_string();
        let mut incomplete = task.clone();
        incomplete.version = Some("2.0.0".into());
        storage
            .put_task(&incomplete_id, &serde_json::to_vec(&incomplete).unwrap())
            .await
            .unwrap();
        let reconciled = reconcile_tasks(&storage, std::slice::from_ref(&record))
            .await
            .unwrap();
        assert_eq!(reconciled[&incomplete_id].state, "failed");
        assert!(reconciled[&incomplete_id].finished);
    }

    #[tokio::test]
    async fn pagination_preserves_filters_and_formats_dates() {
        let records = ["common", "common_extra"]
            .into_iter()
            .map(|name| Record {
                meta: galaxy::CollectionMeta {
                    namespace: "engineering".into(),
                    name: name.into(),
                    version: "1.0.0".into(),
                    dependencies: serde_json::json!({}),
                },
                sha256: "00".repeat(32),
                size: 1,
                artifact: format!("{name}.tar.gz"),
                published_at: 1_600_000_000,
            })
            .collect();
        let response = list_collection_records(
            &Search {
                search: Some("common".into()),
                page: None,
                namespace: Some("engineering".into()),
                collection: None,
                limit: Some(1),
                offset: None,
            },
            "https://galaxy.example.test",
            records,
        );
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["data"][0]["published_at"], "2020-09-13T12:26:40Z");
        let next = json["links"]["next"].as_str().unwrap();
        assert!(next.contains("limit=1"));
        assert!(next.contains("offset=1"));
        assert!(next.contains("search=common"));
        assert!(next.contains("namespace=engineering"));
    }

    #[tokio::test]
    async fn global_auth_blocks_anonymous_catalog_and_allows_admin_session() {
        let state = state().await;
        {
            let mut cfg = state.config.write().await;
            cfg.auth.enabled = true;
            cfg.auth.local.enabled = true;
            cfg.namespaces.push(crate::config::NamespaceConfig {
                name: "engineering".into(),
                push_networks: vec![],
            });
        }
        let response = public_router(state.clone(), true, 128 * 1024 * 1024)
            .oneshot(
                Request::get("/api/galaxy/v3/namespaces")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let id = "test-session";
        state.sessions.lock().await.insert(
            id.into(),
            Session {
                username: "test".into(),
                auth_source: "local".into(),
                admin: true,
                namespaces: HashSet::new(),
                expires_at: now() + 60,
                oidc_refresh: None,
                oidc_checked_at: 0,
                refresh_lock: Arc::new(Mutex::new(())),
            },
        );
        let response = public_router(state, true, 128 * 1024 * 1024)
            .oneshot(
                Request::get("/api/galaxy/v3/namespaces")
                    .header("cookie", "galaxyd_session=test-session")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn read_access_matrix_covers_anonymous_sessions_and_token_scopes() {
        let state = state().await;
        let token_dir = tempfile::tempdir().unwrap();
        std::fs::write(
            token_dir.path().join("engineering.read.secrets"),
            "read-only\n",
        )
        .unwrap();
        std::fs::write(
            token_dir.path().join("engineering.write.secrets"),
            "writer\n",
        )
        .unwrap();
        {
            let mut cfg = state.config.write().await;
            cfg.auth.enabled = true;
            cfg.token_dir = token_dir.path().to_owned();
            cfg.namespaces
                .extend(["engineering", "research"].into_iter().map(|name| {
                    crate::config::NamespaceConfig {
                        name: name.into(),
                        push_networks: vec![],
                    }
                }));
        }
        let cfg = state.config.read().await.clone();
        let mut headers = HeaderMap::new();
        assert_eq!(
            require_read_access(&state, &cfg, &headers, "engineering").await,
            Err(StatusCode::UNAUTHORIZED)
        );
        headers.insert("authorization", "Bearer read-only".parse().unwrap());
        assert!(require_read_access(&state, &cfg, &headers, "engineering")
            .await
            .is_ok());
        headers.insert("authorization", "Bearer writer".parse().unwrap());
        assert!(require_read_access(&state, &cfg, &headers, "engineering")
            .await
            .is_ok());
        headers.insert("authorization", "Bearer invalid".parse().unwrap());
        assert_eq!(
            require_read_access(&state, &cfg, &headers, "engineering").await,
            Err(StatusCode::UNAUTHORIZED)
        );
        headers.insert("authorization", "Bearer read-only".parse().unwrap());
        assert_eq!(
            require_read_access(&state, &cfg, &headers, "research").await,
            Err(StatusCode::UNAUTHORIZED)
        );

        state.sessions.lock().await.insert(
            "user".into(),
            Session {
                username: "user".into(),
                auth_source: "oidc".into(),
                admin: false,
                namespaces: HashSet::from(["engineering".into()]),
                expires_at: now() + 60,
                oidc_refresh: None,
                oidc_checked_at: now(),
                refresh_lock: Arc::new(Mutex::new(())),
            },
        );
        headers.clear();
        headers.insert("cookie", "galaxyd_session=user".parse().unwrap());
        assert!(require_read_access(&state, &cfg, &headers, "engineering")
            .await
            .is_ok());
        assert_eq!(
            require_read_access(&state, &cfg, &headers, "research").await,
            Err(StatusCode::NOT_FOUND)
        );
        state.sessions.lock().await.insert(
            "admin".into(),
            Session {
                username: "admin".into(),
                auth_source: "oidc".into(),
                admin: true,
                namespaces: HashSet::new(),
                expires_at: now() + 60,
                oidc_refresh: None,
                oidc_checked_at: now(),
                refresh_lock: Arc::new(Mutex::new(())),
            },
        );
        headers.insert("cookie", "galaxyd_session=admin".parse().unwrap());
        assert!(require_read_access(&state, &cfg, &headers, "research")
            .await
            .is_ok());
        state.sessions.lock().await.insert(
            "expired".into(),
            Session {
                username: "expired".into(),
                auth_source: "local".into(),
                admin: true,
                namespaces: HashSet::new(),
                expires_at: now().saturating_sub(1),
                oidc_refresh: None,
                oidc_checked_at: 0,
                refresh_lock: Arc::new(Mutex::new(())),
            },
        );
        headers.insert("cookie", "galaxyd_session=expired".parse().unwrap());
        assert_eq!(
            require_read_access(&state, &cfg, &headers, "research").await,
            Err(StatusCode::UNAUTHORIZED)
        );
    }

    #[tokio::test]
    async fn http_routes_enforce_authentication_and_namespace_boundaries() {
        let state = state().await;
        let tokens = tempfile::tempdir().unwrap();
        std::fs::write(tokens.path().join("engineering.read.secrets"), "reader\n").unwrap();
        std::fs::write(tokens.path().join("engineering.write.secrets"), "writer\n").unwrap();
        {
            let mut cfg = state.config.write().await;
            cfg.auth.enabled = true;
            cfg.auth.local.enabled = true;
            cfg.token_dir = tokens.path().to_owned();
            cfg.namespaces
                .extend(["engineering", "research"].into_iter().map(|name| {
                    crate::config::NamespaceConfig {
                        name: name.into(),
                        push_networks: vec![],
                    }
                }));
        }
        let record = Record {
            meta: galaxy::CollectionMeta {
                namespace: "engineering".into(),
                name: "common".into(),
                version: "1.0.0".into(),
                dependencies: serde_json::json!({}),
            },
            sha256: galaxy::hex(&sha2::Sha256::digest(b"archive")),
            size: 7,
            artifact: "file.tar.gz".into(),
            published_at: 1,
        };
        state.storage.publish(&record, b"archive").await.unwrap();
        state.catalog.write().await.push(record);
        let research = Record {
            meta: galaxy::CollectionMeta {
                namespace: "research".into(),
                name: "common".into(),
                version: "1.0.0".into(),
                dependencies: serde_json::json!({}),
            },
            sha256: galaxy::hex(&sha2::Sha256::digest(b"archive")),
            size: 7,
            artifact: "research.tar.gz".into(),
            published_at: 1,
        };
        state.storage.publish(&research, b"archive").await.unwrap();
        state.catalog.write().await.push(research);
        state
            .sessions
            .lock()
            .await
            .insert("user".into(), test_session(false, &["engineering"]));
        state
            .sessions
            .lock()
            .await
            .insert("admin".into(), test_session(true, &[]));
        let mut expired = test_session(true, &[]);
        expired.expires_at = now().saturating_sub(1);
        state
            .sessions
            .lock()
            .await
            .insert("expired".into(), expired);
        state.tasks.lock().await.insert(
            "job".into(),
            ImportTask {
                namespace: "engineering".into(),
                collection: None,
                version: None,
                sha256: None,
                state: "completed".into(),
                finished: true,
                started_at: now(),
                finished_at: Some(now()),
            },
        );
        let app = public_router(state.clone(), true, 128 * 1024 * 1024);
        let read_routes = [
            "/api/galaxy/v3/collections?namespace=engineering",
            "/api/galaxy/v3/collections/engineering/common/",
            "/api/galaxy/v3/collections/engineering/common/versions/",
            "/api/galaxy/v3/collections/engineering/common/versions/1.0.0/",
            "/api/galaxy/v3/artifacts/engineering/common/1.0.0/",
        ];
        for route in read_routes {
            assert_eq!(
                http_request(app.clone(), "GET", route, None).await.status(),
                StatusCode::UNAUTHORIZED,
                "{route}"
            );
            assert_eq!(
                http_request(
                    app.clone(),
                    "GET",
                    route,
                    Some(("authorization", "Bearer reader"))
                )
                .await
                .status(),
                StatusCode::OK,
                "{route}"
            );
            assert_eq!(
                http_request(
                    app.clone(),
                    "GET",
                    route,
                    Some(("authorization", "Bearer writer"))
                )
                .await
                .status(),
                StatusCode::OK,
                "{route}"
            );
            assert_eq!(
                http_request(
                    app.clone(),
                    "GET",
                    route,
                    Some(("authorization", "Bearer invalid"))
                )
                .await
                .status(),
                StatusCode::UNAUTHORIZED,
                "{route}"
            );
            assert_eq!(
                http_request(
                    app.clone(),
                    "GET",
                    route,
                    Some(("cookie", "galaxyd_session=user"))
                )
                .await
                .status(),
                StatusCode::OK,
                "{route}"
            );
            assert_eq!(
                http_request(
                    app.clone(),
                    "GET",
                    route,
                    Some(("cookie", "galaxyd_session=admin"))
                )
                .await
                .status(),
                StatusCode::OK,
                "{route}"
            );
        }
        let other = "/api/galaxy/v3/collections/research/common/versions/";
        assert_eq!(
            http_request(
                app.clone(),
                "GET",
                other,
                Some(("cookie", "galaxyd_session=user"))
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            http_request(
                app.clone(),
                "GET",
                other,
                Some(("authorization", "Bearer reader"))
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            http_request(
                app.clone(),
                "GET",
                other,
                Some(("cookie", "galaxyd_session=admin"))
            )
            .await
            .status(),
            StatusCode::OK
        );
        assert_eq!(
            http_request(app.clone(), "GET", "/api/galaxy/", None)
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            http_request(
                app.clone(),
                "GET",
                "/api/galaxy/",
                Some(("authorization", "Bearer reader"))
            )
            .await
            .status(),
            StatusCode::OK
        );
        assert_eq!(
            http_request(
                app.clone(),
                "GET",
                "/api/galaxy/v3/namespaces",
                Some(("authorization", "Bearer reader"))
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        let response = http_request(
            app.clone(),
            "GET",
            "/api/galaxy/v3/namespaces",
            Some(("cookie", "galaxyd_session=user")),
        )
        .await;
        let json: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(json["data"].as_array().unwrap().len(), 1);
        assert_eq!(json["data"][0]["name"], "engineering");
        let response = http_request(
            app.clone(),
            "GET",
            "/api/galaxy/v3/namespaces",
            Some(("cookie", "galaxyd_session=admin")),
        )
        .await;
        let json: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(json["data"].as_array().unwrap().len(), 2);
        let response = http_request(
            app.clone(),
            "GET",
            "/api/galaxy/v3/collections",
            Some(("cookie", "galaxyd_session=user")),
        )
        .await;
        let json: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(json["data"].as_array().unwrap().len(), 1);
        assert_eq!(json["data"][0]["namespace"], "engineering");
        assert_eq!(
            http_request(
                app.clone(),
                "GET",
                "/api/galaxy/v3/collections",
                Some(("authorization", "Bearer reader"))
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            http_request(
                app.clone(),
                "GET",
                "/api/galaxy/v3/namespaces",
                Some(("cookie", "galaxyd_session=expired"))
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        let task = "/api/galaxy/v3/imports/collections/job/";
        assert_eq!(
            http_request(app.clone(), "GET", task, None).await.status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            http_request(
                app.clone(),
                "GET",
                task,
                Some(("authorization", "Bearer reader"))
            )
            .await
            .status(),
            StatusCode::OK
        );
        assert_eq!(
            http_request(
                app.clone(),
                "GET",
                task,
                Some(("authorization", "Bearer invalid"))
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            http_request(
                app.clone(),
                "GET",
                task,
                Some(("cookie", "galaxyd_session=admin"))
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        let upload = "/api/galaxy/v3/artifacts/collections/";
        assert_eq!(
            http_request(app.clone(), "POST", upload, None)
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            http_request(
                app.clone(),
                "POST",
                upload,
                Some(("authorization", "Bearer reader"))
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            http_request(
                app.clone(),
                "POST",
                upload,
                Some(("authorization", "Bearer writer"))
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            http_request(
                app.clone(),
                "POST",
                upload,
                Some(("cookie", "galaxyd_session=admin"))
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            http_request(app.clone(), "GET", "/", None).await.status(),
            StatusCode::TEMPORARY_REDIRECT
        );
        assert_eq!(
            http_request(
                app.clone(),
                "GET",
                "/",
                Some(("cookie", "galaxyd_session=user"))
            )
            .await
            .status(),
            StatusCode::OK
        );
        state.config.write().await.auth.enabled = false;
        assert_eq!(
            http_request(app.clone(), "GET", "/api/galaxy/v3/namespaces", None)
                .await
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            http_request(app, "GET", read_routes[1], None)
                .await
                .status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn archive_publication_requires_write_token_for_archive_namespace() {
        let state = state().await;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("engineering.read.secrets"), "reader\n").unwrap();
        std::fs::write(dir.path().join("engineering.write.secrets"), "writer\n").unwrap();
        std::fs::write(
            dir.path().join("research.write.secrets"),
            "research-writer\n",
        )
        .unwrap();
        {
            let mut cfg = state.config.write().await;
            cfg.auth.enabled = true;
            cfg.token_dir = dir.path().to_owned();
            cfg.namespaces
                .extend(["engineering", "research"].into_iter().map(|name| {
                    crate::config::NamespaceConfig {
                        name: name.into(),
                        push_networks: vec![],
                    }
                }));
        }
        state
            .sessions
            .lock()
            .await
            .insert("admin".into(), test_session(true, &[]));
        state
            .sessions
            .lock()
            .await
            .insert("user".into(), test_session(false, &["engineering"]));
        let app = public_router(state.clone(), true, 1024 * 1024);
        let post_archive = |credential: Option<(&str, &str)>, body: Vec<u8>| {
            let mut builder = Request::post("/api/galaxy/v3/artifacts/collections/").header(
                "content-type",
                "multipart/form-data; boundary=security-boundary",
            );
            if let Some((name, value)) = credential {
                builder = builder.header(name, value);
            }
            let mut request = builder.body(Body::from(body)).unwrap();
            request.extensions_mut().insert(ConnectInfo(
                "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            ));
            request
        };
        let (engineering, archive) = upload_body("engineering", "2.0.0");
        for (credential, status) in [
            (None, StatusCode::UNAUTHORIZED),
            (
                Some(("authorization", "Bearer reader")),
                StatusCode::FORBIDDEN,
            ),
            (
                Some(("authorization", "Bearer invalid")),
                StatusCode::FORBIDDEN,
            ),
            (
                Some(("cookie", "galaxyd_session=admin")),
                StatusCode::UNAUTHORIZED,
            ),
            (
                Some(("cookie", "galaxyd_session=user")),
                StatusCode::UNAUTHORIZED,
            ),
            (
                Some(("authorization", "Bearer research-writer")),
                StatusCode::FORBIDDEN,
            ),
        ] {
            let response = app
                .clone()
                .oneshot(post_archive(credential, engineering.clone()))
                .await
                .unwrap();
            assert_eq!(response.status(), status, "{credential:?}");
        }
        assert!(state.catalog.read().await.is_empty());
        let (research, _) = upload_body("research", "2.0.0");
        assert_eq!(
            app.clone()
                .oneshot(post_archive(
                    Some(("authorization", "Bearer writer")),
                    research
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        let response = app
            .clone()
            .oneshot(post_archive(
                Some(("authorization", "Bearer writer")),
                engineering.clone(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let result: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        let task_path = url::Url::parse(result["task"].as_str().unwrap())
            .unwrap()
            .path()
            .to_owned();
        assert_eq!(
            http_request(
                app.clone(),
                "GET",
                &task_path,
                Some(("authorization", "Bearer reader"))
            )
            .await
            .status(),
            StatusCode::OK
        );
        let download = http_request(
            app.clone(),
            "GET",
            "/api/galaxy/v3/artifacts/engineering/common/2.0.0/",
            Some(("authorization", "Bearer reader")),
        )
        .await;
        assert_eq!(download.status(), StatusCode::OK);
        assert_eq!(
            download.into_body().collect().await.unwrap().to_bytes(),
            archive.as_slice()
        );
        assert_eq!(state.catalog.read().await.len(), 1);
    }

    #[tokio::test]
    async fn publication_completes_after_client_disconnects() {
        publication_survives_disconnect_and_shutdown(false).await;
    }

    #[tokio::test]
    async fn task_creation_completes_after_client_disconnects() {
        publication_survives_disconnect_and_shutdown(true).await;
    }

    async fn publication_survives_disconnect_and_shutdown(pause_on_create: bool) {
        let mut state = state().await;
        let directory = tempfile::tempdir().unwrap();
        let tokens = tempfile::tempdir().unwrap();
        std::fs::write(tokens.path().join("engineering.write.secrets"), "writer\n").unwrap();
        let published = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());
        state.storage = Arc::new(PausedPublishStorage {
            inner: storage::LocalStorage::new(directory.path().to_path_buf()),
            published: published.clone(),
            resume: resume.clone(),
            pause_on_create,
        });
        {
            let mut config = state.config.write().await;
            config.token_dir = tokens.path().to_path_buf();
            config.namespaces.push(crate::config::NamespaceConfig {
                name: "engineering".into(),
                push_networks: vec![],
            });
        }
        let (body, archive) = upload_body("engineering", "3.0.0");
        let mut request = Request::post("/api/galaxy/v3/artifacts/collections/")
            .header(
                "content-type",
                "multipart/form-data; boundary=security-boundary",
            )
            .header("authorization", "Bearer writer")
            .body(Body::from(body))
            .unwrap();
        request.extensions_mut().insert(ConnectInfo(
            "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
        ));
        let handler =
            tokio::spawn(public_router(state.clone(), true, 1024 * 1024).oneshot(request));
        tokio::time::timeout(std::time::Duration::from_secs(5), published.notified())
            .await
            .unwrap();
        handler.abort();
        let _ = handler.await;
        assert_eq!(state.upload_slots.available_permits(), 1);
        state.publications.close();
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(20),
            state.publications.wait(),
        )
        .await
        .is_err());
        resume.notify_one();
        tokio::time::timeout(std::time::Duration::from_secs(5), state.publications.wait())
            .await
            .unwrap();
        assert_eq!(state.upload_slots.available_permits(), 2);
        assert_eq!(state.catalog.read().await.len(), 1);
        let persisted = state.storage.tasks().await.unwrap();
        assert_eq!(persisted.len(), 1);
        let task: ImportTask = serde_json::from_slice(&persisted[0].1).unwrap();
        assert!(task.finished);
        assert_eq!(task.state, "completed");
        assert_eq!(
            state
                .storage
                .get("engineering", "common", "3.0.0")
                .await
                .unwrap()
                .1,
            archive
        );
    }

    #[tokio::test]
    async fn oidc_callback_validates_identity_and_rejects_login_after_reload() {
        use std::sync::atomic::AtomicU8;
        const TEST_SIGNING_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIGrD/e7uKYqSY4twDEsRfMMuLSrODf14dpTiTK6K1YI0\n-----END PRIVATE KEY-----\n";
        const TEST_PUBLIC_KEY: &str = "2-Jj2UvNCvQiUPNYRgSi0cJSPiJI6Rs6D0UTeEpQVj8";
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let state = state().await;
        let mode = Arc::new(AtomicU8::new(0));
        let nonce = Arc::new(Mutex::new(String::new()));
        let token_started = Arc::new(tokio::sync::Notify::new());
        let release_token = Arc::new(tokio::sync::Notify::new());
        let discovery_issuer = issuer.clone();
        let token_issuer = issuer.clone();
        let token_nonce = nonce.clone();
        let token_mode = mode.clone();
        let token_started_signal = token_started.clone();
        let token_release = release_token.clone();
        let user_mode = mode.clone();
        let provider = Router::new()
            .route("/.well-known/openid-configuration", get(move || {
                let issuer = discovery_issuer.clone();
                async move { Json(serde_json::json!({
                    "issuer":issuer, "authorization_endpoint":format!("{issuer}/authorize"),
                    "token_endpoint":format!("{issuer}/token"),
                    "userinfo_endpoint":format!("{issuer}/userinfo"),
                    "jwks_uri":format!("{issuer}/jwks"),
                })) }
            }))
            .route("/jwks", get(|| async { Json(serde_json::json!({"keys":[{
                "kty":"OKP", "crv":"Ed25519", "x":TEST_PUBLIC_KEY,
                "kid":"test-key", "alg":"EdDSA", "use":"sig",
            }]})) }))
            .route("/token", post(move |Form(form): Form<HashMap<String, String>>| {
                let issuer = token_issuer.clone();
                let nonce = token_nonce.clone();
                let mode = token_mode.clone();
                let started = token_started_signal.clone();
                let release = token_release.clone();
                async move {
                    assert_eq!(form.get("grant_type").map(String::as_str), Some("authorization_code"));
                    assert_eq!(form.get("redirect_uri").map(String::as_str), Some("http://localhost:18080/auth/oidc/callback"));
                    assert_eq!(form.get("client_secret").map(String::as_str), Some("test-secret"));
                    assert!(form.get("code_verifier").is_some_and(|v| !v.is_empty()));
                    if mode.load(Ordering::SeqCst) == 3 {
                        started.notify_one();
                        release.notified().await;
                    }
                    let mut header = jsonwebtoken::Header::new(Algorithm::EdDSA);
                    header.kid = Some("test-key".into());
                    let id_token = jsonwebtoken::encode(
                        &header,
                        &serde_json::json!({
                            "iss":if mode.load(Ordering::SeqCst) == 6 { "https://wrong-issuer.example" } else { issuer.as_str() },
                            "aud":if mode.load(Ordering::SeqCst) == 1 { "wrong-client" } else { "galaxyd" },
                            "sub":"subject", "exp":now() + 3600,
                            "nonce":if mode.load(Ordering::SeqCst) == 5 { "wrong-nonce".to_owned() } else { nonce.lock().await.clone() },
                        }),
                        &jsonwebtoken::EncodingKey::from_ed_pem(TEST_SIGNING_KEY.as_bytes()).unwrap(),
                    ).unwrap();
                    Json(serde_json::json!({"access_token":"access", "refresh_token":"refresh", "id_token":id_token}))
                }
            }))
            .route("/userinfo", get(move || {
                let mode = user_mode.clone();
                async move { Json(serde_json::json!({
                    "sub":if mode.load(Ordering::SeqCst) == 2 { "other" } else { "subject" },
                    "preferred_username":"alice", "groups":if mode.load(Ordering::SeqCst) == 4 { vec!["engineering"] } else { vec!["admins","engineering"] },
                })) }
            }));
        let server = tokio::spawn(async move { axum::serve(listener, provider).await.unwrap() });
        let dir = tempfile::tempdir().unwrap();
        let secret_path = dir.path().join("oidc.secret");
        std::fs::write(&secret_path, "test-secret").unwrap();
        {
            let mut cfg = state.config.write().await;
            cfg.auth.enabled = true;
            cfg.auth.oidc.enabled = true;
            cfg.auth.oidc.issuer_url = issuer;
            cfg.auth.oidc.client_id = "galaxyd".into();
            cfg.auth.oidc.client_secret_file = secret_path;
            cfg.server.public_url = "http://localhost:18080".into();
            cfg.auth.oidc.group_mappings = vec![
                crate::config::GroupMapping {
                    group: "admins".into(),
                    namespaces: vec![],
                    admin: true,
                },
                crate::config::GroupMapping {
                    group: "engineering".into(),
                    namespaces: vec!["engineering".into()],
                    admin: false,
                },
            ];
            cfg.namespaces.push(crate::config::NamespaceConfig {
                name: "engineering".into(),
                push_networks: vec![],
            });
            cfg.namespaces.push(crate::config::NamespaceConfig {
                name: "research".into(),
                push_networks: vec![],
            });
        }
        let app = public_router(state.clone(), true, 1024 * 1024);
        let start = |app: Router, state: AppState, nonce: Arc<Mutex<String>>| async move {
            let response = http_request(app, "GET", "/auth/oidc/login?return_to=%2F", None).await;
            assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
            let location =
                url::Url::parse(response.headers()["location"].to_str().unwrap()).unwrap();
            assert_eq!(
                location
                    .query_pairs()
                    .find(|(key, _)| key == "redirect_uri")
                    .unwrap()
                    .1,
                "http://localhost:18080/auth/oidc/callback"
            );
            let login_state = location
                .query_pairs()
                .find(|(key, _)| key == "state")
                .unwrap()
                .1
                .into_owned();
            assert!(location
                .query_pairs()
                .find(|(key, _)| key == "scope")
                .unwrap()
                .1
                .contains("offline_access"));
            let cookie = response.headers()["set-cookie"]
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .to_owned();
            *nonce.lock().await = state
                .oidc_pending
                .lock()
                .await
                .get(&login_state)
                .unwrap()
                .nonce
                .clone();
            (login_state, cookie)
        };
        let (login_state, cookie) = start(app.clone(), state.clone(), nonce.clone()).await;
        let callback = format!("/auth/oidc/callback?state={login_state}&code=sample-code");
        assert_eq!(
            http_request(
                app.clone(),
                "GET",
                &callback,
                Some(("cookie", "galaxyd_oidc_state=wrong"))
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        let response = http_request(app.clone(), "GET", &callback, Some(("cookie", &cookie))).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let session_cookie = response
            .headers()
            .get_all("set-cookie")
            .iter()
            .find_map(|value| {
                value
                    .to_str()
                    .ok()
                    .filter(|value| value.starts_with("galaxyd_session="))
            })
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let response = http_request(
            app.clone(),
            "GET",
            "/auth/status",
            Some(("cookie", &session_cookie)),
        )
        .await;
        let status: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(status["authenticated"], true);
        assert_eq!(status["admin"], true);
        assert_eq!(status["username"], "alice");
        let response = http_request(
            app.clone(),
            "GET",
            "/api/galaxy/v3/namespaces",
            Some(("cookie", &session_cookie)),
        )
        .await;
        let listing: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(listing["data"].as_array().unwrap().len(), 2);
        assert_eq!(
            http_request(app.clone(), "GET", &callback, Some(("cookie", &cookie)))
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );

        mode.store(4, Ordering::SeqCst);
        let (scoped_state, scoped_cookie) = start(app.clone(), state.clone(), nonce.clone()).await;
        let scoped_callback = format!("/auth/oidc/callback?state={scoped_state}&code=sample-code");
        let response = http_request(
            app.clone(),
            "GET",
            &scoped_callback,
            Some(("cookie", &scoped_cookie)),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let scoped_session = response
            .headers()
            .get_all("set-cookie")
            .iter()
            .find_map(|value| {
                value
                    .to_str()
                    .ok()
                    .filter(|value| value.starts_with("galaxyd_session="))
            })
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let response = http_request(
            app.clone(),
            "GET",
            "/auth/status",
            Some(("cookie", &scoped_session)),
        )
        .await;
        let status: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(status["admin"], false);
        let response = http_request(
            app.clone(),
            "GET",
            "/api/galaxy/v3/namespaces",
            Some(("cookie", &scoped_session)),
        )
        .await;
        let listing: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(listing["data"].as_array().unwrap().len(), 1);
        assert_eq!(
            http_request(
                app.clone(),
                "GET",
                "/api/galaxy/v3/collections/research/common/versions/",
                Some(("cookie", &scoped_session))
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );

        for case in [1, 2, 5, 6] {
            mode.store(case, Ordering::SeqCst);
            let (login_state, cookie) = start(app.clone(), state.clone(), nonce.clone()).await;
            let callback = format!("/auth/oidc/callback?state={login_state}&code=sample-code");
            assert_eq!(
                http_request(app.clone(), "GET", &callback, Some(("cookie", &cookie)))
                    .await
                    .status(),
                StatusCode::UNAUTHORIZED,
                "case {case}"
            );
        }

        mode.store(3, Ordering::SeqCst);
        let (login_state, cookie) = start(app.clone(), state.clone(), nonce.clone()).await;
        let callback = format!("/auth/oidc/callback?state={login_state}&code=sample-code");
        let callback_app = app.clone();
        let pending_callback = tokio::spawn(async move {
            http_request(callback_app, "GET", &callback, Some(("cookie", &cookie))).await
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), token_started.notified())
            .await
            .unwrap();
        let reloaded = state.config.read().await.clone();
        apply_reload(&state, reloaded).await.unwrap();
        release_token.notify_one();
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(2), pending_callback)
                .await
                .unwrap()
                .unwrap()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert!(state.sessions.lock().await.is_empty());
        server.abort();
    }

    #[tokio::test]
    async fn local_login_cookie_logout_origin_and_reload_are_enforced() {
        let state = state().await;
        let dir = tempfile::tempdir().unwrap();
        let hash = argon2::Argon2::default()
            .hash_password(b"correct", &SaltString::generate(&mut OsRng))
            .unwrap()
            .to_string();
        let users = dir.path().join("admins.users");
        std::fs::write(&users, format!("admin:{hash}\n")).unwrap();
        {
            let mut cfg = state.config.write().await;
            cfg.auth.enabled = true;
            cfg.auth.local.enabled = true;
            cfg.auth.local.users_file = users;
        }
        let app = public_router(state.clone(), true, 1024 * 1024);
        let submit = |origin: Option<&str>, password: &str| {
            let mut builder = Request::post("/auth/local/login")
                .header("content-type", "application/x-www-form-urlencoded");
            if let Some(origin) = origin {
                builder = builder.header("origin", origin);
            }
            let mut request = builder
                .body(Body::from(format!("username=admin&password={password}")))
                .unwrap();
            request.extensions_mut().insert(ConnectInfo(
                "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            ));
            request
        };
        assert_eq!(
            app.clone()
                .oneshot(submit(None, "correct"))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            app.clone()
                .oneshot(submit(Some("https://evil.example"), "correct"))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            app.clone()
                .oneshot(submit(Some("http://localhost:8080"), "wrong"))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let response = app
            .clone()
            .oneshot(submit(Some("http://localhost:8080"), "correct"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let cookie = response.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let response = http_request(
            app.clone(),
            "GET",
            "/auth/status",
            Some(("cookie", &cookie)),
        )
        .await;
        let status: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(status["authenticated"], true);
        let mut logout = Request::post("/auth/logout")
            .header("origin", "http://localhost:8080")
            .header("cookie", &cookie)
            .body(Body::empty())
            .unwrap();
        logout.extensions_mut().insert(ConnectInfo(
            "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
        ));
        assert_eq!(
            app.clone().oneshot(logout).await.unwrap().status(),
            StatusCode::SEE_OTHER
        );
        let response = http_request(
            app.clone(),
            "GET",
            "/auth/status",
            Some(("cookie", &cookie)),
        )
        .await;
        let status: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(status["authenticated"], false);

        for _ in 0..5 {
            assert_eq!(
                app.clone()
                    .oneshot(submit(Some("http://localhost:8080"), "wrong"))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::UNAUTHORIZED
            );
        }
        assert_eq!(
            app.clone()
                .oneshot(submit(Some("http://localhost:8080"), "correct"))
                .await
                .unwrap()
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        state.failed_logins.lock().await.clear();

        let old_generation = *state.auth_gate.read().await;
        let reloaded = state.config.read().await.clone();
        apply_reload(&state, reloaded).await.unwrap();
        assert!(
            !remember_session_if_current(
                &state,
                "stale".into(),
                test_session(true, &[]),
                old_generation
            )
            .await
        );
        assert!(!state.sessions.lock().await.contains_key("stale"));
        state.config.write().await.auth.local.users_file = dir.path().join("missing.users");
        assert_eq!(
            app.oneshot(submit(Some("http://localhost:8080"), "correct"))
                .await
                .unwrap()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn oidc_refresh_updates_roles_handles_failures_and_allows_parallel_sessions() {
        use std::sync::atomic::{AtomicU8, AtomicUsize};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let mode = Arc::new(AtomicU8::new(0));
        let seen = Arc::new(Mutex::new(Vec::<String>::new()));
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(tokio::sync::Notify::new());
        let discovery_issuer = issuer.clone();
        let token_mode = mode.clone();
        let token_seen = seen.clone();
        let token_active = active.clone();
        let token_peak = peak.clone();
        let token_release = release.clone();
        let user_mode = mode.clone();
        let provider = Router::new()
            .route("/.well-known/openid-configuration", get(move || {
                let issuer = discovery_issuer.clone();
                async move { Json(serde_json::json!({
                    "issuer": issuer,
                    "token_endpoint": format!("{issuer}/token"),
                    "userinfo_endpoint": format!("{issuer}/userinfo"),
                })) }
            }))
            .route("/token", post(move |Form(form): Form<HashMap<String, String>>| {
                let mode = token_mode.clone();
                let seen = token_seen.clone();
                let active = token_active.clone();
                let peak = token_peak.clone();
                let release = token_release.clone();
                async move {
                    let count = active.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(count, Ordering::SeqCst);
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    active.fetch_sub(1, Ordering::SeqCst);
                    let supplied = form.get("refresh_token").cloned().unwrap_or_default();
                    seen.lock().await.push(supplied.clone());
                    if mode.load(Ordering::SeqCst) == 6 {
                        release.notified().await;
                    }
                    match mode.load(Ordering::SeqCst) {
                        1 => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error":"temporary"}))),
                        2 => (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"invalid_grant"}))),
                        _ => (StatusCode::OK, Json(serde_json::json!({
                            "access_token":"access",
                            "refresh_token": if supplied == "initial" { "rotated" } else { "rotated-again" },
                        }))),
                    }
                }
            }))
            .route("/userinfo", get(move || {
                let mode = user_mode.clone();
                async move {
                    match mode.load(Ordering::SeqCst) {
                        4 => (StatusCode::OK, Json(serde_json::json!({"sub":"different","groups":["engineering"]}))),
                        5 => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error":"temporary"}))),
                        3 => (StatusCode::OK, Json(serde_json::json!({"sub":"subject","groups":["engineering"]}))),
                        _ => (StatusCode::OK, Json(serde_json::json!({"sub":"subject","groups":["engineering","admins"]}))),
                    }
                }
            }));
        let server = tokio::spawn(async move { axum::serve(listener, provider).await.unwrap() });
        let state = state().await;
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("client.secret");
        std::fs::write(&secret, "secret").unwrap();
        {
            let mut cfg = state.config.write().await;
            cfg.auth.enabled = true;
            cfg.auth.oidc.enabled = true;
            cfg.auth.oidc.issuer_url = issuer;
            cfg.auth.oidc.client_id = "galaxyd".into();
            cfg.auth.oidc.client_secret_file = secret;
            cfg.auth.oidc.refresh_interval_seconds = 1;
            cfg.auth.oidc.group_mappings = vec![
                crate::config::GroupMapping {
                    group: "admins".into(),
                    namespaces: vec![],
                    admin: true,
                },
                crate::config::GroupMapping {
                    group: "engineering".into(),
                    namespaces: vec!["engineering".into()],
                    admin: false,
                },
            ];
            cfg.namespaces.push(crate::config::NamespaceConfig {
                name: "engineering".into(),
                push_networks: vec![],
            });
        }
        let stale = || Session {
            username: "subject".into(),
            auth_source: "oidc".into(),
            admin: true,
            namespaces: HashSet::from(["engineering".into()]),
            expires_at: now() + 3600,
            oidc_refresh: Some(OidcRefresh {
                token: "initial".into(),
                subject: "subject".into(),
            }),
            oidc_checked_at: now().saturating_sub(10),
            refresh_lock: Arc::new(Mutex::new(())),
        };
        state.sessions.lock().await.insert("one".into(), stale());
        state.sessions.lock().await.insert("two".into(), stale());
        let app = public_router(state.clone(), true, 1024 * 1024);
        let (one, two) = tokio::join!(
            http_request(
                app.clone(),
                "GET",
                "/auth/status",
                Some(("cookie", "galaxyd_session=one"))
            ),
            http_request(
                app.clone(),
                "GET",
                "/auth/status",
                Some(("cookie", "galaxyd_session=two"))
            ),
        );
        assert_eq!(one.status(), StatusCode::OK);
        assert_eq!(two.status(), StatusCode::OK);
        assert!(
            peak.load(Ordering::SeqCst) >= 2,
            "different users must refresh in parallel"
        );

        state
            .sessions
            .lock()
            .await
            .get_mut("one")
            .unwrap()
            .oidc_checked_at = now().saturating_sub(10);
        mode.store(5, Ordering::SeqCst);
        assert_eq!(
            http_request(
                app.clone(),
                "GET",
                "/auth/status",
                Some(("cookie", "galaxyd_session=one"))
            )
            .await
            .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert!(state.sessions.lock().await.contains_key("one"));
        mode.store(3, Ordering::SeqCst);
        let response = http_request(
            app.clone(),
            "GET",
            "/auth/status",
            Some(("cookie", "galaxyd_session=one")),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["admin"], false);
        assert_eq!(body["namespaces"][0], "engineering");
        assert!(seen
            .lock()
            .await
            .iter()
            .any(|token| token == "rotated-again"));

        state
            .sessions
            .lock()
            .await
            .get_mut("one")
            .unwrap()
            .oidc_checked_at = now().saturating_sub(10);
        mode.store(2, Ordering::SeqCst);
        let response = http_request(
            app.clone(),
            "GET",
            "/auth/status",
            Some(("cookie", "galaxyd_session=one")),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["authenticated"], false);
        assert!(!state.sessions.lock().await.contains_key("one"));

        let mut no_refresh = stale();
        no_refresh.oidc_refresh = None;
        state
            .sessions
            .lock()
            .await
            .insert("no-refresh".into(), no_refresh);
        let response = http_request(
            app.clone(),
            "GET",
            "/auth/status",
            Some(("cookie", "galaxyd_session=no-refresh")),
        )
        .await;
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["authenticated"], false);
        state
            .sessions
            .lock()
            .await
            .get_mut("two")
            .unwrap()
            .oidc_checked_at = now().saturating_sub(10);
        mode.store(4, Ordering::SeqCst);
        let response = http_request(
            app.clone(),
            "GET",
            "/auth/status",
            Some(("cookie", "galaxyd_session=two")),
        )
        .await;
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["authenticated"], false);

        mode.store(6, Ordering::SeqCst);
        state.sessions.lock().await.insert("racing".into(), stale());
        let before = seen.lock().await.len();
        let request = tokio::spawn(http_request(
            app.clone(),
            "GET",
            "/api/galaxy/v3/namespaces",
            Some(("cookie", "galaxyd_session=racing")),
        ));
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while seen.lock().await.len() <= before {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        let reloaded = state.config.read().await.clone();
        let reload_state = state.clone();
        let reload = tokio::spawn(async move { apply_reload(&reload_state, reloaded).await });
        tokio::task::yield_now().await;
        release.notify_one();
        tokio::time::timeout(std::time::Duration::from_secs(2), reload)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let status = tokio::time::timeout(std::time::Duration::from_secs(2), request)
            .await
            .unwrap()
            .unwrap()
            .status();
        assert!(matches!(status, StatusCode::OK | StatusCode::UNAUTHORIZED));
        assert!(!state.sessions.lock().await.contains_key("racing"));
        server.abort();
    }

    #[test]
    fn oidc_group_mapping_replaces_permissions_from_current_groups() {
        let mut cfg = Config::default();
        cfg.auth.oidc.group_mappings = vec![
            crate::config::GroupMapping {
                group: "admins".into(),
                namespaces: vec![],
                admin: true,
            },
            crate::config::GroupMapping {
                group: "engineering".into(),
                namespaces: vec!["engineering".into()],
                admin: false,
            },
        ];
        let (admin, namespaces) = oidc_permissions(&cfg, &HashSet::from(["engineering".into()]));
        assert!(!admin);
        assert_eq!(namespaces, HashSet::from(["engineering".into()]));
        let (admin, namespaces) = oidc_permissions(&cfg, &HashSet::from(["admins".into()]));
        assert!(admin);
        assert!(namespaces.is_empty());
        let (admin, namespaces) = oidc_permissions(&cfg, &HashSet::new());
        assert!(!admin);
        assert!(namespaces.is_empty());
    }

    #[tokio::test]
    async fn local_login_uses_catalog_theme() {
        let state = state().await;
        {
            let mut config = state.config.write().await;
            config.auth.local.enabled = true;
            config.auth.oidc.enabled = true;
            config.auth.oidc.display_name = "Corporate SSO".into();
        }
        let response = public_router(state, true, 128 * 1024 * 1024)
            .oneshot(
                Request::get("/auth/local/login")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let html = String::from_utf8_lossy(&body);
        assert!(html.contains("--surface-raised"));
        assert!(html.contains("galaxyd-theme"));
        assert!(html.contains("autocomplete=\"current-password\""));
        assert!(!html.contains("<h1>galaxyd</h1>"));
        assert!(!html.contains("Powered by galaxyd"));
        assert!(html.contains(".theme { position: absolute;"));
        assert!(html.contains("display: flex; align-items: center;"));
        assert!(html.contains("Login via Corporate SSO"));
    }
}
