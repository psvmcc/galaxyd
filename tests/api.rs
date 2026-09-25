#[test]
fn example_configuration_files_are_present() {
    for path in [
        "config/galaxyd.example.toml",
        "config/galaxyd.example.yaml",
        "config/galaxyd.auth.local.example.toml",
        "config/galaxyd.auth.local.example.yaml",
        "config/galaxyd.auth.oidc.example.toml",
        "config/galaxyd.auth.oidc.example.yaml",
    ] {
        galaxyd::config::Config::load(std::path::Path::new(path))
            .unwrap_or_else(|error| panic!("invalid example config {path}: {error}"));
    }
    assert!(std::path::Path::new("static/index.html").exists());
    assert!(std::path::Path::new("static/login.html").exists());
}

#[tokio::test]
async fn exposes_ansible_collection_version_contract() {
    use axum::{body::Body, http::Request};
    use galaxyd::{
        app::{public_router, AppState},
        config::{Config, NamespaceConfig},
        galaxy::CollectionMeta,
        storage::{LocalStorage, Record, Storage},
    };
    use http_body_util::BodyExt;
    use prometheus_client::{metrics::counter::Counter, registry::Registry};
    use sha2::{Digest, Sha256};
    use std::{
        collections::HashMap,
        sync::{atomic::AtomicBool, Arc},
    };
    use tokio::sync::{Mutex, RwLock};
    use tower::ServiceExt;

    let dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(LocalStorage::new(dir.path().to_path_buf()));
    let bytes = b"artifact";
    storage
        .publish(
            &Record {
                meta: CollectionMeta {
                    namespace: "engineering".into(),
                    name: "common".into(),
                    version: "1.2.3".into(),
                    dependencies: serde_json::json!({}),
                },
                sha256: galaxyd::galaxy::hex(&Sha256::digest(bytes)),
                size: bytes.len(),
                artifact: "artifact.tar.gz".into(),
                published_at: 1,
            },
            bytes,
        )
        .await
        .unwrap();
    let mut config = Config::default();
    config.namespaces.push(NamespaceConfig {
        name: "engineering".into(),
        push_networks: vec![],
    });
    let state = AppState {
        config: Arc::new(RwLock::new(config)),
        storage,
        ready: Arc::new(AtomicBool::new(true)),
        requests: Counter::default(),
        registry: Arc::new(RwLock::new(Registry::default())),
        tasks: Arc::new(Mutex::new(HashMap::new())),
        catalog: Arc::new(RwLock::new(vec![Record {
            meta: CollectionMeta {
                namespace: "engineering".into(),
                name: "common".into(),
                version: "1.2.3".into(),
                dependencies: serde_json::json!({}),
            },
            sha256: galaxyd::galaxy::hex(&Sha256::digest(bytes)),
            size: bytes.len(),
            artifact: "artifact.tar.gz".into(),
            published_at: 1,
        }])),
        sessions: Arc::new(Mutex::new(HashMap::new())),
        oidc_pending: Arc::new(Mutex::new(HashMap::new())),
        upload_slots: Arc::new(tokio::sync::Semaphore::new(2)),
        auth_slots: Arc::new(tokio::sync::Semaphore::new(16)),
        failed_logins: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        auth_gate: Arc::new(RwLock::new(0)),
        refresh_slots: Arc::new(tokio::sync::Semaphore::new(8)),
        publications: tokio_util::task::TaskTracker::new(),
    };
    let app = public_router(state, true, 16 * 1024 * 1024);
    let response = app
        .clone()
        .oneshot(
            Request::get("/api/galaxy/v3/collections/engineering/common/versions/1.2.3/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let json: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(
        json["artifact"]["sha256"],
        galaxyd::galaxy::hex(&Sha256::digest(bytes))
    );
    assert_eq!(json["metadata"]["dependencies"], serde_json::json!({}));

    let response = app
        .oneshot(
            Request::get("/api/galaxy/v3/artifacts/engineering/common/1.2.3/")
                .extension(axum::extract::ConnectInfo(
                    "127.0.0.1:12345".parse::<std::net::SocketAddr>().unwrap(),
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers()["content-length"],
        bytes.len().to_string()
    );
    assert_eq!(
        response.headers()["content-disposition"],
        "attachment; filename=\"engineering-common-1.2.3.tar.gz\""
    );
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        bytes.as_slice()
    );
}

#[tokio::test]
async fn accepts_multipart_larger_than_axum_default_limit() {
    use axum::{body::Body, extract::ConnectInfo, http::Request};
    use base64::Engine;
    use flate2::{write::GzEncoder, Compression};
    use galaxyd::{
        app::{public_router, AppState},
        config::{Config, NamespaceConfig},
        storage::LocalStorage,
    };
    use prometheus_client::{metrics::counter::Counter, registry::Registry};
    use sha2::{Digest, Sha256};
    use std::{
        collections::HashMap,
        net::SocketAddr,
        sync::{atomic::AtomicBool, Arc},
    };
    use tokio::sync::{Mutex, RwLock};
    use tower::ServiceExt;

    let dir = tempfile::tempdir().unwrap();
    let token_dir = tempfile::tempdir().unwrap();
    std::fs::write(token_dir.path().join("engineering.secrets"), "secret\n").unwrap();
    let mut config = Config {
        token_dir: token_dir.path().to_path_buf(),
        ..Config::default()
    };
    config.network.max_upload_bytes = 8 * 1024 * 1024;
    config.namespaces.push(NamespaceConfig {
        name: "engineering".into(),
        push_networks: vec![],
    });
    let state = AppState {
        config: Arc::new(RwLock::new(config)),
        storage: Arc::new(LocalStorage::new(dir.path().to_path_buf())),
        ready: Arc::new(AtomicBool::new(true)),
        requests: Counter::default(),
        registry: Arc::new(RwLock::new(Registry::default())),
        tasks: Arc::new(Mutex::new(HashMap::new())),
        catalog: Arc::new(RwLock::new(Vec::new())),
        sessions: Arc::new(Mutex::new(HashMap::new())),
        oidc_pending: Arc::new(Mutex::new(HashMap::new())),
        upload_slots: Arc::new(tokio::sync::Semaphore::new(2)),
        auth_slots: Arc::new(tokio::sync::Semaphore::new(16)),
        failed_logins: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        auth_gate: Arc::new(RwLock::new(0)),
        refresh_slots: Arc::new(tokio::sync::Semaphore::new(8)),
        publications: tokio_util::task::TaskTracker::new(),
    };

    let mut payload = vec![0u8; 3 * 1024 * 1024];
    let mut value = 0x1234_5678u32;
    for byte in &mut payload {
        value ^= value << 13;
        value ^= value >> 17;
        value ^= value << 5;
        *byte = value as u8;
    }
    let payload_sha = galaxyd::galaxy::hex(&Sha256::digest(&payload));
    let files = serde_json::to_vec(&serde_json::json!({"files":[{"name":"payload.bin","ftype":"file","chksum_sha256":payload_sha}]})).unwrap();
    let files_sha = galaxyd::galaxy::hex(&Sha256::digest(&files));
    let manifest = serde_json::to_vec(&serde_json::json!({
        "collection_info":{"namespace":"engineering","name":"common","version":"1.0.0","dependencies":{}},
        "file_manifest_file":{"chksum_sha256":files_sha}
    })).unwrap();
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    {
        let mut archive = tar::Builder::new(&mut encoder);
        for (name, bytes) in [
            ("MANIFEST.json", manifest.as_slice()),
            ("FILES.json", files.as_slice()),
            ("payload.bin", payload.as_slice()),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_path(name).unwrap();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive.append(&header, bytes).unwrap();
        }
        archive.finish().unwrap();
    }
    let artifact = encoder.finish().unwrap();
    assert!(artifact.len() > 2 * 1024 * 1024);
    let checksum = galaxyd::galaxy::hex(&Sha256::digest(&artifact));
    let boundary = "galaxyd-boundary";
    let mut body = Vec::new();
    body.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"sha256\"\r\n\r\n{checksum}\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"collection.tar.gz\"\r\nContent-Type: application/gzip\r\n\r\n").as_bytes());
    body.extend_from_slice(&artifact);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let mut request = Request::post("/api/galaxy/v3/artifacts/collections/")
        .header(
            "content-type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .header("authorization", "Token secret")
        .body(Body::from(body))
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
    ));
    let response = public_router(state.clone(), true, 8 * 1024 * 1024)
        .oneshot(request)
        .await
        .unwrap();
    assert_eq!(response.status(), 202);

    let encoded = base64::engine::general_purpose::STANDARD.encode(&artifact);
    let base64_body = format!("--{boundary}\r\nContent-Disposition: form-data; name=\"sha256\"\r\n\r\n{checksum}\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"collection.tar.gz\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{encoded}\r\n--{boundary}--\r\n");
    assert!(base64_body.len() > artifact.len() + 1024 * 1024);
    let request = || {
        let mut request = Request::post("/api/galaxy/v3/artifacts/collections/")
            .header(
                "content-type",
                format!("multipart/form-data; boundary={boundary}"),
            )
            .header("authorization", "Token secret")
            .body(Body::from(base64_body.clone()))
            .unwrap();
        request.extensions_mut().insert(ConnectInfo(
            "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
        ));
        request
    };
    let decoded_limit = artifact.len();
    state.config.write().await.network.max_upload_bytes = decoded_limit;
    assert!(base64_body.len() > decoded_limit + 1024 * 1024);
    let response = public_router(state.clone(), true, decoded_limit)
        .oneshot(request())
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        409,
        "decoded archive reached duplicate check"
    );

    state.config.write().await.network.max_upload_bytes = 1024 * 1024;
    let response = public_router(state, true, 1024 * 1024)
        .oneshot(request())
        .await
        .unwrap();
    assert_eq!(response.status(), 413);
}
