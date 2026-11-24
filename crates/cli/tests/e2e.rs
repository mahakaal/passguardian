//! End to end: the real CLI code against the real router, two devices, no mocks of the API.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use passguardian_cli::{Cli, CliError, Item};
use passguardian_core::KdfParams;
use passguardian_server_api::tokens::TokenSigner;
use passguardian_server_api::{router, AppState};
use passguardian_server_domain::testing::{InMemoryStore, ManualClock, SequentialIds};
use passguardian_server_domain::Timestamp;

const FAST: KdfParams = KdfParams {
    memory_kib: 64,
    iterations: 1,
    parallelism: 1,
};

/// Starts the server on a random port in its own thread and returns its address.
fn start_server() -> String {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let state = AppState::new(
                InMemoryStore::new(),
                ManualClock::new(Timestamp::from_unix_seconds(1_000_000)),
                SequentialIds::new(),
                TokenSigner::new(&[9; 32]).unwrap(),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            tx.send(listener.local_addr().unwrap()).unwrap();
            axum::serve(listener, router(state)).await.unwrap();
        });
    });
    format!("http://{}", rx.recv().unwrap())
}

fn device(name: &str) -> (Cli, PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "passguardian-e2e-{}-{name}-{}",
        std::process::id(),
        uuid_like()
    ));
    (Cli::new(dir.clone()).with_kdf(FAST), dir)
}

fn uuid_like() -> String {
    format!("{:?}", std::time::Instant::now()).replace(|c: char| !c.is_alphanumeric(), "")
}

fn item(name: &str, password: &str) -> Item {
    Item {
        name: name.into(),
        username: "manu".into(),
        password: password.into(),
        url: "https://example.org".into(),
        notes: String::new(),
    }
}

#[test]
fn two_devices_share_one_vault() {
    let server = start_server();
    let (laptop, laptop_dir) = device("laptop");
    let (phone, phone_dir) = device("phone");
    let master = "correct horse battery staple";

    laptop
        .register(&server, "manu@example.org", master, "laptop")
        .unwrap();
    let id = laptop.add(master, &item("GitHub", "s3cret-one")).unwrap();
    laptop.add(master, &item("Bank", "s3cret-two")).unwrap();

    // The second device logs in with only the email and the password.
    phone
        .login(&server, "manu@example.org", master, "phone")
        .unwrap();
    let names: Vec<_> = phone
        .list(master)
        .unwrap()
        .into_iter()
        .map(|e| e.item.name)
        .collect();
    assert_eq!(names, ["Bank", "GitHub"]);
    assert_eq!(
        phone.get(master, "github").unwrap().item.password,
        "s3cret-one"
    );
    assert_eq!(phone.get(master, &id).unwrap().item.name, "GitHub");

    // A deletion on one device reaches the other.
    phone.delete(master, "Bank").unwrap();
    assert_eq!(laptop.list(master).unwrap().len(), 1);
    assert!(matches!(
        laptop.get(master, "Bank"),
        Err(CliError::ItemNotFound(_))
    ));
    let (revision, count) = laptop.status(master).unwrap();
    assert_eq!((revision, count), (3, 1));

    for dir in [laptop_dir, phone_dir] {
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[test]
fn wrong_password_and_logged_out_devices_get_nothing() {
    let server = start_server();
    let (laptop, laptop_dir) = device("laptop2");
    let (phone, phone_dir) = device("phone2");
    laptop
        .register(&server, "ada@example.org", "right password", "laptop")
        .unwrap();
    laptop.add("right password", &item("Mail", "pw")).unwrap();

    assert!(phone
        .login(&server, "ada@example.org", "wrong password", "phone")
        .is_err());
    assert!(matches!(
        phone.list("right password"),
        Err(CliError::NotLoggedIn)
    ));
    assert!(matches!(
        laptop.list("wrong password"),
        Err(CliError::WrongPassword)
    ));

    laptop.logout().unwrap();
    assert!(matches!(
        laptop.list("right password"),
        Err(CliError::NotLoggedIn)
    ));

    for dir in [laptop_dir, phone_dir] {
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[test]
fn the_session_file_is_private_and_holds_no_password() {
    let server = start_server();
    let (laptop, dir) = device("laptop3");
    laptop
        .register(&server, "eve@example.org", "hunter2 hunter2", "laptop")
        .unwrap();
    let text = std::fs::read_to_string(dir.join("session.json")).unwrap();
    assert!(!text.contains("hunter2"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.join("session.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "session file readable by others");
    }
    let _ = std::fs::remove_dir_all(dir);
}
