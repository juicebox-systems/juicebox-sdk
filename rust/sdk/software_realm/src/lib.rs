use juicebox_sdk_core::types::RealmId;
use juicebox_sdk_process_group::ProcessGroup;
use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::time::sleep;

pub struct RunnerArgs {
    pub id: RealmId,
    pub port: u16,
    pub secrets: HashMap<String, HashMap<u8, String>>,
}

pub struct Runner;

impl Runner {
    pub async fn run(pg: &mut ProcessGroup, args: &RunnerArgs) {
        println!(
            "Starting software realm with id: {:?}, port: {}",
            args.id, args.port
        );
        pg.spawn(
            Command::new("jb-sw-realm")
                .arg("-id")
                .arg(hex::encode(args.id.0))
                .arg("-port")
                .arg(args.port.to_string())
                .stdout(Stdio::null())
                .env(
                    "TENANT_SECRETS",
                    serde_json::to_string(&args.secrets).unwrap(),
                ),
        );
        for _ in 0..100 {
            match reqwest::get(format!("http://0.0.0.0:{}", args.port)).await {
                Ok(response) if response.status().is_success() => return,
                _ => {
                    sleep(Duration::from_millis(10)).await;
                }
            }
        }
        panic!("repeatedly failed to connect to realm");
    }
}
