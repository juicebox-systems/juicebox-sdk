use juicebox_process_group::ProcessGroup;
use juicebox_realm_api::types::RealmId;
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
    // Returns true if the software realm was successfully started.
    pub async fn run(pg: &mut ProcessGroup, args: &RunnerArgs) -> bool {
        println!(
            "Starting software realm with id: {:?}, port: {}",
            args.id, args.port
        );
        let mut child = Command::new("jb-sw-realm")
            .arg("-id")
            .arg(hex::encode(args.id.0))
            .arg("-port")
            .arg(args.port.to_string())
            .stdout(Stdio::null())
            .env(
                "TENANT_SECRETS",
                serde_json::to_string(&args.secrets).unwrap(),
            )
            .spawn()
            .expect("failed to launch jb-sw-realm");

        for _ in 0..100 {
            match reqwest::get(format!("http://0.0.0.0:{}", args.port)).await {
                Ok(response) if response.status().is_success() => {
                    pg.add(child);
                    return true;
                }
                _ => {
                    if let Ok(Some(_exit_code)) = child.try_wait() {
                        // The child process has already exited. This likely due
                        // to a conflict on the port its trying to use
                        return false;
                    }
                    sleep(Duration::from_millis(10)).await;
                }
            }
        }
        false
    }
}
