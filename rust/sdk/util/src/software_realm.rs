use juicebox_sdk_core::types::RealmId;
use std::collections::HashMap;
use std::process::Command;

use crate::process_group::ProcessGroup;

pub struct Args {
    id: RealmId,
    port: u16,
    secrets: HashMap<String, HashMap<u8, String>>,
}

pub struct Runner;

impl Runner {
    pub async fn run(pg: &mut ProcessGroup, args: &Args) {
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
                .env(
                    "TENANT_SECRETS",
                    serde_json::to_string(&args.secrets).unwrap(),
                ),
        );
    }
}
