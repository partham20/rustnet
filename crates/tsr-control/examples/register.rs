//! Smoke test: register with a control server and print the first netmap.
//! `cargo run -p tsr-control --example register -- http://headscale:8080 <authkey>`

use tsr_control::{client::ControlClient, keys::PrivateKey, tailcfg::*, CAPABILITY_VERSION};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("debug,h2=info")
        .init();
    let args: Vec<String> = std::env::args().collect();
    let server: url::Url = args[1].parse()?;
    let machine = PrivateKey::generate();
    let node = PrivateKey::generate();
    let disco = PrivateKey::generate();
    let hostinfo = Hostinfo {
        hostname: "tsr-smoke".into(),
        os: "linux".into(),
        ipn_version: "1.84.0-tsr".into(),
        ..Default::default()
    };

    let mut c = ControlClient::connect(&server, &machine).await?;
    let resp = c
        .register(&RegisterRequest {
            version: CAPABILITY_VERSION,
            node_key: node.node_public(),
            auth: Some(RegisterResponseAuth {
                auth_key: args[2].clone(),
            }),
            hostinfo: hostinfo.clone(),
            ..Default::default()
        })
        .await?;
    println!("register: {resp:?}");
    let mut map = c
        .map(&MapRequest {
            version: CAPABILITY_VERSION,
            node_key: node.node_public(),
            disco_key: disco.disco_public(),
            hostinfo,
            stream: true,
            keep_alive: true,
            ..Default::default()
        })
        .await?;
    let m = map.next().await?.expect("one map response");
    let n = m.node.unwrap();
    println!(
        "self: {} {:?}; {} peers",
        n.name,
        n.addresses,
        m.peers.map_or(0, |p| p.len())
    );
    Ok(())
}
