use anyhow::{Context, Result};
use sockrocket_core::{
    AppConfig,
    config::{storage::write_nodes_and_subscriptions, subscription::parse_subscription_content},
    create_outbound_unwarmed, node_fingerprint,
};
use std::{collections::BTreeSet, fs};

const FIXTURE: &str = include_str!("fixtures/mihomo-nine-protocols.yaml");

#[test]
fn mihomo_subscription_loads_all_nine_protocols_after_save() -> Result<()> {
    let imported = parse_subscription_content(FIXTURE, "auto")?;
    let expected = BTreeSet::from([
        "ss",
        "vmess",
        "vless",
        "trojan",
        "hysteria2",
        "tuic",
        "anytls",
        "mieru",
        "wireguard",
    ]);
    assert_eq!(imported.len(), expected.len());
    assert_eq!(
        imported
            .iter()
            .map(|n| n.protocol.name())
            .collect::<BTreeSet<_>>(),
        expected
    );

    let dir = std::env::temp_dir().join(format!("sr-mihomo-nine-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&dir)?;
    let path = dir.join("config.yaml");
    let config = AppConfig {
        nodes: imported,
        ..AppConfig::default()
    };
    fs::write(&path, serde_yaml::to_string(&AppConfig::default())?)?;
    let saved = write_nodes_and_subscriptions(&path, &config)
        .and_then(|_| Ok(AppConfig::from_yaml_str(&fs::read_to_string(&path)?)?));
    fs::remove_dir_all(dir)?;
    let saved = saved?;
    assert_eq!(saved.nodes.len(), expected.len());
    for (before, after) in config.nodes.iter().zip(&saved.nodes) {
        assert_eq!(after.name, before.name);
        assert_eq!(node_fingerprint(after), node_fingerprint(before));
        create_outbound_unwarmed(after).with_context(|| after.name.clone())?;
    }
    Ok(())
}

#[test]
#[ignore = "requires SOCKROCKET_REFERENCE_MIHOMO"]
fn reference_mihomo_validates_the_same_subscription() -> Result<()> {
    let binary =
        std::env::var_os("SOCKROCKET_REFERENCE_MIHOMO").context("Mihomo executable required")?;
    let dir = std::env::temp_dir().join(format!("sr-mihomo-ref-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&dir)?;
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/mihomo-nine-protocols.yaml");
    let result = std::process::Command::new(binary)
        .args(["-t", "-d"])
        .arg(&dir)
        .arg("-f")
        .arg(fixture)
        .status();
    fs::remove_dir_all(dir)?;
    anyhow::ensure!(result?.success(), "Mihomo rejected the shared fixture");
    Ok(())
}
