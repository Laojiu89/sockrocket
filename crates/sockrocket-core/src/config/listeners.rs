use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ListenerType {
    Http,
    Socks,
    Mixed,
    Shadowsocks,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ListenerExit {
    Direct,
    Proxy,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub protocol: ListenerType,
    #[serde(default = "default_listen")]
    pub listen: IpAddr,
    pub port: u16,
    pub exit: ListenerExit,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub username: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub password: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cipher: String,
}

impl std::fmt::Debug for ListenerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ListenerConfig")
            .field("name", &self.name)
            .field("protocol", &self.protocol)
            .field("address", &self.address())
            .field("exit", &self.exit)
            .field("enabled", &self.enabled)
            .finish_non_exhaustive()
    }
}

fn default_enabled() -> bool {
    true
}

fn default_listen() -> IpAddr {
    Ipv4Addr::LOCALHOST.into()
}

impl ListenerConfig {
    pub fn address(&self) -> SocketAddr {
        SocketAddr::new(self.listen, self.port)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.name == self.name.trim()
                && !self.name.is_empty()
                && self.name.len() <= 96
                && !self.name.chars().any(char::is_control),
            "入站名称应为 1–96 字节，首尾不能有空格"
        );
        ensure!(self.port != 0, "监听端口须为 1–65535");
        ensure!(
            !self.listen.is_multicast() && self.listen != IpAddr::V4(Ipv4Addr::BROADCAST),
            "监听地址须为本机 IP 或通配地址"
        );
        ensure!(
            self.password.len() <= 255 && !self.password.chars().any(char::is_control),
            "密码不能包含控制字符，最长 255 字节"
        );
        if self.protocol == ListenerType::Shadowsocks {
            ensure!(self.username.is_empty(), "Shadowsocks 只使用密码认证");
            ensure!(!self.password.is_empty(), "请填写 Shadowsocks 密码");
            ensure!(
                matches!(
                    self.cipher.as_str(),
                    "aes-128-gcm" | "aes-256-gcm" | "chacha20-ietf-poly1305"
                ),
                "请选择支持的 Shadowsocks 加密方式"
            );
            return Ok(());
        }
        ensure!(self.cipher.is_empty(), "只有 Shadowsocks 使用加密方式字段");
        ensure!(
            self.username.len() <= 255
                && !self.username.contains(':')
                && !self.username.chars().any(char::is_control),
            "用户名不能包含冒号或控制字符，最长 255 字节"
        );
        ensure!(
            self.username.is_empty() == self.password.is_empty(),
            "请同时填写用户名和密码"
        );
        Ok(())
    }
}

pub fn validate_listeners(listeners: &[ListenerConfig], reserved_ports: &[u16]) -> Result<()> {
    ensure!(listeners.len() <= 32, "最多可配置 32 个入站");
    let mut names = HashSet::new();
    let mut addresses = Vec::new();
    for listener in listeners {
        listener.validate()?;
        ensure!(
            names.insert(&listener.name),
            "入站名称已存在：{}",
            listener.name
        );
        if listener.enabled {
            let address = listener.address();
            ensure!(
                !reserved_ports.contains(&listener.port)
                    && !addresses.iter().any(|other| overlaps(address, *other)),
                "监听地址或端口已被占用：{address}"
            );
            addresses.push(address);
        }
    }
    Ok(())
}

fn overlaps(a: SocketAddr, b: SocketAddr) -> bool {
    a.port() == b.port() && (a.ip() == b.ip() || a.ip().is_unspecified() || b.ip().is_unspecified())
}

pub fn listeners_from_yaml(map: &serde_yaml::Mapping) -> Result<Vec<ListenerConfig>> {
    match map.get("listeners") {
        Some(value) => {
            serde_yaml::from_value(value.clone()).map_err(|_| anyhow::anyhow!("入站配置格式无效"))
        }
        None => Ok(Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lan_listener_credentials_are_optional_except_for_shadowsocks() {
        let mut listener: ListenerConfig = serde_yaml::from_str(
            "name: example\ntype: mixed\nlisten: 192.0.2.1\nport: 18080\nexit: direct\n",
        )
        .unwrap();

        for protocol in [ListenerType::Http, ListenerType::Socks, ListenerType::Mixed] {
            listener.protocol = protocol;
            assert!(listener.validate().is_ok());
            listener.username = "user".into();
            assert!(listener.validate().is_err());
            listener.password = "test-password".into();
            assert!(listener.validate().is_ok());
            listener.username.clear();
            assert!(listener.validate().is_err());
            listener.password.clear();
        }

        listener.protocol = ListenerType::Shadowsocks;
        listener.cipher = "aes-128-gcm".into();
        assert!(listener.validate().is_err());
        listener.password = "test-password".into();
        assert!(listener.validate().is_ok());
    }
}
