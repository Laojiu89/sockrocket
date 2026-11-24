use super::*;
use sockrocket_core::config::listeners::{
    ListenerConfig, ListenerType, listeners_from_yaml, validate_listeners,
};

fn revision(map: &Mapping) -> String {
    let section = map.get("listeners").unwrap_or(&Y::Null);
    content_digest(
        serde_yaml::to_string(section)
            .unwrap_or_default()
            .as_bytes(),
    )
}

fn reserved_ports(map: &Mapping) -> [u16; 4] {
    [
        conf_u16(map, "socks_port", 1080),
        conf_u16(map, "http_port", 1087),
        conf_u16(map, "dns_port", 5300),
        conf_u16(map, "api_port", DEFAULT_API_PORT),
    ]
}

pub(super) fn list() -> J {
    let Ok(map) = load_conf() else {
        return err_msg("配置读取失败");
    };
    let Ok(listeners) = listeners_from_yaml(&map) else {
        return err_msg("入站配置格式无效");
    };
    let rows: Vec<_> = listeners.iter().map(|entry| json!({
        "name": entry.name, "type": entry.protocol, "listen": entry.listen,
        "port": entry.port, "exit": entry.exit, "enabled": entry.enabled,
        "username": entry.username, "has_password": !entry.password.is_empty(), "cipher": entry.cipher,
    })).collect();
    json!({"ok": true, "listeners": rows, "revision": revision(&map), "running": is_running()})
}

pub(super) fn mutate(post: &J, delete: bool) -> J {
    let Ok(mut map) = load_conf() else {
        return err_msg("配置读取失败");
    };
    if post.get("revision").and_then(J::as_str) != Some(revision(&map).as_str()) {
        return err_msg("入站配置已变化，请刷新后重试");
    }
    let Ok(mut entries) = listeners_from_yaml(&map) else {
        return err_msg("入站配置格式无效");
    };
    let original = post.get("original_name").and_then(J::as_str).unwrap_or("");
    let position = entries.iter().position(|entry| entry.name == original);
    if (delete || !original.is_empty()) && position.is_none() {
        return err_msg("找不到要修改的入站，请刷新后重试");
    }
    let running = is_running();
    if delete {
        entries.remove(position.expect("existing listener"));
    } else {
        let Ok(mut entry) = serde_json::from_value::<ListenerConfig>(
            post.get("listener").cloned().unwrap_or(J::Null),
        ) else {
            return err_msg("入站格式无效，请检查监听地址、端口和协议");
        };
        let previous = position.map(|index| &entries[index]);
        if let Some(old) = previous
            && entry.password.is_empty()
            && (entry.protocol == ListenerType::Shadowsocks || !entry.username.is_empty())
            && (entry.protocol == ListenerType::Shadowsocks)
                == (old.protocol == ListenerType::Shadowsocks)
        {
            entry.password.clone_from(&old.password);
        }
        let test_address = entry.address();
        let probe = entry.enabled
            && !entries.iter().any(|old| {
                running
                    && old.enabled
                    && sockrocket_core::config::listeners::overlaps(old.address(), test_address)
            });
        if let Some(index) = position {
            entries[index] = entry;
        } else {
            entries.push(entry);
        }
        if let Err(error) = validate_listeners(&entries, &reserved_ports(&map)) {
            return err_msg(error.to_string());
        }
        if probe && let Err(error) = std::net::TcpListener::bind(test_address) {
            return err_msg(format!("无法监听 {test_address}：{error}"));
        }
    }
    map.insert(
        ykey("listeners"),
        serde_yaml::to_value(&entries).expect("serializable listeners"),
    );
    if let Err(error) = save_conf(&map) {
        return err_msg(format!("保存入站失败：{error}"));
    }
    json!({"ok": true, "msg": if running { "已保存，运行中的服务将重新加载入站配置。" } else { "已保存，启动 Sockrocket 后生效。" }})
}

pub(super) fn validate(map: &Mapping) -> Result<()> {
    validate_listeners(&listeners_from_yaml(map)?, &reserved_ports(map))
}
