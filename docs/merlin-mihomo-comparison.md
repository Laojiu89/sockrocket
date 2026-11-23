# 梅林节点导入与 Mihomo 的协议对照

对照版本为 Mihomo（Clash Meta）v1.19.31。使用同一份含九个节点的 Clash YAML，Mihomo 通过 `-t` 配置校验，Sockrocket 自动识别全部节点，保存并重新读取后节点身份一致，九种协议均可构建出站。测试使用合成凭据和示例地址。逐项联网覆盖另见[协议互通记录](protocols.md#local-interoperability-tests)。

| 协议 | 核对的配置行为 | 使用边界 |
| --- | --- | --- |
| Hysteria2 | 支持独立 SNI、认证、证书指纹、Salamander、Gecko 和跳端口。Clash 的 `ports` 优先于 `port`，支持范围和分隔列表。Clash 导入默认允许 UDP。 | Realms、ECH、客户端证书认证和独立证书校验名不在当前支持范围。证书固定使用叶子证书指纹。 |
| Shadowsocks | 核对了普通 AEAD、SS2022 密钥、原生 UDP 和 ShadowTLS v3。 | ShadowTLS 包装仅支持 TCP。支持 simple-obfs 的 HTTP/TLS 模式，以及 v2ray-plugin 的 WebSocket 和 Mux.Cool。显式要求 SS UDP-over-TCP 的条目会跳过。 |
| VMess | AEAD（`alterId: 0`）、WebSocket、TLS 和 TCP REALITY。WSS 可从不区分大小写的 Host 请求头取得默认 SNI。 | 保留旧版非零 `alterId`。普通 VMess 的 UDP 编码仍有差异。 |
| VLESS | 核对了原生 TLS、WebSocket、WSS 的 Host 与 SNI。显式 `servername` 优先。 | 支持 Xray 的 `mlkem768x25519plus` 加密配置。Vision 对 UDP/443 的处理与 Mihomo 存在差异。 |
| Trojan | 未显式填写 `tls: true` 时也会保留 TLS、SNI 与 ALPN。另测了 gRPC。 | REALITY 限原始 TCP。显式启用 Trojan-Go 的 `ss-opts.enabled` 会跳过。 |
| TUIC | 核对 v5 的 UUID、密码、UDP、QUIC relay 和固定目标 IP。指定 IP 时仍保留用于 TLS 的服务名。 | 不支持 v4 token 和关闭 SNI。 |
| AnyTLS | 原生 TLS、SNI、空闲会话检查与超时、最少空闲会话数。Mihomo 配置中的时间单位为秒。 | 每节点会话池上限 64；不支持 Mihomo 可选的 `client-metadata`。 |
| Mieru | 核对固定端口、TCP、用户名和密码。节点使用标准握手。 | 实验性支持。每条 TCP 连接建立独立会话，不支持 UDP 载体、端口范围或显式要求的多路复用模式。 |
| WireGuard | 核对单 peer 和多 peer，后者按各自的端点、密钥、网段和 reserved 字节处理。 | 原生用户态 WireGuard。AmneziaWG 未实现，隧道 DNS 策略也有差异。 |

HY2 另有运行层回归：在内存传输上运行真实 QUIC、TLS 与 HTTP/3。首个 ALPN 的认证返回 404 后，客户端会尝试下一个候选；收到 233 后保持控制流，TCP 和 UDP 均完成回声测试。供应商节点的证书、认证和路由器网络仍需用实际线路验证。

混合订阅会显示跳过的条数。部分节点不兼容时，刷新会合并可用的新配置并保留未匹配的旧节点；完整刷新时才清理该订阅已移除的节点。

## 复现

```sh
SOCKROCKET_REFERENCE_MIHOMO=/path/to/mihomo \
  cargo test --locked -p sockrocket-core --test mihomo_subscription -- --include-ignored
```

[共同测试配置](../crates/sockrocket-core/tests/fixtures/mihomo-nine-protocols.yaml) · [Mihomo 出站配置手册](https://wiki.metacubex.one/config/proxies/) · [HY2 跳端口](https://wiki.metacubex.one/config/proxies/hysteria2/) · [Mieru 会话模式](https://wiki.metacubex.one/config/proxies/mieru/)
