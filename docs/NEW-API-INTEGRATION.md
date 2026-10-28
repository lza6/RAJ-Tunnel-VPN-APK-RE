# new-api 对接指南 — RAJ Tunnel / BD Tunnel 白标家族

> 面向：由**另一个会话**执行 new-api 侧落地的人。
> 本文件只讲“怎么接”，逆向细节见 [`REVERSE_REPORT.md`](./REVERSE_REPORT.md)。

## 0. 一句话结论（先读，避免白干）

- 本家族的 app **只提供 OpenVPN / SSH / V2Ray / DNSTT 端点**，**不提供** http/socks 出口代理。
- 这些端点要进 new-api 代理池，**必须先在本地起隧道桥接成 `socks5://127.0.0.1:PORT`**，new-api 侧只认 socks5/http URL。
- 节点来源是运营方发布的**加密配置串**（不是 API、不是订阅），所以链路是：配置串 → 解密 → 端点清单 → 本地桥 → 代理池文件。
- **红线**：解出来的节点是第三方运营方自有 VPS。按既定口径，**不入生产池**，只能做研究/demo；生产池仍用自有 VPS 或已授权来源。

## 1. 数据流

```
[base64 配置串]                          ← 运营方发布 / res/raw/servers / filesDir/classes3.dex!a.rlb
      │  python tools/raj_decrypt.py blob.txt      (或 POST /api/decrypt)
      ▼
[配置 JSON]  Servers[]: ServerIPHost / OpenVPNTCPPort / OpenVPNSSLPort / Username / Password
              Networks[]: SNIHost / TunnelType / Payload（注入模板，非节点）
      │  python tools/harvest.py blob.txt -o out
      ▼
out/nodes.json  out/proxies.txt  out/socks_template.txt
      │  每个节点起一个本地桥（openvpn / xray / sing-box）
      ▼
socks5://127.0.0.1:1080x   ← 写进 TRYINGOPEN_PROXY_FILE
      ▼
new-api 代理池（后台「代理池」卡片 / AcquireForChannel）
```

## 2. 解密：拿到端点清单

配置串是三层：`base64 → AES-128-CBC(K[0:16], iv=0, PKCS7) → XXTEA(K[0:16])`，
`K = SHA256("T}wcex;{(*~$4M5XZtd!zK")`。**已内置在工具里，不用你重算。**

```bash
cd tools

# 单串 → 打印解密后的完整配置
python raj_decrypt.py ../samples/blob_1.5.txt

# 批量 → 产出 nodes.json / proxies.txt / socks_template.txt
python harvest.py ../samples -o ../out
# 需要顺手测活/压测
python harvest.py ../samples -o ../out --probe
python harvest.py ../samples -o ../out --bench 32 --rounds 3
```

> 字段说明：`ServerIPHost` / 端口 / `Name` 都是**逐字段独立加密**的，工具已还原；
> 端口字段尾部有 XXTEA 对齐填充（如 `1194\x04\x00\x00\x00`），工具已剥离。

## 3. 协议判定与桥接方式

| `Protocol` | 含义 | 桥接方案 | 备注 |
|---|---|---|---|
| `0` | OpenVPN（TCP/SSL 端口） | `openvpn --config x.ovpn` + `tun2socks`/`gost` 转 socks5 | 需要 `Username`/`Password` 或证书；`res/raw/a.ovpn` 是模板（`remote 0.0.0.0 1194`，带 vendor 自签 CA） |
| `TunnelType=0` + `SNIHost` | SNI/HTTP payload 注入（“免费上网”穿刺） | **不适用** | 那是穿透计费网关的 payload 引擎（`[split]/[delay_split]/[random]/[repeat]/[ua]`），不是代理 |
| v2ray 导入（`vless:// vmess:// trojan:// hysteria2://`） | 走内置 Xray core | 直接用 `xray`/`sing-box` 起 `socks` inbound | 需运营方另外给出对应 URI |
| DNSTT（`libotensahorse.so`） | DNS 隧道 | `dnstt-client` + `tun2socks` | 慢，不适合池子 |

生成 OVPN 配置示例（把 `<HOST>` / `<PORT>` / 账号替换成 `nodes.json` 的值，CA 用 `apktool_out/res/raw/a.ovpn` 里的 `<ca>`）：

```
client
dev tun
proto tcp
remote <HOST> <PORT>
cipher none
auth none
auth-user-pass /etc/raj/<HOST>.auth
redirect-gateway def1
setenv CLIENT_CERT 0
verb 3
```

一个可用最小桥（每个节点一套）：

```bash
openvpn --config /etc/raj/node1.ovpn --daemon raj-node1
gost -L socks5://127.0.0.1:10801 -F direct      # 或 tun2socks 绑定 tun 网卡
curl -s --socks5-hostname 127.0.0.1:10801 https://api.ipify.org    # 验证真实出口
```

> **验收口径**：必须用上面那条 `curl` 看到**不同于本机**的出口 IP，TCP 握手成功不算通过。

## 4. 写入 new-api 代理池

代码位置：`relay/channel/tryingopen/proxy_pool.go`

- 环境变量 `TRYINGOPEN_PROXY_FILE` 指向一个文本文件，**每行一个代理 URL**，`#` 开头为注释。
- 静态池是全量替换语义（重建时按文件为准），免费池抓取周期由 `proxy_pool_setting.free_fetch_minutes` 控制（默认 30 分钟，越界回落 30）。
- 每行格式：`scheme://[user:pass@]host:port`，支持把节点标记写在行内。

`out/socks_template.txt` 已是可直接改的模板，填端口后：

```bash
TRYINGOPEN_PROXY_FILE=/opt/raj/out/socks_template.txt
```

```text
socks5://127.0.0.1:10801#raj-1-sa-riyadh
socks5://127.0.0.1:10802#raj-2-ae-dubai
```

重载：调用 `LoadProxies()`（进程内函数，改文件后重启服务或触发重载入口即可），
后台「代理池」卡片会按**每个文件独立一张卡**显示（该行为已在既有实现里固定）。

## 5. Demo API 契约（本地联调可直接用）

`python demo/server.py` → `http://127.0.0.1:8960`

| 方法 | 路径 | 请求 | 响应 |
|---|---|---|---|
| GET | `/api/builtin` | – | `{mykey, sha256, config, nodes}`：解包内置 `res/raw/servers` |
| POST | `/api/decrypt` | `{"blob":"<base64>"}` | 同上（任意配置串） |
| POST | `/api/probe` | `{"nodes":[…],"timeout":3}` | `{results:[{host,port,alive,ms,error}], summary}` |
| POST | `/api/bench` | `{"nodes":[…],"workers":32,"rounds":3,"timeout":3}` | `{attempts,alive,alive_rate,p50_ms,p95_ms,p99_ms,conn_per_s,…}` |

```bash
curl -s localhost:8960/api/builtin | jq '.config.Servers[0]'
curl -s -X POST localhost:8960/api/decrypt -H 'Content-Type: application/json' \
     -d "{\"blob\":\"$(cat samples/blob_1.5.txt)\"}" | jq '.nodes'
```

## 6. 本样本的实测边界（别抱错误期待）

| 项 | 值 |
|---|---|
| 内置配置（1.5 与 Play 最新 1.7 一致，MD5 `ee9a8675…`） | `ServerIPHost=0.0.0.0`、`Name="Please update config first"`、TCP `1194`、SSL `443`、`flag=xx` |
| 内置节点测活 | `dead`（`WinError 10049`，地址非法） |
| 节点枚举 | **0 条可连通端点** |
| 压测链路（外部样本池 67 节点 × 3 轮 × 32 并发） | 存活率 37.3%、p50 71 ms、p95 261.9 ms、10.7 conn/s（样本非本 app，仅证明工具链） |

所以：**在拿到运营方发布的真实配置串之前，这段对接不会产出任何代理 IP。**
拿到串之后，第 2～4 步是全自动的。

## 7. 待确认（交给对接会话时一并确认）

1. `Protocol` 的非 0 取值语义（需一份非占位符配置对照）。
2. 每个 OVPN 端点是否需要 `Username/Password`（占位符里是空的）；无凭据时需证书。
3. 桥接进程编排方式：一节点一进程（简单、资源随节点线性增长）vs 单实例多 tun（复杂、省内存）。
4. 池子定位：研究/demo 池 or 生产池（红线：第三方节点不入生产池）。
