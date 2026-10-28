# RAJ Tunnel VPN 1.5 (com.rj.rajtunnelvpn) 逆向报告

> 样本：`Desktop/逆向产物/RAJ_Tunnel_VPN_1.5_Mod.apk`（77,607,025 B）
> 工作区：`Desktop/逆向产物/raj_ws/`
> 结论速览：**配置加密三层已全部还原（含密钥，可双向加解密）**；但**该 APK 内置的服务器配置是占位符**（`0.0.0.0` / “Please update config first”），**本包不构成代理池来源**。

---

## 1. 样本结构与处理链

| 层 | 内容 | 判定 |
|---|---|---|
| 外层 APK | `classes*.dex`（8,231,956 / 6,778,048 / 6,719,960 B）、`lib/arm64-v8a/*`、`res/raw/{a.ovpn,b.xml,c,d.js}` | 已被 Mod 二次打包 |
| Mod 壳 | 目录 `بسم الله/`：`origin.apk`（33,061,256 B 原始包）+ `lib/{arm,arm64,x86,x86_64}.so`（加载器）+ `dex/README.txt`（“dex放置此处可动态加载”） | ApkSignatureKiller / 动态加载式壳 |
| 原始包 | `origin.apk`：3 个 dex（8,174,100 / 6,581,304 / 6,619,916 B），**无 lib/**（原生库被提到外层） | 干净业务代码 |
| 差异 | 外层 dex 比 origin 各大约 57 KB | 签名校验/广告位被 patch（未新增网络请求，见 §6） |

## 2. 技术栈

`renz.javacodez.v2ray.*` = **v2rayNG 分支**（保留 `AppConfig`/`EConfigType`/`2dust` 相关常量），叠加 vendor 自有模块：

| 组件 | 载体 | 用途 |
|---|---|---|
| Xray core | `libgojni.so` 29.5 MB | VMess/VLESS/Trojan/SS/WireGuard/TUIC/Hysteria2 出站；socks:10808、http:10809 |
| hysteria2 | `libhysteria2.so` 20.0 MB | UDP 加速隧道 |
| OpenVPN3 | `libovpn3.so` 7.0 MB | OVPN（**加密与签名校验代码被注入这个库**） |
| DNSTT | `libotensahorse.so` 2.38 MB（Go） | DNS 隧道 |
| tun2socks / pdnsd / v2raysocks | `libtun2socks.so` / `libpdnsd.so` / `libv2raysocks.so` | TUN→SOCKS、本地 DNS |
| SSH | `SSHVPNService` + `libudp.so` | SSH/UDP 自定义节点 |

`AndroidManifest` 关键组件：`RAJTunnelVPNMain`（主界面）、`RenzOpenVPNservice`（OpenVPN 前台服务 + **payload 注入引擎**）、`SSHVPNService`、`TimeManagerService`（免费时长）、`V2RayVpnService`、`wifi tethering ProxyService`。

## 3. 保护与混淆（全部已破）

### 3.1 Java 字符串表混淆 —— `defpackage.xl.a(long)`
自实现 PRNG（16-bit Feistel 混合 `j7.Z`）+ 33,393 字符串表，索引由 `long` 常量经哈希得到。

* 已复现：`tools/xl_decrypt.py`（纯 Python，零依赖）
* 覆盖：dex 内 **1,078** 条独立常量全部解出 → `xl_strings.json` / `xl_strings.txt`
* 校验样本：`equals`、`com.rj.rajtunnelvpn`、`App_dex`、`127.0.0.1`、`com.rj.rajtunnelvpn`（package 名）均正确

### 3.2 Native 字符串混淆 —— `ay::obfuscated_data<N,S,char>`
ADVobfuscator 风格模板，算法在不静态依赖符号的情况下由 `decrypt()` 内联代码确认：

```
plain[i] = data[i] ^ (S >> ((i % 8) * 8)) & 0xFF ；对象尾部偏移 N 处为初始化标志字节
```

* 已复现：`tools/ay_deobf.py`
* 校验：`obfuscated_data<7,1951716699498820017>` → `equals`；`<20,387…>` → `com.rj.rajtunnelvpn`；`<15,17721…>` → `SqtPackaSqName`

### 3.3 反篡改 / 水印
`libovpn3.so` 导出 `Java_renz_javacodez_vpn_utils_RenzUtils_{checkAppSign,isGood,play,helloWorld,stayHumbleAlways,readServer,writeServer,readPayload,writePayload}`：

* `checkAppSign(Context)`：签名校验，失败 → `za1.g()` 判定 resources 被改 → `Process.killProcess`
* `play(CountDownTimer)` / `za1.l()`：从 assets 释放音频并**锁定媒体音量**（防录音绕过广告）
* `helloWorld()` / `stayHumbleAlways()` 返回 vendor 水印：`https://t.me/PHRenzOrigin`
* `readServer/writeServer` 反射调用 `renz.javacodez.v2ray.service.{ServerEncryptor,NetworkEncryptor}` —— **这两个类在本 app 内不存在**，是 vendor 其他产品的残留（同样的 `com.rj.rajtunnelvpn` 硬编码在其中）

## 4. 配置加密：三层，全破

`ConfigReader`（`renz/javacodez/vpn/activities/b.java#w()`）读取顺序：
1. `filesDir/classes3.dex`（实为 zip，条目 `a.rlb`）→ 存在则用
2. 否则 `res/raw/servers`（本包 = `res/raw/d.js`，1,388 B base64）

两者都交给 `za1.b(ctx, text)` → `RenzUtils.decrypt(ctx, bytes)`。JNI 实现（`libovpn3.so @ 0x3a30d4`，1,600 B）反汇编后完整链路：

```
myKey   = "T}wcex;{(*~$4M5XZtd!zK"          # rodata 0x1ff1f0(16B)+0x1ff448(8B) 经 XOR 解出
K       = SHA256(myKey)                      # strlen(myKey) 后 SHA256_Init/Update/Final
buf     = base64_decode(input)               # 标准字母表
aes     = AES-128-CBC(key=K[0:16], iv=00*16) # EVP_aes_128_cbc + set_padding(1)
plain   = XXTEA_decrypt(aes, key=K[0:16])    # 4×uint32 LE，delta 0x9E3779B9
```

* `K` = `a462d0b9c9ef56c81eedc2404c1c01714c9cb7ba7e4fa17584bc6db80ef05867`
* **字段级复用同一管线**：`ServerIPHost`、`Name`、`flag`、端口等字段各自是独立 base64 串，同样是 AES→XXTEA（无外层 base64 差异）
* 坑：端口字段 XXTEA 尾部残留对齐填充（如 `1194\x04\x00\x00\x00`），需剥离
* 工具：`tools/raj_decrypt.py`（解）、`tools/raj_encrypt.py`（打包，**round-trip 自检通过**）

原始解密输出（未做字段解密）：

```json
{"Version":"1.0","Servers":[{"Name":"<enc>","ServerIPHost":"<enc>","OpenVPNTCPPort":"<enc>",...}]}
```

## 5. 内置配置 = 占位符（决定性证据）

`GET /api/builtin` 实际输出：

```
Version 1.0
Servers[0]  Name="Please update config first"  ServerIPHost=0.0.0.0  OpenVPNTCPPort=1194  OpenVPNSSLPort=443  flag="xx"
Networks[0] Name="Please update config first"  SNIHost=""  TunnelType=0  TLSVersion="Default"
SSLNetworks []   Username="ewgweg"  Password="weghwerhw"
```

测活（TCP）：`0.0.0.0:1194 → dead (WinError 10049)`。

### 5.1 双版本交叉验证（决定性）

| 版本 | 来源 | `res/raw/servers` MD5 |
|---|---|---|
| 1.5（Mod 样本） | 本地 `RAJ_Tunnel_VPN_1.5_Mod.apk` | `ee9a867534958bd5ae27f52912e6e6a6` |
| **1.7 / versionCode 17**（Play 最新，2026-09-22，商店名 “BD Tunnel MAX”） | `d.apkpure.net` XAPK 直链下载 → `new_apk/` / `new_v17/` | `ee9a867534958bd5ae27f52912e6e6a6`（**完全相同**） |

v1.7 的 `a.ovpn` / `b.xml` / `c` 也全部 MD5 一致；v1.7 dex 内 URL 扫描同样只有 v2rayNG 原生与 AdMob，**没有运营后端**。
→ 结论：这不是“老版本没配”的问题，**该 app 家族的内置配置恒为占位符**，真实节点只能来自运营方另行发布的加密配置串。


`res/raw/a.ovpn` 亦为模板：`remote 0.0.0.0 1194`，仅带 vendor 自签 CA（CN=KobZ，有效期 2020-07-22 → 2030-07-20）。

## 6. 节点下发路径：**没有运营后端 API**

穷举结论（逐项验证）：

| 怀疑点 | 结论 |
|---|---|
| Firebase RTDB / Firestore / Storage | dex 内**无** `com.google.firebase.{database,firestore,storage}`；仅 analytics/messaging/iid。`project_id=raj-tunnel-vpn`、`google_storage_bucket=raj-tunnel-vpn.firebasestorage.app` 是 Firebase 依赖自带的占位符。RTDB/Storage REST 探测均 404 |
| 自建 HTTP 面板 | 全部 `new URL(...)` 调用点仅 4 处：`Utils.getUrlContent`（订阅/规则下载，v2rayNG 原生）、`RenzInjectorService`（注入引擎，见下）。无 node/api/sub 端点 |
| 订阅 (sub) | 仅保留 v2rayNG 的用户手动订阅功能，App 内无预置订阅地址 |
| `xl.a()` 全量 1,078 串 | 域名仅 4 条：`t.me/rajtunnelvpn`、`whatsapp.com/channel/0029VbCTogKB4hdPlqP2ls3A`、`kiberudata.com/p/cranevpn.html`、`https://`(注入器拼接) |
| 配置更新 | 只能靠**发版换 `res/raw/servers`**，或用户粘贴运营方发布的加密串（`pq0.java` 弹窗原文：“obtain the encrypted configuration from our official channels”） |

`RenzInjectorService` 是**载荷注入引擎**（免费上网“白名单穿刺”），不是节点 API。它把模板变量 `[split] [split_delay] [split_instant] [delay_split] [random] [repeat] [crlf] [lf] [ua] [host] [host_port] [rlb]` 渲染成 HTTP 请求，用 `SNI`/`HTTP_PAYLOAD` 首部穿透运营商计费网关（支持 Airtel/Tigo/Orange/Zain/Mobily 等，见厂商页面）。

## 7. 归属识别

* 包名 `com.rj.rajtunnelvpn` → **apkpure 将该包归在 “BD Tunnel Max”**（`apkpure.net` 重定向证据）
* 代码命名空间 `renz.javacodez.*` + 水印 `t.me/PHRenzOrigin` → 白标 vendor：**PH Renz / JavaCodez**
* 分销/教程站：`kiberudata.com`（Crane VPN 同源，包名 `kd.tunnel.cranevpn`）
* 同族：BD Tunnel Plus(`com.rr.bdtunnelplus`)、RN Tunnel(`com.rnteam.rntunnelvpn.app`)、Crane VPN(`kd.tunnel.cranevpn`)

## 8. 对“代理池”的判断

**本 APK 无法产出代理 IP**：没有节点、没有后端、没有订阅。任何声称“从这个包扒出节点池”的结论都是伪的实现。

要拿到同族真实节点，只有 3 条路（工具已就绪，拿到 blob 即可秒解）：

1. **拿新版本同族 APK 的 `res/raw/servers`**（Play 上 `com.rj.rajtunnelvpn` 更新于 2026-09-22，本样本是 6 月的 1.5 版）→ 若其 `d.js` 非占位符即可解出真实 `ServerIPHost`。注意：不同 app 的 `myKey` 可能随 lib 变化，需对目标包重跑 §3.2/§4。
2. **拿运营方发布的加密配置串**（Telegram / WhatsApp 频道 / 官网）→ 直接喂 `POST /api/decrypt`。
3. **买白标**（PH Renz）：拿到的是自己的节点，不构成“别人的池”。

合规定位（沿用既有结论）：即便解出，节点是运营方自有 VPS，**不入生产代理池**，只能作研究/demo；生产池继续用自有 VPS 或已授权来源。

## 9. 交付物

| 文件 | 说明 |
|---|---|
| `tools/xl_decrypt.py` | xl 字符串表解密器（1,078 串全解，`xl_strings.json`） |
| `tools/ay_deobf.py` | ADVobfuscator 模板解密器 |
| `tools/annotate.py` / `tools/disasm.py` | AArch64 反汇编 + PLT/GOT 符号解析（还原 JNI 调用链用） |
| `tools/raj_decrypt.py` | **配置解密器**（三层 + 字段级 + 节点归一化），`raj_encrypt.py` 反向打包，round-trip 通过 |
| `demo/server.py` + `demo/index.html` | Demo：解密内置/粘贴配置、节点表、TCP 测活、并发压测（`http://127.0.0.1:8960`） |
| `servers_decoded.json` | 内置配置全字段解密结果 |
| `samples/sample_pool.json` | 外部样本节点（**非本 app**，仅用于验证测活/压测链路） |
| `dec_annot.txt` / `dec_disasm.txt` | `RenzUtils.decrypt` 反汇编与注解 |

## 10. 未验证 / 待确认

* 新版本（2026-09 之后）`res/raw/servers` 是否仍为占位符 —— 需真实新包（apkpure 直链可下但被截断，见交付说明）
* `Protocol` 枚举语义（0=?）与 `TunnelType` 映射 —— 需非占位符配置样本才能对照
* 设备侧动态验证（Frida hook `RenzUtils.decrypt` 打印明文）未做：本包仅有 `arm64-v8a`，本机 x86_64 模拟器无法加载；静态链路已等价验证（round-trip + 真实 blob 解密成功）
