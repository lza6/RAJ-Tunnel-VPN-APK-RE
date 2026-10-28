# RAJ Tunnel VPN / BD Tunnel MAX (com.rj.rajtunnelvpn) — 逆向与配置解密工具

`com.rj.rajtunnelvpn`（Google Play 商店名 **BD Tunnel MAX**，白标 vendor: **PH Renz / JavaCodez**）的完整逆向、三层配置加密还原、以及可直接复用的解密/测活/压测工具链。

> ⚠️ 一句话结论：**加密全部逆向成功（含密钥，可双向加解密）**，但**该 app 家族的内置服务器配置恒为占位符**（`0.0.0.0` / `"Please update config first"`），1.5 与 Play 最新 1.7 的 `res/raw/servers` 字节完全相同。**本仓库不产出可用代理 IP**，真实节点只能来自运营方另行发布的加密配置串。

## 状态

| 项 | 状态 | 证据 |
|---|---|---|
| Mod 壳剥离（`بسم الله/{origin.apk,lib/*.so}`） | ✅ | `docs/REVERSE_REPORT.md` §1 |
| Java 字符串表混淆 `xl.a(long)` | ✅ 复现，1,078 串全解 | `tools/xl_decrypt.py` → `xl_strings.json` |
| Native 混淆 `ay::obfuscated_data<N,S>` | ✅ 复现 | `tools/ay_deobf.py` |
| 配置三层加密（base64→AES-128-CBC→XXTEA） | ✅ 密钥已取，双向验证 | `tools/raj_decrypt.py` / `raj_encrypt.py`（round-trip OK） |
| 内置配置解密 + 字段级解密 | ✅ | `docs/servers_decoded.json` |
| 节点下发后端 API | ❌ 不存在（穷举验证） | 报告 §6 |
| Firebase RTDB/Storage | ❌ 不存在（仅 analytics/messaging） | 报告 §6 |
| 内置节点可用性 | ❌ 0 条（占位符） | 测活 `dead`，报告 §5 |
| Play 最新版 1.7 交叉验证 | ✅ 配置 MD5 与 1.5 一致 | 报告 §5.1 |
| 测活 / 压测工具链 | ✅ 实测 | 外部样本池 67 节点 × 3 轮 × 32 并发 |
| new-api 对接 | 📄 文档就绪 | [`docs/NEW-API-INTEGRATION.md`](docs/NEW-API-INTEGRATION.md) |

## 加密链路速查

```
blob(base64) --base64--> raw --AES-128-CBC(K[0:16], iv=00*16, PKCS7)--> mid --XXTEA(K[0:16])--> JSON

K     = SHA256(myKey)                                   # a462d0b9c9ef56c8…f05867
myKey = "T}wcex;{(*~$4M5XZtd!zK"                        # libovpn3.so rodata 0x1ff1f0 + 0x1ff448
```

`ServerIPHost`、端口、`Name`、`flag` 等字段**各自独立加密**，复用同一管线；端口字段尾部带 XXTEA 对齐填充（如 `1194\x04\x00\x00\x00`）。

## 工具

| 文件 | 用途 |
|---|---|
| `tools/raj_decrypt.py` | 配置解密（三层 + 字段级 + 节点归一化） |
| `tools/raj_encrypt.py` | 反向打包（可自造配置串），自带 round-trip 自检 |
| `tools/harvest.py` | 批量解 + 导出 `nodes.json` / `proxies.txt` / `socks_template.txt`，可选 `--probe` / `--bench` |
| `tools/xl_decrypt.py` | Java 字符串表解密器 |
| `tools/ay_deobf.py` | Native 模板字符串解密器 |
| `tools/annotate.py`, `tools/disasm.py` | AArch64 反汇编 + PLT/GOT 符号解析 |
| `demo/server.py` + `demo/index.html` | Demo：解密 / 测活 / 并发压测（`:8960`） |

```bash
cd tools
python raj_encrypt.py                      # 加解密往返自检
python raj_decrypt.py ../samples/blob_1.5.txt   # 内置配置 → JSON
python harvest.py ../samples -o ../out --bench 32 --rounds 3
cd ../demo && python server.py             # http://127.0.0.1:8960
```

## 实测数据

```
内置节点测活        : 0.0.0.0:1194 → dead (WinError 10049)
外部样本池压测      : attempts 201 | alive 75 | 37.3% | p50 71.0ms | p95 261.9ms | p99 275.5ms | 10.7 conn/s
                      （样本来自另一 app 的收割产物，只用于验证测活/压测链路）
```

## 目录

```
docs/REVERSE_REPORT.md        完整逆向报告（结构/混淆/加密/下发路径/归属）
docs/NEW-API-INTEGRATION.md   new-api 对接指南（给对接会话看的落地文档）
docs/servers_decoded.json     内置配置全字段解密结果
tools/                        解密 / 打包 / 收割 / 反汇编工具
demo/                         Demo 服务与页面
samples/blob_1.5.txt          内置配置原始 base64（占位符）
samples/external/             外部样本节点（非本 app，仅验证工具链）
xl_strings.json/.txt          1,078 条解密后的 Java 字符串
dec_annot.txt                 RenzUtils.decrypt 带符号注解的反汇编
```

## 合规红线

解出的节点是第三方运营方自有 VPS。**不入生产代理池**，仅作研究/demo。生产池只用自有 VPS 或已获授权来源。

## 免责声明

仅用于安全研究与互操作性验证。仓库不包含任何真实节点的凭据、不提供绕过付费的功能，作者不对第三方使用行为负责。
