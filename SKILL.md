---
name: renz-white-label-vpn-reverse
description: 逆向 Renz / JavaCodez（PH Renz）系白标 VPN app（RAJ Tunnel / BD Tunnel MAX / Crane VPN / RN Tunnel）并解开其 servers 配置：xl 字符串表、ADVobfuscator native 混淆、base64→AES-128-CBC→XXTEA 三层配置加密、new-api 代理池桥接。当遇到 com.rj.* / kd.tunnel.* / com.rr.bdtunnelplus / renz.javacodez.* 的 APK，或需要解一个 base64 加密的 servers 配置串时使用。
---

# Renz / JavaCodez 白标 VPN 逆向技能卡

## 何时用

- 目标 APK 含 `renz.javacodez.v2ray|vpn` 命名空间，或 `RenzUtils`（`checkAppSign / decrypt / encrypt / play / stayHumbleAlways`）JNI
- 拿到一个 base64 配置串，要解成 `ServerIPHost` + 端口 + 协议
- 要把这类 app 的节点接进 new-api 代理池

## 关键事实（省掉重新摸索）

1. 技术栈 = **v2rayNG 分支**（`renz.javacodez.v2ray.*`）+ openvpn3 + hysteria2 + dnstt(`libotensahorse.so`, Go) + tun2socks/pdnsd。
2. **加密与签名校验 JNI 注入在 `libovpn3.so`**（不是独立 libcrypto 封装）。找 `Java_renz_javacodez_vpn_utils_RenzUtils_*` 符号即定位。
3. 配置来源两处：`res/raw/servers`（apktool 常被改名成 `res/raw/a.ovpn|b.xml|c|d.js`，**认内容不认名**：base64 长串就是它）、以及 `filesDir/classes3.dex`（实为 zip，条目 `a.rlb`）。
4. **内置配置多半是占位符**（`ServerIPHost=0.0.0.0` / `"Please update config first"`）。先解出来再判断有没有货，不要假设有节点。
5. 该家族**没有节点下发后端**（无 Firebase RTDB/Storage、无 sub 端点）。别浪费时间找 API。

## 标准流程

```bash
# 1) 剥壳：外层 APK 里找 origin.apk（Mod 壳常见目录名 "بسم الله"）
unzip -o target.apk -d apk && ls apk
# 2) resources 与三类产物
java -jar apktool.jar d -s -f -o apktool_out target.apk
"D:/apk-analysis/jadx/bin/jadx.bat" -d jadx_out -j 8 --no-res --no-imports apk/classes*.dex
# 3) Java 字符串表：defpackage/xl.java + PRNG defpackage/j7.java → tools/xl_decrypt.py
# 4) native：读 libovpn3.so 的 JNI decrypt 反汇编（tools/annotate.py 解 PLT/GOT 符号名）
# 5) 取 myKey：AARCH64 上搜 "str x0,[&myKey]" 的懒初始化块（adrp/add → rodata 常量 → XOR 还原）
# 6) 解配置：tools/raj_decrypt.py；批量 tools/harvest.py
```

## 三层配置加密（同一家族稳定）

```
plain = XXTEA_decrypt( AES128CBC_decrypt(base64(blob), key=K[0:16], iv=00*16, PKCS7), key=K[0:16] )
K     = SHA256(myKey)        # myKey 每个 app 可能不同，必须从目标包取
```

- XXTEA = 标准 Corrected Block TEA，key = `K[0:16]` 解释成 4×uint32 LE，delta `0x9E3779B9`
- 字段（`ServerIPHost`/端口/`Name`/`flag`…）**各自独立加密**，复用同管线
- 端口字段尾部残留 XXTEA 对齐填充（`b'1194\x04\x00\x00\x00'`），要剥离
- 反向打包见 `tools/raj_encrypt.py`（round-trip 验证）

## 取 myKey 的定位技巧

`RenzUtils.decrypt` 里 `myKey` 是 `.bss` 的 `char*`，通过 GOT（`AARCH64_GLOB_DAT` → 符号名 `myKey`）访问。
写它的是一个惰性初始化函数：`ldr q0,[rodata]; str q0,[buf]` 后逐字节 `eor` 还原，末尾 `str x0,[GOT(myKey)]`。
把 rodata 常量按 `plain[i] = data[i] ^ (S >> ((i%8)*8)) & 0xFF` 解开即得明文（S 来自 `ay::obfuscated_data<N,S,char>` 符号名）。

## 混淆器识别

| 特征 | 名称 | 解法 |
|---|---|---|
| `defpackage/xl.java` + 巨型 `String[] a` + `a(long)` PRNG | 自实现字符串表混淆 | `tools/xl_decrypt.py`（改表路径即可复用） |
| `_ZN2ay15obfuscated_dataILy<N>ELy<S>EcE...` | ADVobfuscator | `tools/ay_deobf.py` |

## 落到代理池（重要）

这些节点是 **OpenVPN/SSH/V2Ray 端点，不是 http/socks 出口**。进 new-api 必须本地桥接成 `socks5://127.0.0.1:PORT`，再写进 `TRYINGOPEN_PROXY_FILE`（每行一个 URL，`#` 注释）。
验收必须看**真实出口 IP 变化**，TCP 握手成功不算通过。详见 `docs/NEW-API-INTEGRATION.md`。

## 红线

- 第三方运营方自有 VPS：**不入生产池**，只做研究/demo
- 不内置/不传播真实凭据；样本只留占位符配置
