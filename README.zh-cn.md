<p align="center">
  <img src="docs/logo.png" width="128" alt="luci-app-netbird logo">
</p>

# luci-app-netbird

[English](README.md) | **简体中文**

OpenWrt / ImmortalWrt 上管理 [NetBird](https://netbird.io) mesh-VPN 客户端的 LuCI 应用 —— 在路由器上使用 NetBird，无需命令行。
同时兼容 OpenWrt / ImmortalWrt 24.x（`opkg`）和 25.x（`apk`）。

## 功能

把 NetBird 客户端的能力接入 LuCI 管理界面：

- 连接 / 重新连接 / 断开 / 注销；支持自托管管理服务器
- 二进制版本管理 —— 官方 release、系统软件源或自定义 URL
- 防火墙自动化 —— NetBird 区域与 LAN ↔ mesh 转发
- 完整 `netbird up` 设置 —— WireGuard、路由、DNS、SSH、IPv6、Rosenpass、日志层级
- 对端状态与实时日志

## 安装

**一键安装** —— 添加签名软件源,然后安装本插件 + 简体中文语言包:

```sh
# 使用 curl:
sh -c "$(curl -fsSL https://luci-app-netbird.okk.sh/install.sh)"
# 没有 curl 的路由器:
wget -O - https://luci-app-netbird.okk.sh/install.sh | sh
```

之后照常管理 —— 命令行 `opkg`/`apk`,或 **LuCI → 系统 → 软件包**。本插件与架构无关(`PKGARCH:=all`);在 **服务 → NetBird** 中访问。

<details><summary><b>只添加软件源(自己再装)</b></summary>

```sh
wget -O - https://luci-app-netbird.okk.sh/feed.sh | sh
opkg install luci-app-netbird luci-i18n-netbird-zh-cn
# 或:  apk add luci-app-netbird luci-i18n-netbird-zh-cn
```
</details>

<details><summary><b>用安装包手动安装</b></summary>

运行依赖(通常已随固件存在):`rpcd`、`rpcd-mod-ucode`、`luci-base`、`netbird`。可选:`conntrack`。

```sh
# OpenWrt / ImmortalWrt 24.10(opkg)
opkg install rpcd rpcd-mod-ucode luci-base netbird
opkg install luci-app-netbird_*.ipk luci-i18n-netbird-zh-cn_*.ipk
# OpenWrt / ImmortalWrt 25+(apk)
apk add rpcd rpcd-mod-ucode luci-base netbird
apk add --allow-untrusted luci-app-netbird-*.apk luci-i18n-netbird-zh-cn-*.apk
```
</details>

<details><summary><b>从源码构建</b></summary>

把本仓库加入 OpenWrt / ImmortalWrt 的 SDK 或 buildroot(`package/` 下或 feed),然后 `make package/luci-app-netbird/compile V=s`。
</details>

**卸载:** `wget -O - https://luci-app-netbird.okk.sh/uninstall.sh | sh`

## 快速上手

1. 在 [NetBird 控制台](https://app.netbird.io)（或你的自托管面板）创建一个**安装密钥（setup key）**。
2. **服务 → NetBird → 认证** —— 自托管请先填「管理 URL」；打开主开关，粘入密钥，点**连接**。
3. *（可选）* **网络**标签页 —— 先「创建防火墙区域」，再按需启用 `LAN → NetBird` / `NetBird → LAN` 转发。

## 文档

- [架构](docs/ARCHITECTURE.md) —— 设计、数据流、模块边界
- [发布](docs/RELEASING.md) —— CI 触发规则、按包版本发布
- [更新日志](CHANGELOG.md) —— 版本历史

## 说明

- 已在 x86_64 验证；其他架构（arm64 / 386 / armv6）支持但测试较少。
- SSH 扩展（Root 登录 / SFTP / 端口转发）需 netbird 0.72.x+。
- `/etc/config/netbird` 是 conffile —— 升级保留你的设置。

## 许可

Apache-2.0 —— 见 [`LICENSE`](LICENSE) 与 [`NOTICE`](NOTICE)。
架构与部分范式参考 [luci-app-tailscale-community](https://github.com/Tokisaki-Galaxy/luci-app-tailscale-community)（Apache-2.0）；UI 思路参考 OPNsense [os-netbird](https://github.com/opnsense/plugins/tree/master/net/os-netbird)（BSD-2-Clause，© NetBird GmbH）。

## 截图

### 认证

![认证 — 已连接](docs/screenshots/zh-cn/luci-app-netbird-menu-1-1.jpg)
![认证 — 登录](docs/screenshots/zh-cn/luci-app-netbird-menu-1-2.jpg)

### 版本管理

![版本管理](docs/screenshots/zh-cn/luci-app-netbird-menu-2.jpg)

### 设置

![设置](docs/screenshots/zh-cn/luci-app-netbird-menu-3-1.jpg)
![设置](docs/screenshots/zh-cn/luci-app-netbird-menu-3-2.jpg)
![设置](docs/screenshots/zh-cn/luci-app-netbird-menu-3-3.jpg)
![设置](docs/screenshots/zh-cn/luci-app-netbird-menu-3-4.jpg)
![设置](docs/screenshots/zh-cn/luci-app-netbird-menu-3-5.jpg)

### 状态

![状态](docs/screenshots/zh-cn/luci-app-netbird-menu-4.jpg)

### 网络

![网络](docs/screenshots/zh-cn/luci-app-netbird-menu-5.jpg)

### 日志

![日志](docs/screenshots/zh-cn/luci-app-netbird-menu-6.jpg)
