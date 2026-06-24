# SPDX-License-Identifier: Apache-2.0
#
# luci-app-netbird — LuCI app to manage the NetBird mesh-VPN client.

include $(TOPDIR)/rules.mk

LUCI_TITLE:=LuCI support for NetBird
LUCI_DESCRIPTION:=LuCI web interface to manage the NetBird mesh-VPN client \
	(authentication, connection, settings, peers status and logs).
# 全部运行时依赖走 EXTRA_DEPENDS:只写进包 control/PKGINFO 的 Depends,不触发 SDK 去
# 编译它们的 target 链。原因:
#   - +netbird 会拖 golang/host(C23 typedef bool 冲突)
#   - +luci-base 会拖 lucihttp(SDK 缺 ucode/module.h)
# 这些包在目标机由 opkg/apk 提供;control/PKGINFO 的 Depends 仍完整列出,运行时正常解析。
# 格式(apk):**逗号分隔 + 每项带版本约束**。OWRT25 apk 路径(CONFIG_USE_APK)经
# include/package-pack.mk 的 FormatDepends 处理 EXTRA_DEPENDS,要求逗号分隔且每项必须有版本
# 约束(无约束直接 $(error);空格分隔会被当成单项 "netbird (版本约束 rpcd)" 致依赖搅烂成
# netbirdrpcd、其余丢失——真机 apk add 实测)。`(>=0)`=任意版本;此格式对 ipk(原样塞入版本化
# Depends,opkg 接受)与 apk 同时成立。参照 luci-app-adguardhome 同类(golang)惯例。
# 不列 libuci:apk 下它是 **ABI 版本化**包(目标上叫 libuci20250120,`apk list libuci` 为空),
# SDK 的 GetABISuffix 在 SDK 上下文取不到其 ABI 后缀 → 渲染成裸 libuci>=0 在目标无法解析
# (真机 apk add 实测 breaks);且 libuci 被 rpcd/rpcd-mod-ucode/uci 传递依赖保证存在,无需显式列。
LUCI_DEPENDS:=
LUCI_EXTRA_DEPENDS:=netbird (>=0), rpcd (>=0), rpcd-mod-ucode (>=0), luci-base (>=0)
LUCI_PKGARCH:=all
LUCI_URL:=https://github.com/dont-touchme/luci-app-netbird
LUCI_MAINTAINER:=PC27149 <foxhis11@gmail.com>

PKG_NAME:=luci-app-netbird
PKG_VERSION:=0.1.0
PKG_RELEASE:=4
PKG_MAINTAINER:=PC27149 <foxhis11@gmail.com>
PKG_LICENSE:=Apache-2.0
PKG_LICENSE_FILES:=LICENSE

# i18n 子包版本跟随主包 release。luci.mk 默认 PKG_PO_VERSION=findrev(luci 仓 git rev),
# 在 luci 树外 standalone 构建时恒为 "0" → 每次发布 i18n 子包版本不变,opkg 把"同版本"
# 子包当已最新而跳过升级,译文更新到不了 opkg 升级用户(apk 则照常 replace、不受影响)。
# 固定为主包版本,使 PKG_RELEASE 每次递增时 i18n 子包版本一并递增 → opkg 升级也刷新 .lmo。
PKG_PO_VERSION:=$(PKG_VERSION)-r$(PKG_RELEASE)

# /etc/config/netbird 标记为 conffile:opkg 升级不覆盖用户配置;
# 刷机保护由 uci-defaults 追加 /etc/sysupgrade.conf 负责。
# 注:须在 luci.mk include 之前定义 —— luci.mk 内部会调用 BuildPackage,
# 之后定义就来不及被收录。
define Package/luci-app-netbird/conffiles
/etc/config/netbird
/etc/config/netbird_bin
endef

# luci.mk 内部已 $(eval $(call BuildPackage,...)),不要再重复调用(否则 package
# 重复定义报错)。
include $(TOPDIR)/feeds/luci/luci.mk
