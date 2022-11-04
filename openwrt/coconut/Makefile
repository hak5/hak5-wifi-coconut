include $(TOPDIR)/rules.mk

PKG_NAME:=wifi-coconut
PKG_REV:=1.1.0
PKG_VERSION:=$(PKG_REV)
PKG_RELEASE:=1
PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/hak5/hak5-wifi-coconut
PKG_SOURCE_VERSION:=v$(PKG_VERSION)
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.gz
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)

PKG_LICENSE:=GPL2

CMAKE_OPTIONS += -DOPENWRT=ON

PKG_USE_MIPS16:=0# MIPS16 prevents protobuf's usage of the 'sync' asm-opcode

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

CMAKE_BINARY_DIR=$(PKG_BUILD_DIR)/build/

define Package/wifi-coconut
	SECTION:=net
	CATEGORY:=Utilities
	DEPENDS:=+libpthread +libusb-1.0
	TITLE:=Hak5 WiFi Coconut
	URL:=https://hak5.org
endef

define Package/wifi-coconut/description
	Hak5 WiFi Coconut
endef

define Package/wifi-coconut/install
	$(INSTALL_DIR) $(1)/lib/firmware

	$(INSTALL_DIR) $(1)/usr/bin
	$(CP) $(PKG_BUILD_DIR)/build/wifi_coconut $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/usr/share/wifiuserspace/firmware 
	$(CP) $(PKG_BUILD_DIR)/libwifiuserspace/firmware/LICENSE-ralink-mediatek.txt $(1)/usr/share/wifiuserspace/firmware
	$(CP) $(PKG_BUILD_DIR)/libwifiuserspace/firmware/rt2870.bin $(1)/usr/share/wifiuserspace/firmware
endef
$(eval $(call BuildPackage,wifi-coconut))

