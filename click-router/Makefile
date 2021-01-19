include $(TOPDIR)/rules.mk

PKG_NAME:=click-router
PKG_VERSION:=20201026
PKG_RELEASE:=1
PKG_REV:=593d10826cf5f945a78307d095ffb0897de515de
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=git://github.com/kohler/click.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=$(PKG_REV)
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/kernel.mk

define Package/click-router
	SECTION:=net
	CATEGORY:=Network
	TITLE:=Click Modular Router
	URL:=http://read.cs.ucla.edu/click
	DEPENDS:= +libpcap +libexpat +libstdcpp +libc
endef

define Package/click-router/Description
	The Click Modular Router userspace package
endef


define Build/Configure
	$(CP) ./files/llrpc.patch $(PKG_BUILD_DIR)/include/click
	(cd $(PKG_BUILD_DIR)/include/click/; \
		patch -N  < llrpc.patch; \
	)
	(mkdir -p $(PKG_BUILD_DIR)/include/net; \
	)
	$(CP) ../../build_dir/target-mips_24kc_musl/linux-ar71xx_generic/linux-4.9.243/user_headers/include/linux/*.h $(PKG_BUILD_DIR)/include/net/; \
	$(CP) ./odin-agent/src/odinagent.* $(PKG_BUILD_DIR)/elements/local/ 
	$(CP) ./files/click_1.patch $(PKG_BUILD_DIR)
	(cd $(PKG_BUILD_DIR); \
		patch -N < click_1.patch; \
	)
	$(CP) ./files/click_2.patch $(PKG_BUILD_DIR)/include/click
	(cd $(PKG_BUILD_DIR)/include/click/; \
		patch -N < click_2.patch; \
	)
	$(CP) ./files/error_cc.patch $(PKG_BUILD_DIR)/lib
	(cd $(PKG_BUILD_DIR)/lib; \
		patch -N  < error_cc.patch; \
	)

	$(CP) ./files/if_ether_1.patch  ../../staging_dir/toolchain-mips_24kc_gcc-7.3.0_musl/include/linux/
	(cd ../../staging_dir/toolchain-mips_24kc_gcc-7.3.0_musl/include/linux/; \
		(patch -N < if_ether_1.patch)||true; \
	)
	$(CP) ./files/if_ether_2.patch  ../../staging_dir/toolchain-mips_24kc_gcc-7.3.0_musl/include/netinet/
	(cd ../../staging_dir/toolchain-mips_24kc_gcc-7.3.0_musl/include/netinet/; \
		(patch -N < if_ether_2.patch)||true; \
	)

	(cd $(PKG_BUILD_DIR); \
		rm -rf config.{cache,status} ; \
		./configure \
			--prefix=/usr \
			--host=$(GNU_TARGET_NAME) \
			--with-linux=/home/ubuntu/openwrt/build_dir/toolchain-mips_24kc_gcc-7.3.0_musl/linux/ \
			--enable-tools=host \
			--enable-wifi \
			--disable-app-fuzzer \
			--disable-app-performance \
			--disable-app-sniffer \
			--enable-app-tunnel \
			--disable-app-stats \
			--disable-doc \
			--disable-doc-man \
			--enable-local \
			--enable-userlevel \
			--build=mips \
			ARCH=$(ARCH) \
	)

endef


define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) elemlist
	$(MAKE) -C $(PKG_BUILD_DIR)
endef

define Package/click-router/install
	$(INSTALL_DIR) $(1)/
	$(CP) $(PKG_INSTALL_DIR)/usr $(1)/
endef

$(eval $(call BuildPackage,click-router))
