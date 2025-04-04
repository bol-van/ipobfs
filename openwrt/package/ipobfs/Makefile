include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=ipobfs
PKG_RELEASE:=1
PKG_VERSION:=1.0

PKG_BUILD_DIR:=$(KERNEL_BUILD_DIR)/ipobfs-$(PKG_VERSION)
export KERNELDIR:=$(LINUX_DIR)

include $(INCLUDE_DIR)/package.mk


define Package/ipobfs
	SECTION:=net
	CATEGORY:=Network
	TITLE:=ipobs
	SUBMENU:=Zapret
	DEPENDS:=+libnetfilter-queue +libcap
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./ipobfs ./ipobfs_mod $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR)/ipobfs $(TARGET_CONFIGURE_OPTS)
	$(MAKE) $(KERNEL_MAKEOPTS) -C $(PKG_BUILD_DIR)/ipobfs_mod
endef

define Package/ipobfs/install
	$(INSTALL_DIR) $(1)/opt/ipobfs/ipobfs
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ipobfs/ipobfs $(1)/opt/ipobfs/ipobfs
endef

include $(INCLUDE_DIR)/kernel-defaults.mk
include $(INCLUDE_DIR)/package-defaults.mk


define KernelPackage/ipobfs
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Zapret
  TITLE:=ipobfs kernel module
  FILES:= $(PKG_BUILD_DIR)/ipobfs_mod/ipobfs.$(LINUX_KMOD_SUFFIX)
endef


$(eval $(call BuildPackage,ipobfs))
$(eval $(call KernelPackage,ipobfs))
