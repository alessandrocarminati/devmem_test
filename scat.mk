CMT_VERSION = 1.0
CMT_SITE = package/cmt/src
CMT_SITE_METHOD = local

define CMT_BUILD_CMDS
	$(MAKE) -C $(@D) CC="$(TARGET_CC)" CFLAGS="$(TARGET_CFLAGS)"
endef

define CMT_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0755 $(@D)/cmt $(TARGET_DIR)/usr/bin/cmt
#	$(INSTALL) -D -m 0755 $(@D)/writestr $(TARGET_DIR)/usr/bin/writestr
#	$(INSTALL) -D -m 0755 $(@D)/w_and_r $(TARGET_DIR)/usr/bin/w_and_r
endef

$(eval $(generic-package))
