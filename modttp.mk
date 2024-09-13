################################################################################
#
# modttp
#
################################################################################

MODTTP_VERSION = 1.0.0
MODTTP_SITE:= $(BR2_EXTERNAL_DOJO_PATH)/package/modttp
MODTTP_SITE_METHOD:= local

$(eval $(kernel-module))
$(eval $(generic-package))
