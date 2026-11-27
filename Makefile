TARGET := iphone:clang:latest:9.0
ARCHS := armv7
include $(THEOS)/makefiles/common.mk

TWEAK_NAME = ReMusic
ReMusic_FILES = Tweak.x
ReMusic_FRAMEWORKS = UIKit WebKit
ReMusic_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/tweak.mk
