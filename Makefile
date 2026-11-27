TARGET := iphone:clang:latest:9.0
ARCHS := armv7
include $(THEOS)/makefiles/common.mk

TWEAK_NAME = ReMusic
ReMusic_FILES = signin12.x ReMusicDiag.m Globals.m general.m TRJSONUtils.m
# -w and the -Wno-error flags keep newer compilers from turning old-style code warnings into build errors
ReMusic_CFLAGS = -fno-objc-arc -I. -w -Wno-error -Wno-error=implicit-function-declaration -Wno-error=int-conversion -Wno-error=incompatible-pointer-types -Wno-error=incompatible-function-pointer-types
ReMusic_FRAMEWORKS = UIKit Foundation CoreGraphics

include $(THEOS_MAKE_PATH)/tweak.mk
