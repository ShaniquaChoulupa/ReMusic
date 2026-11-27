TARGET := iphone:clang:latest:9.0
ARCHS := armv7
include $(THEOS)/makefiles/common.mk

TWEAK_NAME = ReMusic
ReMusic_FILES = signin12.x Globals.m general.m TRJSONUtils.m
ReMusic_CFLAGS = -fno-objc-arc -I.
ReMusic_FRAMEWORKS = UIKit Foundation CoreGraphics

include $(THEOS_MAKE_PATH)/tweak.mk
