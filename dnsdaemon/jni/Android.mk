LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := afwall_dnsd
LOCAL_SRC_FILES := afwall_dnsd.c
LOCAL_CFLAGS := -O2 -Wall -Wextra -Werror -std=c11
LOCAL_LDLIBS := -llog

include $(BUILD_EXECUTABLE)
