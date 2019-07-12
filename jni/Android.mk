LOCAL_PATH := $(call my-dir)/..

include $(CLEAR_VARS)
LOCAL_MODULE := crypto
LOCAL_SRC_FILES := libcrypto.so
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/openssl/
include $(PREBUILT_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_C_INCLUDES	:= $(LOCAL_PATH)/cpputils
LOCAL_C_INCLUDES	+= $(LOCAL_PATH)
LOCAL_C_INCLUDES	+= $(LOCAL_PATH)/dumputils
LOCAL_C_INCLUDES	+= /usr/local/opt/openssl/include

LOCAL_CFLAGS		:= -D_UNIX -D_NO_WINDOWS -D_NO_RAPI -D_BOOST_LITE  -Wno-psabi 
LOCAL_CFLAGS		+= -D_USE_OPENSSL
LOCAL_SHARED_LIBRARIES	+= crypto

LOCAL_SRC_FILES		:= dump.cpp dumputils/bighexdump.cpp dumputils/bigascdump.cpp

LOCAL_MODULE		:= dump
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_C_INCLUDES	:= $(LOCAL_PATH)/cpputils
LOCAL_C_INCLUDES	+= $(LOCAL_PATH)

LOCAL_SRC_FILES		:= dump2.cpp

LOCAL_MODULE		:= dump2
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_C_INCLUDES	+= $(LOCAL_PATH)
LOCAL_C_INCLUDES	+= $(LOCAL_PATH)/cpputils
LOCAL_C_INCLUDES	+= /usr/local/include

LOCAL_CFLAGS		:= -D_UNIX -D_NO_WINDOWS -D_NO_RAPI -D_BOOST_LITE

LOCAL_SRC_FILES		:= mmdump.cpp

LOCAL_MODULE		:= mmdump
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_C_INCLUDES	+= $(LOCAL_PATH)
LOCAL_C_INCLUDES	+= $(LOCAL_PATH)/cpputils
LOCAL_C_INCLUDES	+= /usr/local/include
LOCAL_C_INCLUDES	+= ../../secphone/engine

LOCAL_CFLAGS		:= -D_UNIX -D_NO_WINDOWS -D_NO_RAPI -D_BOOST_LITE

LOCAL_SRC_FILES		:= mmedit.cpp

LOCAL_MODULE		:= mmedit
include $(BUILD_EXECUTABLE)

