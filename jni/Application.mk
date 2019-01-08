NDK_TOOLCHAIN_VERSION := clang
APP_CPPFLAGS += -std=c++1z -fexceptions
APP_STL	:= c++_static
#APP_STL := gnustl_static
APP_ABI := armeabi-v7a
APP_PLATFORM := android-19
APP_GNUSTL_FORCE_CPP_FEATURES := exceptions rtti
