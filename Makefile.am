
RTM_CPPFLAGS = @RTM_CPPFLAGS@
AM_CPPFLAGS=$(RTM_CPPFLAGS)

lib_LIBRARIES = librtm.a
librtm_a_SOURCES = \
   core/src/rtm.c \
   core/src/rtm_posix.c \
   core/src/rtm_json.c \
   easy/rtm_easy.c

if ENABLE_APPLE_SSL
librtm_a_SOURCES += \
   core/src/rtm_apple_ssl.c
endif

if ENABLE_OPEN_SSL
librtm_a_SOURCES += \
   core/src/rtm_openssl.c
endif
