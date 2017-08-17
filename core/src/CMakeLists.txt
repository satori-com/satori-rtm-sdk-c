# Construct sources list
set(SOURCES rtm.c rtm_json.c rtm_byteorder.c)

if(UNIX)
  list(APPEND SOURCES io/rtm_posix.c)
elseif(MSVC)
  list(APPEND SOURCES io/rtm_windows.c)
else()
  message(FATAL_ERROR "Environment that is neither UNIX nor Visual Studio is not supported")
endif()

if(USE_GNUTLS)
  set(RTM_HAS_SSL 1)
  list(APPEND SOURCES ssl/rtm_gnutls.c)
elseif(USE_OPENSSL)
  set(RTM_HAS_SSL 1)
  list(APPEND SOURCES ssl/rtm_openssl.c ssl/rtm_openssl_bio.c)
elseif(USE_APPLE_SSL)
  set(RTM_HAS_SSL 1)
  list(APPEND SOURCES ssl/rtm_apple_ssl.c)
else()
  set(RTM_HAS_SSL 0)
  list(APPEND SOURCES ssl/rtm_hmac_md5.c)
endif()

# Sources list is now ready
if(BUILD_STATIC)
    add_library(rtm-core-sdk STATIC ${SOURCES})
else()
    add_library(rtm-core-sdk SHARED ${SOURCES})
endif()

set_target_properties(rtm-core-sdk PROPERTIES LINKER_LANGUAGE C)

if(MSVC)
  target_link_libraries(rtm-core-sdk wsock32 ws2_32)
  add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif()

include_directories("$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}>")
target_link_libraries(rtm-core-sdk ${TLS_LIBRARIES})

# Create configuration header
include(CheckFunctionExists)
check_function_exists(getenv RTM_HAS_GETENV)
set(RTM_LOGGING ${ENABLE_LOGGING})

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/rtm_config.h.in
  ${CMAKE_CURRENT_BINARY_DIR}/rtm_config.h
  @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/rtm_config.h
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")


# Installation
if(OSX)
    if(BUILD_STATIC)
      set_target_properties(rtm-core-sdk PROPERTIES
                            OUTPUT_NAME "SatoriCoreSDKtatic"
                            INSTALL_NAME_DIR "@rpath/SatoriCoreSDKStatic.framework"
                            INSTALL_RPATH "@executable_path/Frameworks;@loader_path/Frameworks"
                            )
      install(FILES rtm.h
              DESTINATION include/SatoriCoreSDKStatic
              RENAME Core.h
              )
  else()
      set_target_properties(rtm-core-sdk PROPERTIES
                            OUTPUT_NAME "SatoriCoreSDK"
                            INSTALL_NAME_DIR "@rpath/SatoriCoreSDK.framework"
                            INSTALL_RPATH "@executable_path/Frameworks;@loader_path/Frameworks"
                            )
      install(FILES rtm.h
              DESTINATION include/SatoriCoreSDK
              RENAME Core.h
              )
  endif()
endif()

install(FILES rtm.h
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)
install(TARGETS rtm-core-sdk
        DESTINATION "${CMAKE_INSTALL_LIBDIR}"
)
