# Create configuration header
include(CheckFunctionExists)
check_function_exists(getenv RTM_HAS_GETENV)
set(RTM_LOGGING ${ENABLE_LOGGING})
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/rtm_config.h.in
  ${CMAKE_CURRENT_BINARY_DIR}/rtm_config.h
  @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/rtm_config.h
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

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
  list(APPEND SOURCES ssl/rtm_gnutls.c)
elseif(USE_OPENSSL)
  list(APPEND SOURCES ssl/rtm_openssl.c ssl/rtm_openssl_bio.c)
elseif(USE_APPLE_SSL)
  list(APPEND SOURCES ssl/rtm_apple_ssl.c)
else()
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

if(USE_GNUTLS)
  find_package(GnuTLS REQUIRED)
  message(STATUS "GNU TLS: " ${GNUTLS_VERSION_STRING})

  include_directories(${GNUTLS_INCLUDE_DIR})
  target_link_libraries(rtm-core-sdk ${GNUTLS_LIBRARIES})
  add_definitions(-DUSE_GNUTLS ${GNUTLS_DEFINITIONS})

elseif(USE_OPENSSL)
  add_definitions(-DUSE_OPENSSL)
  if(MSVC)
      message(WARNING
          "\nAutomatically finding OpenSSL on Windows is not supported yet. "
          "Please install OpenSSL and configure the Visual Studio Project to find it. ")
  else()
      find_package(OpenSSL REQUIRED)
      message(STATUS "OpenSSL: " ${OPENSSL_VERSION})

      add_definitions(${OPENSSL_DEFINITIONS})
      include_directories(${OPENSSL_INCLUDE_DIR})
      target_link_libraries(rtm-core-sdk ${OPENSSL_LIBRARIES})
  endif()

elseif(USE_APPLE_SSL)
  message(STATUS "Selected Apple Security framework")

  target_link_libraries(rtm-core-sdk "-framework foundation" "-framework security")
  add_definitions(-DUSE_APPLE_SSL)

else()
  message(STATUS "No TLS backend selected.")
endif()

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
