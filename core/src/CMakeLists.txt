# Construct sources list
set(BASE_SOURCES rtm.c rtm_json.c rtm_byteorder.c)
set(SOURCES ${BASE_SOURCES})
file(GLOB BASE_HEADERS *.h)


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
  list(APPEND SOURCES rtm_hmac_md5.c)
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
include(CheckCSourceCompiles)
set(RTM_LOGGING ${ENABLE_LOGGING})

configure_file(rtm_config.h.in
  rtm_config.h
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

# Arduino SDK
if(ARDUINO_SDK)
  set(ARDUINO_DIR ${CMAKE_CURRENT_BINARY_DIR}/arduino)

  # For certificate validation in recent versions of the ESP8266/Arduino SDK.
  set(TEST_ENDPOINT zkng8p1v.api.satori.com)
  add_custom_command(
    OUTPUT ${ARDUINO_DIR}/ssl_cert.c
    COMMAND echo 'const char *_rtm_ssl_cert = ' > ${ARDUINO_DIR}/ssl_cert.c
    # The following extracts the last certificate from the certificate chain at the
    # endpoint and prints it as a c string.  Works with any posix compatible sed.
    COMMAND openssl s_client -showcerts -connect ${TEST_ENDPOINT}:443 </dev/null 2>&1 | sed -ne ': o; $$ {x\;p\;}\; /-BEGIN CERTIFICATE-/{ s/.*/\"&\\\\n\"/\; h\;b i\; }\; d\; : i\; n\; s/.*/\"&\\\\n\"/\; H\; /-END CERTIFICATE-/ { n\; b o\; }\; b i\;' >> ${ARDUINO_DIR}/ssl_cert.c
    COMMAND echo '\\;' >> ${ARDUINO_DIR}/ssl_cert.c
  )

  configure_file(${CMAKE_CURRENT_SOURCE_DIR}/../library.properties.in ${ARDUINO_DIR}/library.properties @ONLY)

  function(ArduinoConfig)
    get_cmake_property(NAMES VARIABLES)
    foreach(NAME ${NAMES})
      if(NAME MATCHES "^RTM_")
        set(${NAME} 0)
      endif()
    endforeach()
    set(RTM_HAS_SSL 1)

    configure_file(rtm_config.h.in ${ARDUINO_DIR}/rtm_config.h @ONLY)
  endfunction()
  ArduinoConfig()

  set(ARDUINO_FILES ${ARDUINO_DIR}/rtm_config.h ${ARDUINO_DIR}/library.properties ${ARDUINO_DIR}/ssl_cert.c ${CMAKE_CURRENT_SOURCE_DIR}/io/rtm_esp_arduino.cpp ${CMAKE_CURRENT_SOURCE_DIR}/rtm_hmac_md5.c ${BASE_SOURCES} ${BASE_HEADERS})
  set(ARDUINO_TARGET ${CMAKE_BINARY_DIR}/satori_esp_arduino_library.zip)
  add_custom_command(
    OUTPUT ${ARDUINO_TARGET}
    COMMAND rm -f ${ARDUINO_TARGET}
    COMMAND zip -j ${ARDUINO_TARGET} ${ARDUINO_FILES}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    DEPENDS ${ARDUINO_FILES}
  )

  add_custom_target(arduino-lib ALL DEPENDS ${ARDUINO_TARGET})
endif()
