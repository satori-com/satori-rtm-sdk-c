cmake_minimum_required(VERSION 2.8)
project(RTM_CORE_SDK)

if (NOT CMAKE_VERSION VERSION_LESS 3.4)
    cmake_policy(SET CMP0054 NEW)
    cmake_policy(SET CMP0021 NEW)
    cmake_policy(SET CMP0042 NEW)
endif ()


option(USE_GNUTLS "Use GNUTLS backend" OFF)
option(USE_OPENSSL "Use OpenSSL backend" OFF)
option(USE_APPLE_SSL "Use Apple TLS backend" OFF)
option(DOC "Build the documentation" OFF)
option(BUILD_STATIC "Build static version" OFF)
option(COVERAGE "Generate coverage statistics" OFF)

if(COVERAGE)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --coverage")

    find_program(LCOV_PATH lcov)
    if(NOT LCOV_PATH)
      message(FATAL_ERROR "The COVERAGE flag requires 'lcov' installed")
    endif()

    add_custom_target(coverage
      COMMAND lcov -c -d CMakeFiles/rtm-core-sdk.dir/src -o CMakeFiles/coverage.info
      COMMAND genhtml CMakeFiles/coverage.info -o CMakeFiles/coverage_report
      COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --cyan "Check the ${CMAKE_CURRENT_BINARY_DIR}/CMakeFile/coverage_report to get more information"
      DEPENDS CMakeFiles/rtm-core-sdk.dir/src/*.gcda
      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
      COMMENT "Generating coverage information"
      VERBATIM
    )
endif()

if (${CMAKE_C_COMPILER_ID} MATCHES "Clang")
  # using Clang
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu89 -Wall -Werror -Wno-long-long -Wno-unknown-pragmas")
elseif (${CMAKE_C_COMPILER_ID} MATCHES "GNU")
  # using GCC
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu89 -Wall -Werror -Wno-long-long -Wno-unknown-pragmas")
elseif (${CMAKE_C_COMPILER_ID} MATCHES "Intel")
  # using Intel C++
  # set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -Wno-long-long")
elseif (MSVC)
  # using Visual Studio C++
  string(REGEX REPLACE "/W[0-4]" "/Wall" CMAKE_CC_FLAGS "${CMAKE_C_FLAGS}")
endif()

if(USE_GNUTLS AND USE_OPENSSL)
  message(FATAL_ERROR "USE_GNUTLS and USE_OPENSSL are mutually exclusive")
endif()

if(USE_GNUTLS AND USE_APPLE_SSL)
  message(FATAL_ERROR "USE_GNUTLS and USE_APPLE_SSL are mutually exclusive")
endif()

if(USE_OPENSSL AND USE_APPLE_SSL)
  message(FATAL_ERROR "USE_OPENSSL and USE_APPLE_SSL are mutually exclusive")
endif()

if(NOT(USE_OPENSSL OR USE_APPLE_SSL OR USE_GNUTLS))
  if(APPLE)
    set(USE_APPLE_SSL ON)
  else()
    set(USE_OPENSSL ON)
  endif()
endif()

include_directories(.)
include_directories(system ../vendor)

# Construct sources list

set(SOURCES src/rtm.c src/rtm_json.c)

if(UNIX)
list(APPEND SOURCES src/rtm_posix.c)
elseif(MSVC)
list(APPEND SOURCES src/rtm_windows.c)
else()
message(FATAL_ERROR "Environment that is neither UNIX nor Visual Studio is not supported")
endif()

if(USE_GNUTLS)
  list(APPEND SOURCES src/rtm_gnutls.c)
elseif(USE_OPENSSL)
  list(APPEND SOURCES src/rtm_openssl.c src/rtm_openssl_bio.c)
elseif(USE_APPLE_SSL)
  list(APPEND SOURCES src/rtm_apple_ssl.c)
endif()

# sources list is now ready

if(BUILD_STATIC)
    add_library(rtm-core-sdk STATIC ${SOURCES})
else()
    add_library(rtm-core-sdk SHARED ${SOURCES})
endif()

set_target_properties(rtm-core-sdk PROPERTIES LINKER_LANGUAGE C)

if(UNIX)
else()
target_link_libraries(rtm-core-sdk wsock32 ws2_32)
add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif()

include_directories("$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/src>")

if(USE_GNUTLS)
  find_package(GnuTLS REQUIRED)
  message(STATUS "GNU TLS: " ${GNUTLS_VERSION_STRING})

  include_directories(${GNUTLS_INCLUDE_DIR})
  target_link_libraries(rtm-core-sdk ${GNUTLS_LIBRARIES})
  add_definitions(-DUSE_GNUTLS ${GNUTLS_DEFINITIONS})

elseif(USE_OPENSSL)

  add_definitions(-DUSE_OPENSSL)

  if (MSVC)
      message(WARNING
          "\nAutomatically finding OpenSSL on Windows is not supported yet. "
          "Please install OpenSSL and configure the Visual Studio Project to find it. ")
  else()
      find_package(OpenSSL REQUIRED)
      add_definitions(${OPENSSL_DEFINITIONS})
      message(STATUS "OpenSSL: " ${OPENSSL_VERSION})
      include_directories(${OPENSSL_INCLUDE_DIR})
      target_link_libraries(rtm-core-sdk ${OPENSSL_LIBRARIES})
  endif(MSVC)

elseif(USE_APPLE_SSL)
  message(STATUS "Selected Apple Security framework")

  target_link_libraries(rtm-core-sdk PUBLIC "-framework foundation" "-framework security")
  add_definitions(-DUSE_APPLE_SSL)

else()
  message(STATUS "No TLS backend selected.")

endif()

if(DOC)
  find_package(Doxygen REQUIRED)
  add_custom_target(documentation ALL
                    COMMAND ${DOXYGEN_EXECUTABLE} ${doxyfile}
                    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
                    COMMENT "Generating API documentation with Doxygen"
                    VERBATIM)
  configure_file(${CMAKE_CURRENT_SOURCE_DIR}/docs/Doxyfile.in
                 ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile @ONLY)

  install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/docs/html DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/docs)

endif()

if(OSX)
    if(BUILD_STATIC)
      set_target_properties(rtm-core-sdk PROPERTIES
                            OUTPUT_NAME "SatoriCoreSDKtatic"
                            INSTALL_NAME_DIR "@rpath/SatoriCoreSDKStatic.framework"
                            INSTALL_RPATH "@executable_path/Frameworks;@loader_path/Frameworks"
                            )
      install(FILES src/rtm.h
              DESTINATION include/SatoriCoreSDKStatic
              RENAME Core.h
              )
  else()
      set_target_properties(rtm-core-sdk PROPERTIES
                            OUTPUT_NAME "SatoriCoreSDK"
                            INSTALL_NAME_DIR "@rpath/SatoriCoreSDK.framework"
                            INSTALL_RPATH "@executable_path/Frameworks;@loader_path/Frameworks"
                            )
      install(FILES src/rtm.h
              DESTINATION include/SatoriCoreSDK
              RENAME Core.h
              )
  endif()
endif()

install(FILES src/rtm.h
        DESTINATION "${INSTALL_INC_DIR}"
       )
install(TARGETS rtm-core-sdk
        DESTINATION "${INSTALL_LIB_DIR}"
       )

if(examples)
  add_subdirectory(examples)
endif()

if(test)
  add_definitions(-DRTM_TEST_ENV)
  add_subdirectory(test)
endif()

if(bench)
  add_subdirectory(bench)
endif()

if(perf)
  add_subdirectory(perf)
endif()
