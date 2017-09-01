cmake_minimum_required(VERSION 2.8)
project(RTM_CORE_SDK)

if (NOT CMAKE_VERSION VERSION_LESS 3.4)
    cmake_policy(SET CMP0054 NEW)
    cmake_policy(SET CMP0021 NEW)
    cmake_policy(SET CMP0042 NEW)
endif ()

option(ENABLE_LOGGING "Compile with logging support" ON)
option(USE_GNUTLS "Use GNUTLS backend" OFF)
option(USE_OPENSSL "Use OpenSSL backend" OFF)
option(USE_APPLE_SSL "Use Apple TLS backend" OFF)
option(DOC "Build the documentation" OFF)
option(BUILD_STATIC "Build static version" OFF)
option(COVERAGE "Generate coverage statistics" OFF)

# Set global compiler flags
if (${CMAKE_C_COMPILER_ID} MATCHES "Clang")
  # using Clang
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu11 -Wextra")
elseif (${CMAKE_C_COMPILER_ID} MATCHES "GNU")
  # using GCC
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu11 -Wextra")
elseif (${CMAKE_C_COMPILER_ID} MATCHES "Intel")
  # using Intel C++
  # set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -Wno-long-long")
elseif (MSVC)
  # using Visual Studio C++
  string(REGEX REPLACE "/W[0-4]" "/Wall" CMAKE_CC_FLAGS "${CMAKE_C_FLAGS}")
endif()

# Select SSL implementation
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
    find_package(OpenSSL)
    if(OPENSSL_FOUND)
      set(USE_OPENSSL ON)
    else()
      find_package(GnuTLS)
      if(GNUTLS_FOUND)
        set(USE_GNUTLS ON)
      else()
        message(FATAL_ERROR "Failed to find a SSL implementation. Please install OpenSSL or GnuTLS.")
      endif()
    endif()
  endif()
endif()

# Anything from the core will require access to the SDK
set(RTM_SDK_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src)
include_directories(${RTM_SDK_DIRECTORY})

if(USE_GNUTLS)
  find_package(GnuTLS REQUIRED)
  message(STATUS "GNU TLS: " ${GNUTLS_VERSION_STRING})

  include_directories(${GNUTLS_INCLUDE_DIR})
  add_definitions(-DUSE_GNUTLS ${GNUTLS_DEFINITIONS})
  set(TLS_LIBRARIES ${GNUTLS_LIBRARIES})
  set(PKG_CONFIG_REQUIRES "${PKG_CONFIG_REQUIRES} gnutls")
elseif(USE_OPENSSL)
    find_package(OpenSSL REQUIRED)
    message(STATUS "OpenSSL: " ${OPENSSL_VERSION})

    add_definitions(${OPENSSL_DEFINITIONS})
    include_directories(${OPENSSL_INCLUDE_DIR})
    set(TLS_LIBRARIES ${OPENSSL_LIBRARIES})

  add_definitions(-DUSE_OPENSSL)
  set(PKG_CONFIG_REQUIRES "${PKG_CONFIG_REQUIRES} openssl")

elseif(USE_APPLE_SSL)
  message(STATUS "Selected Apple Security framework")

  add_definitions(-DUSE_APPLE_SSL)
  set(TLS_LIBRARIES "-framework foundation" "-framework security")
  set(PKG_CONFIG_LIBS "${PKG_CONFIG_LIBS} -framework foundation -framework security")
endif()


if(COVERAGE)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --coverage")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --coverage")

    find_program(LCOV_PATH lcov)
    if(NOT LCOV_PATH)
      message(FATAL_ERROR "The COVERAGE flag requires 'lcov' installed")
    endif()

    add_custom_target(coverage
      COMMAND lcov -c -d src/CMakeFiles/rtm-core-sdk.dir -o CMakeFiles/coverage.info
      COMMAND genhtml CMakeFiles/coverage.info -o CMakeFiles/coverage_report
      COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --cyan "Check the ${CMAKE_CURRENT_BINARY_DIR}/CMakeFile/coverage_report to get more information"
      DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/src/CMakeFiles/rtm-core-sdk.dir/*.gcda
      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
      COMMENT "Generating coverage information"
      VERBATIM
    )
endif()

if(DOC)
  add_subdirectory(docs)
endif()

if(EXAMPLES)
  add_subdirectory(examples)
endif()

if(TESTS)
  add_definitions(-DRTM_TEST_ENV)
  add_subdirectory(test)
endif()

if(BENCH)
  add_subdirectory(bench)
endif()

if(PERF)
  add_subdirectory(perf)
endif()

if(UNIX)
  configure_file(${CMAKE_CURRENT_SOURCE_DIR}/satori-rtm.pc.in
                ${CMAKE_CURRENT_BINARY_DIR}/satori-rtm.pc
                @ONLY)
  install(FILES ${CMAKE_CURRENT_BINARY_DIR}/satori-rtm.pc
    DESTINATION "${CMAKE_INSTALL_PKGCONFIGDIR}")
endif()

add_subdirectory(src)
