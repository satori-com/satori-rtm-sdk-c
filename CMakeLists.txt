cmake_minimum_required(VERSION 2.8)

project(satori-sdk-c)
include(ExternalProject)

option(TESTS "Build all tests." OFF)
option(BENCH "Build all benchmarks." OFF)
option(EXAMPLES "Build all examples." OFF)
option(TUTORIALS "Build tutorials." OFF)

# Make credentials configurable

set(YOUR_ENDPOINT "" CACHE STRING "Endpoint to use in example/test applications")
set(YOUR_APPKEY "" CACHE STRING "Appkey to use in example/test applications")
set(YOUR_ROLE "" CACHE STRING "Role to use in example/test applications")
set(YOUR_ROLE_SECRET "" CACHE STRING "Secret to use in example/test applications")
set(YOUR_CHANNEL "" CACHE STRING "Channel to use in example/test applications")

# Load credentials from credentials.json file for CI

set(CREDENTIALS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/credentials.json")
if(NOT EXISTS "${CREDENTIALS_FILE}")
  include("parse_credentials.cmake.txt")
endif()

if((TESTS OR EXAMPLES OR TUTORIALS) AND ((NOT YOUR_ENDPOINT) OR (NOT YOUR_APPKEY)))
  message(FATAL_ERROR "You need to configure an endpoint and appkey to compile examples/tests/tutorials. See README.md.")
endif()

add_definitions(-DYOUR_ENDPOINT="${YOUR_ENDPOINT}" -DYOUR_APPKEY="${YOUR_APPKEY}")
add_definitions(-DYOUR_ROLE="${YOUR_ROLE}" -DYOUR_ROLE_SECRET="${YOUR_ROLE_SECRET}")
add_definitions(-DYOUR_CHANNEL="${YOUR_CHANNEL}")

if(LINUX)
	find_package(GNUInstallDirs)
endif(LINUX)
if(NOT GNUInstallDirs_FOUND)
	# Following GNUInstallDirs naming conventions
	set(CMAKE_INSTALL_INCLUDEDIR "include" CACHE PATH "Installation directory for header files")
	set(CMAKE_INSTALL_LIBDIR "lib" CACHE PATH "Installation directory for library files")
endif(NOT GNUInstallDirs_FOUND)
set(CMAKE_INSTALL_PKGCONFIGDIR "${CMAKE_INSTALL_LIBDIR}/pkgconfig" CACHE PATH "Installation directory for pkgconfig (.pc) files")

set(MAJOR_VERSION 2)
set(MINOR_VERSION 0)
set(PATCH_VERSION 0)

if(TESTS)
  ExternalProject_Add(googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG "release-1.7.0"
    PREFIX "${CMAKE_SOURCE_DIR}/deps/gtest"
    DOWNLOAD_DIR "${CMAKE_SOURCE_DIR}/deps/gtest"
    BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/deps/gtest"
    CMAKE_ARGS -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER} -DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS} -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -DBUILD_SHARED_LIBS=ON -Wno-dev
    INSTALL_COMMAND ""
  )

  ExternalProject_Get_Property(googletest source_dir)
  set(GTEST_INCLUDE_DIR ${source_dir}/include)

  ExternalProject_Get_Property(googletest binary_dir)
  set(GTEST_BIN_DIR "${binary_dir}")
  set(GTEST_LIBRARIES gtest gtest_main)
endif()

if(BENCH)
  ExternalProject_Add(googlebench
    GIT_REPOSITORY https://github.com/google/benchmark.git
    GIT_TAG "v1.0.0"
    PREFIX "${CMAKE_SOURCE_DIR}/deps/gbench"
    DOWNLOAD_DIR "${CMAKE_SOURCE_DIR}/deps/gbench"
    BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/deps/gbench"
    CMAKE_ARGS -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER} -DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS} -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -DBENCHMARK_ENABLE_TESTING=OFF -Wno-dev
    INSTALL_COMMAND ""
  )

  ExternalProject_Get_Property(googlebench source_dir)
  set(GBENCH_INCLUDE_DIR ${source_dir}/include)

  ExternalProject_Get_Property(googlebench binary_dir)
  set(GBENCH_BIN_DIR "${binary_dir}")
  set(GBENCH_LIBRARY benchmark)
endif()

include_directories(core/src/)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/core)

add_subdirectory(core)

if(TUTORIALS)
  add_subdirectory(tutorial)
endif()
