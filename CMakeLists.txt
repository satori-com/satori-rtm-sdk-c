cmake_minimum_required(VERSION 2.8)

project(satori-sdk-c)
include(ExternalProject)

include_directories(.)

option(test "Build all test." OFF)
option(bench "Build all benchmarks." OFF)
option(examples "Build all examples." OFF)

if(LINUX)
	find_package(GNUInstallDirs)
endif(LINUX)
if(NOT GNUInstallDirs_FOUND)
	# Following GNUInstallDirs naming conventions
	set(CMAKE_INSTALL_INCLUDEDIR "include" CACHE PATH "Installation directory for header files")
	set(CMAKE_INSTALL_LIBDIR "lib" CACHE PATH "Installation directory for library files")
endif(NOT GNUInstallDirs_FOUND)
set(CMAKE_INSTALL_PKGCONFIGDIR "${CMAKE_INSTALL_LIBDIR}/pkgconfig" CACHE PATH "Installation directory for pkgconfig (.pc) files")
set(VERSION 2.0)

if(test)
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

if(bench)
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

add_subdirectory(core)
