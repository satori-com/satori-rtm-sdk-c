cmake_minimum_required(VERSION 2.8)

# Download & compile the SDK, and link against it
include(ExternalProject)
ExternalProject_Add(satori_sdk
  GIT_REPOSITORY https://github.com/satori-com/satori-rtm-sdk-c.git
  GIT_TAG "v2.0.0"
  PREFIX "${CMAKE_CURRENT_BINARY_DIR}/deps/satori-sdk"
  DOWNLOAD_DIR "${CMAKE_CURRENT_BINARY_DIR}/deps/satori-sdk"
  BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/deps/satori-sdk"
  CMAKE_ARGS -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER} -DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS} -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} ${SDK_SSL_OPTION}
  INSTALL_COMMAND ""
)
ExternalProject_Get_Property(satori_sdk source_dir)
include_directories(${source_dir}/core/src)
ExternalProject_Get_Property(satori_sdk binary_dir)
set(SATORI_BIN_DIR "${binary_dir}/core")
set(SATORI_LIBRARIES rtm-core-sdk)
link_directories(${SATORI_BIN_DIR})

# This example requires Boost
find_package(Boost REQUIRED COMPONENTS system)
add_library(boost INTERFACE IMPORTED)
set_property(TARGET boost PROPERTY
    INTERFACE_INCLUDE_DIRECTORIES ${Boost_INCLUDE_DIR})

# ..and makes use of modern c++
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -Wall -Wextra")

add_executable(tutorial "main.cc")
add_dependencies(tutorial satori_sdk)
target_link_libraries(tutorial ${SATORI_LIBRARIES})
target_link_libraries(tutorial ${Boost_LIBRARIES})
