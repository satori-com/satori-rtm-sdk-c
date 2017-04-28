cmake_minimum_required(VERSION 2.8)

# enable the module so we can use it
include(ExternalProject)

if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
set(SDK_SSL_OPTION "-DUSE_APPLE_SSL=ON")
else()
set(SDK_SSL_OPTION "-DUSE_OPENSSL=ON")
endif()

ExternalProject_Add(satori_sdk
  GIT_REPOSITORY https://github.com/satori-com/satori-sdk-c.git
  GIT_TAG "v1.0.1"
  PREFIX "${CMAKE_CURRENT_BINARY_DIR}/deps/satori-sdk"
  DOWNLOAD_DIR "${CMAKE_CURRENT_BINARY_DIR}/deps/satori-sdk"
  BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/deps/satori-sdk"

  # inherit compiler and flags, but also add SDK-specific flags
  CMAKE_ARGS -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER} -DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS} -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} ${SDK_SSL_OPTION}

  # no need to install, it's sufficient to just build it
  INSTALL_COMMAND ""
)

# this will allow us finding SDK headers
ExternalProject_Get_Property(satori_sdk source_dir)

# add SDK to project's include path
include_directories(${source_dir}/core/src)

# and this will allow us to find and link to SDK library
ExternalProject_Get_Property(satori_sdk binary_dir)
set(SATORI_BIN_DIR "${binary_dir}/core")
set(SATORI_LIBRARIES rtm-core-sdk)
link_directories(${SATORI_BIN_DIR})

add_executable(tutorial "main.c")

# this tells cmake to actually download and build the SDK when it builds the project
add_dependencies(tutorial satori_sdk)

# link project to SDK library
target_link_libraries(tutorial ${SATORI_LIBRARIES})