cmake_minimum_required(VERSION 2.8)

if(UNIX)
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}  -std=c99")
endif()

include_directories(
  ${CMAKE_CURRENT_LIST_DIR}/../src
)

macro(compile_sample name)
  add_executable(${name} "${name}.c")
  target_link_libraries(${name} rtm-core-sdk)
endmacro(compile_sample)

compile_sample(subscribe_to_open_data_channel)
compile_sample(auth_publish_subscribe)
compile_sample(auth_publish)
compile_sample(subscribe)