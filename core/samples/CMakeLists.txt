cmake_minimum_required(VERSION 2.8)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99")

include_directories(
  ${CMAKE_CURRENT_LIST_DIR}/../src
)

macro(compile_sample name)
  add_executable(${name} "${name}.c")
  target_link_libraries(${name} rtm-core-sdk)
endmacro(compile_sample)

compile_sample(sample1)
