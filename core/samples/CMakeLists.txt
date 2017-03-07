cmake_minimum_required(VERSION 3.4)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99")

macro(compile_sample name)
  add_executable(${name} "${name}.c")
  target_link_libraries(${name} rtm-core-sdk)
endmacro(compile_sample)

compile_sample(sample1)
