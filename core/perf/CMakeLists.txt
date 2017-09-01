cmake_minimum_required(VERSION 2.8)

include_directories(.)

string(REGEX REPLACE "gnu89" "gnu99" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")

add_executable(perf "perf.c")
target_link_libraries(perf rtm-core-sdk m)
