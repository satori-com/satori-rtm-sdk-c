include_directories(.)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99")

add_executable(perf "perf.c")
target_link_libraries(perf rtm-core-sdk m)
