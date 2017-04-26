cmake_minimum_required(VERSION 2.8)

link_directories(${GBENCH_BIN_DIR}/src/Release)
link_directories(${GBENCH_BIN_DIR}/src/Debug)
link_directories(${GBENCH_BIN_DIR}/src)

find_package(Threads REQUIRED)

add_executable(rtm_benchmark "rtm_benchmark.cpp")
set_property(TARGET rtm_benchmark APPEND PROPERTY INCLUDE_DIRECTORIES ${GBENCH_INCLUDE_DIR})
target_link_libraries(rtm_benchmark rtm-core-sdk ${GBENCH_LIBRARY} ${CMAKE_THREAD_LIBS_INIT})
