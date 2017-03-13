cmake_minimum_required(VERSION 3.4)

link_directories(${GBENCH_BIN_DIR}/src/Release)
link_directories(${GBENCH_BIN_DIR}/src/Debug)
link_directories(${GBENCH_BIN_DIR}/src)

find_package(Threads REQUIRED)

add_executable(rtm_benchmark "rtm_benchmark.cpp")
target_include_directories(rtm_benchmark PRIVATE ${GBENCH_INCLUDE_DIR})
target_link_libraries(rtm_benchmark rtm-core-sdk ${GBENCH_LIBRARY} ${CMAKE_THREAD_LIBS_INIT})
