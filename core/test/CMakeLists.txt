cmake_minimum_required(VERSION 3.4)

enable_testing()

find_package(Threads REQUIRED)

link_directories(${GTEST_BIN_DIR})
set(CMAKE_CXX_STANDARD 11)
file(GLOB TEST_FILES *_test.cpp)
add_executable(rtm_unit_tests ${TEST_FILES})
add_definitions(-DTEST)

if(USE_APPLE_SSL)
target_compile_definitions(rtm_unit_tests PRIVATE USE_APPLE_SSL)
endif()
if(USE_OPENSSL)
target_compile_definitions(rtm_unit_tests PRIVATE USE_OPENSSL)
target_include_directories(rtm_unit_tests PRIVATE ${OPENSSL_INCLUDE_DIR})
endif()
if(USE_GNUTLS)
target_compile_definitions(rtm_unit_tests PRIVATE USE_GNUTLS)
target_include_directories(rtm_unit_tests PRIVATE ${GNUTLS_INCLUDE_DIR})
endif()

target_include_directories(rtm_unit_tests SYSTEM PRIVATE
  "../../vendor"
  ${GTEST_INCLUDE_DIR}
)

target_link_libraries(rtm_unit_tests rtm-core-sdk ${GTEST_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
