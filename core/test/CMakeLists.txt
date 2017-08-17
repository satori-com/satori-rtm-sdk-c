cmake_minimum_required(VERSION 2.8)

enable_testing()

find_package(Threads REQUIRED)

link_directories(${GTEST_BIN_DIR})
if(UNIX)
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++0x")
endif()
file(GLOB TEST_FILES *_test.cpp)
add_executable(rtm_unit_tests ${TEST_FILES})

if(USE_APPLE_SSL)
  add_definitions(-DUSE_APPLE_SSL)
elseif(USE_OPENSSL)
  add_definitions(-DUSE_OPENSSL)
  set_property(TARGET rtm_unit_tests APPEND PROPERTY INCLUDE_DIRECTORIES ${OPENSSL_INCLUDE_DIR})
elseif(USE_GNUTLS)
  add_definitions(-DUSE_GNUTLS)
  set_property(TARGET rtm_unit_tests APPEND PROPERTY INCLUDE_DIRECTORIES ${GNUTLS_INCLUDE_DIR})
endif()

include_directories(
  "../src"
  "../vendor"
  ${GTEST_INCLUDE_DIR}
)

if(CREDENTIALS_FILE)
  foreach(FILE IN LISTS TEST_FILES)
    set_source_files_properties(${FILE} OBJECT_DEPENDS ${CREDENTIALS_FILE})
  endforeach()
endif()

target_link_libraries(rtm_unit_tests rtm-core-sdk ${GTEST_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
