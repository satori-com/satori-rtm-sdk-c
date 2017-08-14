cmake_minimum_required(VERSION 2.8)

# Make the credentials configurable
if(NOT TARGET rtm-core-sdk)
  set(YOUR_ENDPOINT "" CACHE STRING "Endpoint to use in example/test applications")
  set(YOUR_APPKEY "" CACHE STRING "Appkey to use in example/test applications")
  set(YOUR_ROLE "" CACHE STRING "Role to use in example/test applications")
  set(YOUR_ROLE_SECRET "" CACHE STRING "Secret to use in example/test applications")
  add_definitions(-DYOUR_ENDPOINT="${YOUR_ENDPOINT}" -DYOUR_APPKEY="${YOUR_APPKEY}")
  add_definitions(-DYOUR_ROLE="${YOUR_ROLE}" -DYOUR_ROLE_SECRET="${YOUR_ROLE_SECRET}")
endif()

# This example requires Boost
if(TARGET rtm-core-sdk)
  find_package(Boost COMPONENTS system)
  if(NOT Boost_FOUND)
    message(WARNING "Boost libraries not found. Skipping boost::asio tutorial.")
    return()
  endif()
else()
  find_package(Boost REQUIRED COMPONENTS system)
endif()

add_library(boost INTERFACE IMPORTED)
set_property(TARGET boost PROPERTY
    INTERFACE_INCLUDE_DIRECTORIES ${Boost_INCLUDE_DIR})

# ..and makes use of modern c++
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -Wall -Wextra -pthread")

add_executable(boost_asio_tutorial "main.cc")

if(CREDENTIALS_FILE)
  set_source_files_properties(main.cc OBJECT_DEPENDS ${CREDENTIALS_FILE})
endif()

target_link_libraries(boost_asio_tutorial ${SATORI_LIBRARIES})
target_link_libraries(boost_asio_tutorial ${Boost_LIBRARIES})

# Link against SDK
if(TARGET rtm-core-sdk)
  add_dependencies(boost_asio_tutorial rtm-core-sdk)
  target_link_libraries(boost_asio_tutorial rtm-core-sdk)
else()
  find_package(PkgConfig REQUIRED)
  pkg_search_module(RTM REQUIRED satori-rtm)
  target_link_libraries(boost_asio_tutorial ${RTM_LIBRARIES})
  include_directories(${RTM_INCLUDE_DIRS})
endif()
