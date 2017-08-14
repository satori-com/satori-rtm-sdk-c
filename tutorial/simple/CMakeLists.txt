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

add_executable(simple_tutorial "main.c")

if(CREDENTIALS_FILE)
  set_source_files_properties(main.cc OBJECT_DEPENDS ${CREDENTIALS_FILE})
endif()

if(TARGET rtm-core-sdk)
  add_dependencies(simple_tutorial rtm-core-sdk)
  target_link_libraries(simple_tutorial rtm-core-sdk)
else()
  find_package(PkgConfig REQUIRED)
  pkg_search_module(RTM REQUIRED satori-rtm)
  target_link_libraries(simple_tutorial ${RTM_LIBRARIES})
  include_directories(${RTM_INCLUDE_DIRS})
endif()
