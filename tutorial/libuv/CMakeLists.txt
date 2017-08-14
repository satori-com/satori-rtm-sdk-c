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

# add libuv as a dependency
find_package(PkgConfig REQUIRED)
if(TARGET rtm-core-sdk)
  pkg_search_module(LIBUV libuv)
  if(NOT LIBUV_VERSION)
    message(WARNING "libuv not found. Skipping libuv tutorial.")
    return()
  endif()
else()
  pkg_search_module(LIBUV REQUIRED libuv)
endif()

add_executable(libuv_tutorial "main.c")

if(CREDENTIALS_FILE)
  set_source_files_properties(main.c OBJECT_DEPENDS ${CREDENTIALS_FILE})
endif()

target_compile_options(libuv_tutorial PUBLIC ${LIBUV_CFLAGS_OTHER})
target_include_directories(libuv_tutorial PUBLIC ${LIBUV_INCLUDE_DIRS})
target_link_libraries(libuv_tutorial ${LIBUV_LIBRARIES})

# link project to SDK library
if(TARGET rtm-core-sdk)
  add_dependencies(libuv_tutorial rtm-core-sdk)
  target_link_libraries(libuv_tutorial rtm-core-sdk)
else()
  pkg_search_module(RTM REQUIRED satori-rtm)
  target_link_libraries(libuv_tutorial ${RTM_LIBRARIES})
  include_directories(${RTM_INCLUDE_DIRS})
endif()
