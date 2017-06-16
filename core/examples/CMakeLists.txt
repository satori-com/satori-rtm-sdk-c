cmake_minimum_required(VERSION 2.8)

if (UNIX)
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}  -std=c99")
endif ()

include_directories(
        ${CMAKE_CURRENT_LIST_DIR}/../src
)

macro(compile_example name)
    add_executable(${name} "${name}.c")
    target_link_libraries(${name} rtm-core-sdk)
endmacro(compile_example)

file(GLOB all_examples . *.c)
foreach (example_file ${all_examples})
    get_filename_component(example_name "${example_file}" "NAME_WE")
    compile_example("${example_name}")
endforeach (example_file)
