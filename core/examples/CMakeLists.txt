cmake_minimum_required(VERSION 2.8)

file(GLOB all_examples . *.c)

foreach (example_file ${all_examples})
  get_filename_component(example_name "${example_file}" "NAME_WE")
  if(CREDENTIALS_FILE)
    set_source_files_properties(${example_file} OBJECT_DEPENDS ${CREDENTIALS_FILE})
  endif()
  add_executable(${example_name} "${example_name}.c")
  target_link_libraries(${example_name} rtm-core-sdk)
endforeach (example_file)
