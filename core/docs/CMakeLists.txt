find_package(Doxygen REQUIRED)
add_custom_target(documentation ALL
                  COMMAND ${DOXYGEN_EXECUTABLE} ${doxyfile}
                  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
                  COMMENT "Generating API documentation with Doxygen"
                  VERBATIM)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in
               ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile @ONLY)

install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/html DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
