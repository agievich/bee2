find_package(Doxygen)

if(NOT DOXYGEN_FOUND)
  message(FATAL_ERROR
    "Doxygen is needed to build the documentation.")
endif()

set(doxyfile bee2.doxy)
set(doxy_html_index_file html/index.html)

add_custom_command(OUTPUT ${doxy_html_index_file}
  COMMAND ${DOXYGEN_EXECUTABLE} ${doxyfile}
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  DEPENDS ${doxyfile}
  COMMENT "Generating HTML documentation")
 
add_custom_target(doc ALL DEPENDS ${doxy_html_index_file})

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/html/
  DESTINATION share/bee2/doc)
