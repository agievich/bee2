configure_file(${CMAKE_CURRENT_SOURCE_DIR}/bee2/info.h.in 
	${CMAKE_CURRENT_SOURCE_DIR}/bee2/info.h @ONLY)
message(STATUS "Configured ${CMAKE_CURRENT_SOURCE_DIR}/bee2/info.h.in")

if(INSTALL_HEADERS)
  install(DIRECTORY bee2 
    DESTINATION include
    PATTERN "info.h.in" EXCLUDE
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
endif()
