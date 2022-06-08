if(MSVC)
  # disable security warnings for fopen()
  add_definitions(/D _CRT_SECURE_NO_WARNINGS)
endif()

add_executable(bee2cmd
	cmd.c
	bsum/bsum.c
)

target_link_libraries(bee2cmd bee2_static)

install(TARGETS bee2cmd
        DESTINATION ${BIN_INSTALL_DIR}
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
