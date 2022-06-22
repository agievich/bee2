if(MSVC)
  # disable security warnings for fopen()
  add_definitions(/D _CRT_SECURE_NO_WARNINGS)
endif()

add_executable(bee2cmd
	bsum/bsum.c
	kg/kg.c
	ver/ver.c
	cmd_core.c
	cmd_main.c
	cmd_privkey.c
	cmd_pwd.c
)

if(WIN32)
  add_executable(bee2cmp
    stamp.c
  )
endif()

target_link_libraries(bee2cmd bee2_static)

install(TARGETS bee2cmd
        DESTINATION ${BIN_INSTALL_DIR}
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
