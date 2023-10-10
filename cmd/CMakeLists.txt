if(MSVC)
  # disable security warnings for fopen()
  add_definitions(/D _CRT_SECURE_NO_WARNINGS)
endif()

add_executable(bee2cmd
	core/cmd_arg.c
	core/cmd_cvc.c
	core/cmd_date.c
	core/cmd_file.c
	core/cmd_print.c
	core/cmd_privkey.c
	core/cmd_pwd.c
	core/cmd_rng.c
	core/cmd_sig.c
	core/cmd_term.c
	core/whereami.c
	bsum/bsum.c
	cvc/cvc.c
	cvr/cvr.c
	es/es.c
	kg/kg.c
	pwd/pwd.c
	sig/sig.c
	ver/ver.c
	cmd_main.c
)

# CMake does not set MINGW in MSys2[MinGW] environment
if(WIN32 OR MINGW OR ${CMAKE_C_PLATFORM_ID} STREQUAL MinGW)
  target_sources(bee2cmd
    PRIVATE stamp/stamp.c
  )
endif()

target_link_libraries(bee2cmd bee2_static)

install(TARGETS bee2cmd
        DESTINATION ${BIN_INSTALL_DIR}
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
