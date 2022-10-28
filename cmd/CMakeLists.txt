if(MSVC)
  # disable security warnings for fopen()
  add_definitions(/D _CRT_SECURE_NO_WARNINGS)
endif()

add_executable(bee2cmd
	core/cmd_arg.c
	core/cmd_cvc.c
	core/cmd_file.c
	core/cmd_privkey.c
	core/cmd_pwd.c
	core/cmd_rng.c
	core/cmd_sig.c
	core/cmd_term.c
	core/whereami.c
	core/cmd_aead.c
	core/cmd_aead_pke.c
	core/cmd_aead_pwd.c
	bsum/bsum.c
	cvc/cvc.c
	kg/kg.c
	pwd/pwd.c
	sig/sig.c
	ver/ver.c
	aead/aead.c
	cmd_main.c
)

if(WIN32)
  target_sources(bee2cmd
    PRIVATE stamp/stamp.c
  )
endif()

target_link_libraries(bee2cmd bee2_static)

install(TARGETS bee2cmd
        DESTINATION ${BIN_INSTALL_DIR}
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
