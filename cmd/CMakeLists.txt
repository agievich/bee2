add_executable(bee2cmd
  affix/affix.c
  bsum/bsum.c
  core/cmd_arg.c
  core/cmd_cvc.c
  core/cmd_date.c
  core/cmd_file.c
  core/cmd_print.c
  core/cmd_privkey.c
  core/cmd_pwd.c
  core/cmd_rng.c
  core/cmd_sig.c
  core/cmd_st.c
  core/cmd_stamp.c
  core/cmd_sys.c
  core/cmd_term.c
  core/whereami.c
  csr/csr.c
  cvc/cvc.c
  cvr/cvr.c
  es/es.c
  kg/kg.c
  pwd/pwd.c
  sig/sig.c
  stamp/stamp.c
  st/st.c
  ver/ver.c
  cmd_main.c
)

include_directories(include)

target_link_libraries(bee2cmd bee2_static)

install(TARGETS bee2cmd
  DESTINATION ${BIN_INSTALL_DIR}
  PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE 
    WORLD_READ WORLD_EXECUTE
) 

# Post

add_custom_command(TARGET bee2cmd
  POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E 
    copy $<TARGET_FILE:bee2cmd> $<TARGET_FILE:bee2cmd>.bak
  COMMAND $<TARGET_FILE:bee2cmd> stamp gen $<TARGET_FILE:bee2cmd>.bak
  COMMAND ${CMAKE_COMMAND} -E 
    copy $<TARGET_FILE:bee2cmd>.bak $<TARGET_FILE:bee2cmd>
  VERBATIM
)
