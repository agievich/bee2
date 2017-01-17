if(MSVC)
  # disable the security warnings for fopen()
  add_definitions(/D _CRT_SECURE_NO_WARNINGS)
endif()

add_executable(bsum
	bsum.c
)

target_link_libraries(bsum bee2_static)

install(TARGETS bsum
        DESTINATION ${BIN_INSTALL_DIR}
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
