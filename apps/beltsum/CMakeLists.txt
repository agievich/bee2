add_executable(beltsum
	beltsum.c
)
target_link_libraries(beltsum bee2)

install(TARGETS beltsum
        DESTINATION ${BIN_INSTALL_DIR}
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
