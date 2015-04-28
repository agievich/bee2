if(WIN32)
  add_executable(stamp
    stamp.c
    stamp_pe.c
  )
  target_link_libraries(stamp bee2)
endif()
