if(WIN32)
  add_executable(stamp
    stamp.c
  )
  target_link_libraries(stamp bee2)
endif()
