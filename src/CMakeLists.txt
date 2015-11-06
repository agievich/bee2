set(src
  core/blob.c
  core/der.c
  core/err.c
  core/mem.c
  core/mt.c
  core/hex.c
  core/obj.c
  core/oid.c
  core/prng.c
  core/rng.c
  core/str.c
  core/tm.c
  core/u16.c
  core/u32.c
  core/u64.c
  core/util.c
  core/word.c
  crypto/bake.c
  crypto/bash.c
  crypto/bels.c
  crypto/belt.c
  crypto/bign.c
  crypto/botp.c
  crypto/brng.c
  crypto/dstu.c
  crypto/g12s.c
  crypto/pfok.c
  math/ec.c
  math/ec2.c
  math/ecp.c
  math/gf2.c
  math/gfp.c
  math/pp.c
  math/pri.c
  math/qr.c
  math/ww.c
  math/zm.c
  math/zz.c
)

if(NOT BUILD_STATIC_LIBS AND NOT BUILD_SHARED_LIBS)
  message(FATAL_ERROR "Need to choose static or shared bee2 build!")
endif()

if(BUILD_STATIC_LIBS)
  if(NOT BUILD_SHARED_LIBS)
    set(bee2_static_target "bee2")
  else()
    # if we build both static and shared, then let
    # tests and apps link to the shared lib target
    set(bee2_static_target "bee2_static")
  endif()

  add_library(${bee2_static_target} STATIC ${src})
  set_target_properties(${bee2_static_target} PROPERTIES OUTPUT_NAME ${bee2_static_target})
  target_link_libraries(${bee2_static_target} ${libs})

  install(TARGETS ${bee2_static_target}
    DESTINATION ${LIB_INSTALL_DIR}
    PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
endif()

if(BUILD_SHARED_LIBS)
  add_library(bee2 SHARED ${src})
  target_link_libraries(bee2 ${libs})

# uncomment next lines to keep track of bee2.so with version numbers
# set_target_properties(bee2 PROPERTIES 
#   VERSION ${BEE2_VERSION_MAJOR}.${BEE2_VERSION_MINOR}.${BEE2_VERSION_PATCH}
#   SOVERSION 2.0)

  install(TARGETS bee2
    DESTINATION ${LIB_INSTALL_DIR}
    PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
endif()
