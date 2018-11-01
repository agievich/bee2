set(src
  core/b64.c
  core/blob.c
  core/dec.c
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
  crypto/bash/bash_f.c
  crypto/bash/bash_hash.c
  crypto/bash/bash_ae.c
  crypto/bels.c
  crypto/belt/belt_block.c
  crypto/belt/belt_wbl.c
  crypto/belt/belt_int.c
  crypto/belt/belt_cbc.c
  crypto/belt/belt_cfb.c
  crypto/belt/belt_ctr.c
  crypto/belt/belt_dwp.c
  crypto/belt/belt_ecb.c
  crypto/belt/belt_bde.c
  crypto/belt/belt_sde.c
  crypto/belt/belt_fmt.c
  crypto/belt/belt_hash.c
  crypto/belt/belt_hmac.c
  crypto/belt/belt_krp.c
  crypto/belt/belt_kwp.c
  crypto/belt/belt_mac.c
  crypto/belt/belt_pbkdf.c
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
  math/zz/zz_add.c
  math/zz/zz_etc.c
  math/zz/zz_gcd.c
  math/zz/zz_mod.c
  math/zz/zz_mul.c
  math/zz/zz_pow.c
  math/zz/zz_red.c
)

add_library(bee2_static STATIC ${src})
set_target_properties(bee2_static PROPERTIES OUTPUT_NAME bee2_static)
target_link_libraries(bee2_static ${libs})

install(TARGETS bee2_static
  DESTINATION ${LIB_INSTALL_DIR}
  PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

if(BUILD_SHARED_LIBS)
  if(NOT WIN32)
    add_library(bee2 SHARED ${src})
  else()
    if(MSVC)
      # disable the security warnings for sprintf() in bee2.c
      add_definitions(/D _CRT_SECURE_NO_WARNINGS)
    endif()
    add_library(bee2 SHARED ${src} 
      ../win/bee2.def
      ../win/bee2.bmp
      ../win/bee2.rc
      ../win/bee2.c
    )
  endif()

  target_link_libraries(bee2 ${libs})

# uncomment next lines to keep track of bee2.so with version numbers
# set_target_properties(bee2 PROPERTIES 
#   VERSION ${BEE2_VERSION_MAJOR}.${BEE2_VERSION_MINOR}.${BEE2_VERSION_PATCH}
#   SOVERSION 2.0)

  install(TARGETS bee2
    DESTINATION ${LIB_INSTALL_DIR}
    PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
endif()
