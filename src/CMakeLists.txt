set(src
  core/apdu.c
  core/b64.c
  core/blob.c
  core/dec.c
  core/der.c
  core/err.c
  core/file.c
  core/hex.c
  core/json.c
  core/mem.c
  core/mt.c
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
  crypto/bash/bash_prg.c
  crypto/bels.c
  crypto/belt/belt_block.c
  crypto/belt/belt_wbl.c
  crypto/belt/belt_lcl.c
  crypto/belt/belt_cbc.c
  crypto/belt/belt_cfb.c
  crypto/belt/belt_compr.c
  crypto/belt/belt_ctr.c
  crypto/belt/belt_dwp.c
  crypto/belt/belt_che.c
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
  crypto/bign/bign_ibs.c
  crypto/bign/bign_keyt.c
  crypto/bign/bign_lcl.c
  crypto/bign/bign_misc.c
  crypto/bign/bign_params.c
  crypto/bign/bign_sign.c
  crypto/bign96.c
  crypto/bpki.c
  crypto/botp.c
  crypto/brng.c
  crypto/btok/btok_bauth.c
  crypto/btok/btok_cvc.c
  crypto/btok/btok_pwd.c
  crypto/btok/btok_sm.c
  crypto/dstu.c
  crypto/g12s.c
  crypto/stb99.c
  crypto/pfok.c
  math/ec.c
  math/ec2.c
  math/ecp.c
  math/gf2.c
  math/gfp.c
  math/pp/pp_etc.c
  math/pp/pp_gcd.c
  math/pp/pp_mod.c
  math/pp/pp_mul.c
  math/pp/pp_red.c
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

if(UNIX AND NOT APPLE)
  target_link_libraries(bee2_static ${CMAKE_DL_LIBS})
else()
  target_link_libraries(bee2_static)
endif()

set_property(TARGET bee2_static PROPERTY POSITION_INDEPENDENT_CODE 
  ${BUILD_PIC})

install(TARGETS bee2_static
  DESTINATION ${LIB_INSTALL_DIR}
  PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE 
    WORLD_READ WORLD_EXECUTE)

if(BUILD_SHARED_LIBS)
  if (CMAKE_COMPILER_IS_MSVC)
    set (src ${src} 
      ../win/bee2.def
      ../img/bee2.bmp
      ../win/bee2.rc
      ../win/bee2.c
    )
  endif()

  add_library(bee2 SHARED ${src})

  if(UNIX AND NOT APPLE)
    target_link_libraries(bee2 ${CMAKE_DL_LIBS})
  else()
    target_link_libraries(bee2)
  endif()

  set_target_properties(bee2 PROPERTIES VERSION ${BEE2_VERSION} SOVERSION 2.0)

  install(TARGETS bee2
    DESTINATION ${LIB_INSTALL_DIR}
    PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE 
      WORLD_READ WORLD_EXECUTE)
endif()
