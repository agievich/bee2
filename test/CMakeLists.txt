add_executable(testbee2
	core/b64_test.c
	core/dec_test.c
	core/mem_test.c
	core/hex_test.c
	core/obj_test.c
	core/oid_test.c
	core/prng_test.c
	core/rng_test.c
	core/str_test.c
	core/tm_test.c
	core/u16_test.c
	core/u32_test.c
	core/u64_test.c
	core/util_test.c
	crypto/bake_test.c
	crypto/bash_bench.c
	crypto/bash_test.c
	crypto/bels_test.c
	crypto/belt_bench.c
	crypto/belt_test.c
	crypto/bign_test.c
	crypto/brng_test.c
	crypto/botp_test.c
	crypto/dstu_test.c
	crypto/g12s_test.c
	crypto/pfok_test.c
	crypto/pkcs5_test.c
	math/pri_test.c
	math/zz_test.c
	math/word_test.c
	math/ecp_test.c
	math/ecp_bench.c
	test.c
)
target_link_libraries(testbee2 bee2_static)

add_test(testbee2 testbee2)