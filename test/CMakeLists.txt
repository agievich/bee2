add_executable(testbee2
	core/b64-test.c
	core/dec-test.c
	core/mem-test.c
	core/hex-test.c
	core/obj-test.c
	core/oid-test.c
	core/prng-test.c
	core/rng-test.c
	core/str-test.c
	core/tm-test.c
	core/u16-test.c
	core/u32-test.c
	core/u64-test.c
	core/util-test.c
	crypto/bake-test.c
	crypto/bash-bench.c
	crypto/bash-test.c
	crypto/bels-test.c
	crypto/belt-bench.c
	crypto/belt-test.c
	crypto/bign-test.c
	crypto/brng-test.c
	crypto/botp-test.c
	crypto/dstu-test.c
	crypto/g12s-test.c
	crypto/pfok-test.c
	math/pri-test.c
	math/zz-test.c
	math/word-test.c
	math/ecp-test.c
	math/ecp-bench.c
	test.c
)
target_link_libraries(testbee2 bee2_static)

add_test(testbee2 testbee2)