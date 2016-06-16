add_executable(testbee2
	core/b64-test.c
	core/dec-test.c
	core/mem-test.c
	core/obj-test.c
	core/oid-test.c
	core/prng-test.c
	core/rng-test.c
	core/tm-test.c
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
	math/ecp-bench.c
	math/pri-test.c
	math/zz-test.c
	math/word-test.c
	test.c
)
target_link_libraries(testbee2 bee2_static)

add_test(testbee2 testbee2)