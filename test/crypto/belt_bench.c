/*
*******************************************************************************
\file belt_bench.c
\brief Benchmarks for STB 34.101.31 (belt)
\project bee2/test
\created 2014.11.18
\version 2020.06.23
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include <stdio.h>
#include <bee2/core/prng.h>
#include <bee2/core/tm.h>
#include <bee2/core/util.h>
#include <bee2/crypto/belt.h>
#include <bee2/math/pp.h>
#include <bee2/math/ww.h>

/*
*******************************************************************************
Замер производительности
*******************************************************************************
*/

bool_t beltBench()
{
	const size_t reps = 5000;
	octet belt_state[512];
	octet combo_state[256];
	octet buf[1024];
	octet key[32];
	octet iv[16];
	octet hash[32];
	size_t i;
	tm_ticks_t ticks;
	// псевдослучайная генерация объектов
	ASSERT(prngCOMBO_keep() <= sizeof(combo_state));
	prngCOMBOStart(combo_state, utilNonce32());
	prngCOMBOStepR(buf, sizeof(buf), combo_state);
	prngCOMBOStepR(key, sizeof(key), combo_state);
	prngCOMBOStepR(iv, sizeof(iv), combo_state);
	// cкорость belt-ecb
	ASSERT(beltECB_keep() <= sizeof(belt_state));
	beltECBStart(belt_state, key, 32);
	for (i = 0, ticks = tmTicks(); i < reps; ++i)
		beltECBStepE(buf, 1024, belt_state),
		beltECBStepD(buf, 1024, belt_state);
	ticks = tmTicks() - ticks;
	printf("beltBench::belt-ecb:  %3u cpb [%5u kBytes/sec]\n",
		(unsigned)(ticks / 2048 / reps),
		(unsigned)tmSpeed(2 * reps, ticks));
	// cкорость belt-cbc
	ASSERT(beltCFB_keep() <= sizeof(belt_state));
	beltCBCStart(belt_state, key, 32, iv);
	for (i = 0, ticks = tmTicks(); i < reps; ++i)
		beltCBCStepE(buf, 1024, belt_state),
		beltCBCStepD(buf, 1024, belt_state);
	ticks = tmTicks() - ticks;
	printf("beltBench::belt-cbc:  %3u cpb [%5u kBytes/sec]\n",
		(unsigned)(ticks / 2048 / reps),
		(unsigned)tmSpeed(2 * reps, ticks));
	// cкорость belt-cfb
	ASSERT(beltCFB_keep() <= sizeof(belt_state));
	beltCFBStart(belt_state, key, 32, iv);
	for (i = 0, ticks = tmTicks(); i < reps; ++i)
		beltCFBStepE(buf, 1024, belt_state),
		beltCFBStepD(buf, 1024, belt_state);
	ticks = tmTicks() - ticks;
	printf("beltBench::belt-cfb:  %3u cpb [%5u kBytes/sec]\n",
		(unsigned)(ticks / 2048 / reps),
		(unsigned)tmSpeed(2 * reps, ticks));
	// cкорость belt-ctr
	ASSERT(beltCTR_keep() <= sizeof(belt_state));
	beltCTRStart(belt_state, key, 32, iv);
	for (i = 0, ticks = tmTicks(); i < reps; ++i)
		beltCTRStepE(buf, 1024, belt_state),
		beltCTRStepD(buf, 1024, belt_state);
	ticks = tmTicks() - ticks;
	printf("beltBench::belt-ctr:  %3u cpb [%5u kBytes/sec]\n",
		(unsigned)(ticks / 2048 / reps),
		(unsigned)tmSpeed(2 * reps, ticks));
	// cкорость belt-mac
	ASSERT(beltMAC_keep() <= sizeof(belt_state));
	beltMACStart(belt_state, key, 32);
	for (i = 0, ticks = tmTicks(); i < reps; ++i)
		beltMACStepA(buf, 1024, belt_state);
	beltMACStepG(hash, belt_state);
	ticks = tmTicks() - ticks;
	printf("beltBench::belt-mac:  %3u cpb [%5u kBytes/sec]\n",
		(unsigned)(ticks / 1024 / reps),
		(unsigned)tmSpeed(reps, ticks));
	// cкорость belt-dwp
	ASSERT(beltDWP_keep() <= sizeof(belt_state));
	beltDWPStart(belt_state, key, 32, iv);
	for (i = 0, ticks = tmTicks(); i < reps; ++i)
		beltDWPStepE(buf, 1024, belt_state),
		beltDWPStepA(buf, 1024, belt_state);
	beltDWPStepG(hash, belt_state);
	ticks = tmTicks() - ticks;
	printf("beltBench::belt-dwp:  %3u cpb [%5u kBytes/sec]\n",
		(unsigned)(ticks / 1024 / reps),
		(unsigned)tmSpeed(reps, ticks));
	// cкорость belt-hash
	ASSERT(beltHash_keep() <= sizeof(belt_state));
	beltHashStart(belt_state);
	for (i = 0, ticks = tmTicks(); i < reps; ++i)
		beltHashStepH(buf, 1024, belt_state);
	beltHashStepG(hash, belt_state);
	ticks = tmTicks() - ticks;
	printf("beltBench::belt-hash: %3u cpb [%5u kBytes/sec]\n",
		(unsigned)(ticks / 1024 / reps),
		(unsigned)tmSpeed(reps, ticks));
	// все нормально
	return TRUE;
}
