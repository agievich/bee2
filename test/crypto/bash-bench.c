/*
*******************************************************************************
\file bash-bench.c
\brief Benchmarks for STB 34.101.77 (bash)
\project bee2/test
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2014.07.15
\version 2018.11.01
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include <stdio.h>
#include <bee2/core/prng.h>
#include <bee2/core/tm.h>
#include <bee2/core/util.h>
#include <bee2/crypto/bash.h>
#include <bee2/crypto/belt.h>
#include <bee2/math/pp.h>
#include <bee2/math/ww.h>

/*
*******************************************************************************
Замер производительности
*******************************************************************************
*/

bool_t bashBench()
{
	octet belt_state[256];
	octet bash_state[1024];
	octet combo_state[256];
	octet buf[1024];
	octet hash[64];
	// заполнить buf псевдослучайными числами
	ASSERT(prngCOMBO_keep() <= sizeof(combo_state));
	prngCOMBOStart(combo_state, utilNonce32());
	prngCOMBOStepR(buf, sizeof(buf), combo_state);
	// оценить скорость хэширования
	{
		const size_t reps = 2000;
		size_t i;
		tm_ticks_t ticks;
		// эксперимент c belt
		ASSERT(beltHash_keep() <= sizeof(belt_state));
		beltHashStart(belt_state);
		for (i = 0, ticks = tmTicks(); i < reps; ++i)
			beltHashStepH(buf, sizeof(buf), belt_state);
		beltHashStepG(hash, belt_state);
		ticks = tmTicks() - ticks;
		printf("bashBench::belt-hash: %3u cycles / byte [%5u kBytes / sec]\n",
			(unsigned)(ticks / 1024 / reps),
			(unsigned)tmSpeed(reps, ticks));
		// эксперимент c bash256
		ASSERT(bash256_keep() <= sizeof(bash_state));
		bash256Start(bash_state);
		for (i = 0, ticks = tmTicks(); i < reps; ++i)
			bash256StepH(buf, sizeof(buf), bash_state);
		bash256StepG(hash, bash_state);
		ticks = tmTicks() - ticks;
		printf("bashBench::bash256:   %3u cycles / byte [%5u kBytes / sec]\n",
			(unsigned)(ticks / 1024 / reps),
			(unsigned)tmSpeed(reps, ticks));
		// эксперимент c bash384
		ASSERT(bash384_keep() <= sizeof(bash_state));
		bash384Start(bash_state);
		for (i = 0, ticks = tmTicks(); i < reps; ++i)
			bash384StepH(buf, sizeof(buf), bash_state);
		bash384StepG(hash, bash_state);
		ticks = tmTicks() - ticks;
		printf("bashBench::bash384:   %3u cycles / byte [%5u kBytes / sec]\n",
			(unsigned)(ticks / 1024 / reps),
			(unsigned)tmSpeed(reps, ticks));
		// эксперимент c bash512
		ASSERT(bash512_keep() <= sizeof(bash_state));
		bash512Start(bash_state);
		for (i = 0, ticks = tmTicks(); i < reps; ++i)
			bash512StepH(buf, sizeof(buf), bash_state);
		bash512StepG(hash, bash_state);
		ticks = tmTicks() - ticks;
		printf("bashBench::bash512:   %3u cycles / byte [%5u kBytes / sec]\n",
			(unsigned)(ticks / 1024 / reps),
			(unsigned)tmSpeed(reps, ticks));
		// cкорость bash-ae128
		ASSERT(bashAE_keep() <= sizeof(bash_state));
		bashAEStart(bash_state, hash, 16, 0, 0);
		bashAEEncrStart(bash_state);
		for (i = 0, ticks = tmTicks(); i < reps; ++i)
			bashAEEncrStep(buf, 1024, bash_state);
		bashAEEncrStop(bash_state);
		bashAEDecrStart(bash_state);
		for (i = 0, ticks = tmTicks(); i < reps; ++i)
			bashAEDecrStep(buf, 1024, bash_state);
		bashAEDecrStop(bash_state);
		ticks = tmTicks() - ticks;
		printf("bashBench::bash-ae128:  %3u cycles / byte [%5u kBytes / sec]\n",
			(unsigned)(ticks / 2048 / reps),
			(unsigned)tmSpeed(2 * reps, ticks));
		// cкорость bash-ae192
		ASSERT(bashAE_keep() <= sizeof(bash_state));
		bashAEStart(bash_state, hash, 24, 0, 0);
		bashAEEncrStart(bash_state);
		for (i = 0, ticks = tmTicks(); i < reps; ++i)
			bashAEEncrStep(buf, 1024, bash_state);
		bashAEEncrStop(bash_state);
		bashAEDecrStart(bash_state);
		for (i = 0, ticks = tmTicks(); i < reps; ++i)
			bashAEDecrStep(buf, 1024, bash_state);
		bashAEDecrStop(bash_state);
		ticks = tmTicks() - ticks;
		printf("bashBench::bash-ae192:  %3u cycles / byte [%5u kBytes / sec]\n",
			(unsigned)(ticks / 2048 / reps),
			(unsigned)tmSpeed(2 * reps, ticks));
		// cкорость bash-ae256
		ASSERT(bashAE_keep() <= sizeof(bash_state));
		bashAEStart(bash_state, hash, 32, 0, 0);
		bashAEEncrStart(bash_state);
		for (i = 0, ticks = tmTicks(); i < reps; ++i)
			bashAEEncrStep(buf, 1024, bash_state);
		bashAEEncrStop(bash_state);
		bashAEDecrStart(bash_state);
		for (i = 0, ticks = tmTicks(); i < reps; ++i)
			bashAEDecrStep(buf, 1024, bash_state);
		bashAEDecrStop(bash_state);
		ticks = tmTicks() - ticks;
		printf("bashBench::bash-ae192:  %3u cycles / byte [%5u kBytes / sec]\n",
			(unsigned)(ticks / 2048 / reps),
			(unsigned)tmSpeed(2 * reps, ticks));
	}
	// все нормально
	return TRUE;
}
