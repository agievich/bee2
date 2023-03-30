/*
*******************************************************************************
\file bash_bench.c
\brief Benchmarks for STB 34.101.77 (bash)
\project bee2/test
\created 2014.07.15
\version 2023.03.30
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
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

extern const char bash_platform[];

bool_t bashBench()
{
	octet belt_state[256];
	octet bash_state[1024];
	octet combo_state[256];
	octet buf[1024];
	octet hash[64];
	size_t l, d;
	// подготовить память
	if (sizeof(belt_state) < beltHash_keep() ||
		sizeof(bash_state) < bashPrg_keep() ||
		sizeof(bash_state) < bashHash_keep() ||
		sizeof(combo_state) < prngCOMBO_keep())
		return FALSE;
	// заполнить buf псевдослучайными числами
	prngCOMBOStart(combo_state, utilNonce32());
	prngCOMBOStepR(buf, sizeof(buf), combo_state);
	// платформа
	printf("bashBench::platform = %s\n", bash_platform);
	// оценить скорость хэширования
	{
		const size_t reps = 2000;
		size_t i;
		tm_ticks_t ticks;
		// эксперимент c belt
		beltHashStart(belt_state);
		for (i = 0, ticks = tmTicks(); i < reps; ++i)
			beltHashStepH(buf, sizeof(buf), belt_state);
		beltHashStepG(hash, belt_state);
		ticks = tmTicks() - ticks;
		printf("bashBench::belt-hash: %3u cpb [%5u kBytes/sec]\n",
			(unsigned)(ticks / 1024 / reps),
			(unsigned)tmSpeed(reps, ticks));
		// эксперимент c bashHashLLL
		for (l = 128; l <= 256; l += 64)
		{
			bashHashStart(bash_state, l);
			for (i = 0, ticks = tmTicks(); i < reps; ++i)
				bashHashStepH(buf, sizeof(buf), bash_state);
			bashHashStepG(hash, l / 4, bash_state);
			ticks = tmTicks() - ticks;
			printf("bashBench::bash%u: %3u cpb [%5u kBytes/sec]\n",
				(unsigned)(2 * l),
				(unsigned)(ticks / sizeof(buf) / reps),
				(unsigned)tmSpeed(reps, ticks));
		}
		// эксперимент с bash-prg-hashLLLD
		for (l = 128; l <= 256; l += 64)
		for (d = 1; d <= 2; ++d)
		{
			bashPrgStart(bash_state, l, d, hash, l / 8, 0, 0);
			bashPrgAbsorbStart(bash_state);
			for (i = 0, ticks = tmTicks(); i < reps; ++i)
				bashPrgAbsorbStep(buf, 1024, bash_state);
			bashPrgSqueeze(hash, l / 4, bash_state);
			ticks = tmTicks() - ticks;
			printf("bashBench::bash-prg-hash%u%u: %3u cpb [%5u kBytes/sec]\n",
				(unsigned)(2 * l), (unsigned)d,
				(unsigned)(ticks / sizeof(buf) / reps),
				(unsigned)tmSpeed(reps, ticks));
		}
		// эксперимент с bash-prg-aeLLLD
		for (l = 128; l <= 256; l += 64)
		for (d = 1; d <= 2; ++d)
		{
			bashPrgStart(bash_state, l, d, 0, 0, hash, l / 8);
			bashPrgEncrStart(bash_state);
			for (i = 0, ticks = tmTicks(); i < reps; ++i)
				bashPrgEncrStep(buf, 1024, bash_state);
			bashPrgDecrStart(bash_state);
			for (i = 0, ticks = tmTicks(); i < reps; ++i)
				bashPrgDecrStep(buf, 1024, bash_state);
			ticks = tmTicks() - ticks;
			printf("bashBench::bash-prg-ae%u%u: %3u cpb [%5u kBytes/sec]\n",
				(unsigned)l, (unsigned)d,
				(unsigned)(ticks / (2 * sizeof(buf)) / reps),
				(unsigned)tmSpeed(2 * reps, ticks));
		}
	}
	// все нормально
	return TRUE;
}
