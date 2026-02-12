/*
*******************************************************************************
\file ecp_bench.c
\brief Benchmarks for elliptic curves over prime fields
\project bee2/test
\created 2013.10.17
\version 2026.02.12
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <stdio.h>
#include <bee2/core/blob.h>
#include <bee2/core/prng.h>
#include <bee2/core/tm.h>
#include <bee2/core/util.h>
#include <bee2/math/ecp.h>
#include <crypto/bign/bign_lcl.h>

/*
*******************************************************************************
Оценка производительности на заданной кривой
*******************************************************************************
*/

static bool_t ecpBenchEc(const ec_o* ec)
{
	const size_t n = ec->f->n;
	const size_t no = ec->f->no;
	const size_t min_w = 3;
	const size_t max_w = 6;
	const size_t min_h = (B_OF_O(no) + max_w - 1) / max_w;
	const size_t max_h = (B_OF_O(no) + min_w - 1) / min_w;
	const size_t max_pre_count = SIZE_BIT_POS(max_w - 1) * min_h;
	const size_t reps = 200;
	void* state;
	octet* combo_state;		/* [prngCOMBO_keep()] */
	word* pt;				/* [2 * n] */
	word* d;				/* [n] */
	ec_pre_t* pre;			/* [SIZE_BIT_POS(max_w - 1) якобиевы точки] */
	void* stack;
	// создать состояние
	state = blobCreate2(
		prngCOMBO_keep(),
		O_OF_W(2 * n),
		O_OF_W(n),
		sizeof(ec_pre_t) + O_OF_W(max_pre_count * ec->d * n),
		utilMax(11,
			ecMulA_deep(n, ec->d, ec->deep, n),
			ecPreSNZ_deep(n, ec->d, ec->deep),
			ecPreSNZA_deep(n, ec->d, ec->deep),
			ecPreSNZH_deep(n, ec->d, ec->deep),
			ecPreHPB_deep(n, ec->d, ec->deep, max_h),
			ecpPreSNZ_deep(n, ec->f->deep, max_w),
			ecpPreSNZA_deep(n, ec->f->deep, max_w),
			ecMulPreSNZ_deep(n, ec->d, ec->deep, n),
			ecMulPreSNZA_deep(n, ec->d, ec->deep, n),
			ecMulPreSNZH_deep(n, ec->d, ec->deep, n),
			ecMulPreHPB_deep(n, ec->d, ec->deep, n)),
		SIZE_MAX,
		&combo_state, &pt, &d, &pre, &stack);
	if (state == 0)
		return FALSE;
	// создать генератор COMBO
	prngCOMBOStart(combo_state, utilNonce32());
	// оценить число кратных точек в секунду
	printf("ecpBench::\n");
	{
		size_t w;
		size_t i;
		tm_ticks_t ticks;
		// ecMulA
		{
			for (i = 0, ticks = tmTicks(); i < reps; ++i)
			{
				prngCOMBOStepR(d, no, combo_state);
				ecMulA(pt, ec->base, ec, d, n, stack);
			}
			ticks = tmTicks() - ticks;
			printf("  ecMulA:                    %u cycles/pt [%u pts/sec]\n",
				(unsigned)(ticks / reps),
				(unsigned)tmSpeed(reps, ticks));
		}
		// ecpPre+ecMulPre[SNZ]
		for (w = min_w; w <= max_w; ++w)
		{
			for (i = 0, ticks = tmTicks(); i < reps; ++i)
			{
				prngCOMBOStepR(d, no, combo_state);
				ecpPreSNZ(pre, ec->base, w, ec, stack);
				ecMulPreSNZ(pt, pre, ec, d, n, stack);
			}
			ticks = tmTicks() - ticks;
			printf("  ecpPre+ecMulPre[SNZ,w=%u]:  %u cycles/pt [%u pts/sec]\n",
				(unsigned)w,
				(unsigned)(ticks / reps),
				(unsigned)tmSpeed(reps, ticks));
		}
		// ecpPre+ecMulPre[SNZA]
		for (w = min_w; w <= max_w; ++w)
		{
			for (i = 0, ticks = tmTicks(); i < reps; ++i)
			{
				prngCOMBOStepR(d, no, combo_state);
				ecpPreSNZA(pre, ec->base, w, ec, stack);
				ecMulPreSNZA(pt, pre, ec, d, n, stack);
			}
			ticks = tmTicks() - ticks;
			printf("  ecpPre+ecMulPre[SNZA,w=%u]: %u cycles/pt [%u pts/sec]\n",
				(unsigned)w,
				(unsigned)(ticks / reps),
				(unsigned)tmSpeed(reps, ticks));
		}
		// ecMulPre[SNZ]
		for (w = min_w; w <= max_w; ++w)
		{
			ecPreSNZ(pre, ec->base, w, ec, stack);
			for (i = 0, ticks = tmTicks(); i < reps; ++i)
			{
				prngCOMBOStepR(d, no, combo_state);
				ecMulPreSNZ(pt, pre, ec, d, n, stack);
			}
			ticks = tmTicks() - ticks;
			printf("  ecMulPre[SNZ,w=%u]:         %u cycles/pt [%u pts/sec]\n",
				(unsigned)w,
				(unsigned)(ticks / reps),
				(unsigned)tmSpeed(reps, ticks));
		}
		// ecMulPre[SNZA]
		for (w = min_w; w <= max_w; ++w)
		{
			ecPreSNZA(pre, ec->base, w, ec, stack);
			for (i = 0, ticks = tmTicks(); i < reps; ++i)
			{
				prngCOMBOStepR(d, no, combo_state);
				ecMulPreSNZA(pt, pre, ec, d, n, stack);
			}
			ticks = tmTicks() - ticks;
			printf("  ecMulPre[SNZA,w=%u]:        %u cycles/pt [%u pts/sec]\n",
				(unsigned)w,
				(unsigned)(ticks / reps),
				(unsigned)tmSpeed(reps, ticks));
		}
		// ecMulPre[SNZH]
		for (w = min_w; w <= max_w; ++w)
		{
			size_t h = (B_OF_O(no) + w - 1) / w;
			ecPreSNZH(pre, ec->base, w, h, ec, stack);
			for (i = 0, ticks = tmTicks(); i < reps; ++i)
			{
				prngCOMBOStepR(d, no, combo_state);
				ecMulPreSNZH(pt, pre, ec, d, n, stack);
			}
			ticks = tmTicks() - ticks;
			printf("  ecMulPre[SNZH,w=%u]:        %u cycles/pt [%u pts/sec]\n",
				(unsigned)w,
				(unsigned)(ticks / reps),
				(unsigned)tmSpeed(reps, ticks));
		}
		// ecMulPre[HPB]
		for (w = min_w; w <= max_w; ++w)
		{
			size_t h = (B_OF_O(no) + w - 1) / w;
			ecPreHPB(pre, ec->base, w, h, ec, stack);
			for (i = 0, ticks = tmTicks(); i < reps; ++i)
			{
				prngCOMBOStepR(d, no, combo_state);
				ecMulPreHPB(pt, pre, ec, d, n, stack);
			}
			ticks = tmTicks() - ticks;
			printf("  ecMulPre[HPB,w=%u]:         %u cycles/pt [%u pts/sec]\n",
				(unsigned)w,
				(unsigned)(ticks / reps),
				(unsigned)tmSpeed(reps, ticks));
		}
		// ecPre[SNZ]
		for (w = min_w; w <= max_w; ++w)
		{
			for (i = 0, ticks = tmTicks(); i < reps; ++i)
				ecPreSNZ(pre, ec->base, w, ec, stack);
			ticks = tmTicks() - ticks;
			printf("  ecPre[SNZ,w=%u]:            %u cycles/pre [%u pre/sec]\n",
				(unsigned)w,
				(unsigned)(ticks / reps),
				(unsigned)tmSpeed(reps, ticks));
		}
		// ecpPre[SNZ]
		for (w = min_w; w <= max_w; ++w)
		{
			for (i = 0, ticks = tmTicks(); i < reps; ++i)
				ecpPreSNZ(pre, ec->base, w, ec, stack);
			ticks = tmTicks() - ticks;
			printf("  ecpPre[SNZ,w=%u]:           %u cycles/pre [%u pre/sec]\n",
				(unsigned)w,
				(unsigned)(ticks / reps),
				(unsigned)tmSpeed(reps, ticks));
		}
	}
	// завершение
	blobClose(state);
	return TRUE;
}

/*
*******************************************************************************
Оценка производительности на кривой bign-curve256v1
*******************************************************************************
*/

bool_t ecpBench()
{
	bool_t ret;
	bign_params params[1];
	ec_o* ec;
	// создать кривую
	if (bignParamsStd(params, "1.2.112.0.2.0.34.101.45.3.2") != ERR_OK ||
		bignEcCreate(&ec, params) != ERR_OK)
		return FALSE;
	// оценка
	ret = ecpBenchEc(ec);
	// завершение
	bignEcClose(ec);
	return ret;
}
