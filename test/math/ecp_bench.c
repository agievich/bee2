/*
*******************************************************************************
\file ecp_bench.c
\brief Benchmarks for elliptic curves over prime fields
\project bee2/test
\created 2013.10.17
\version 2026.02.16
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
			ecPreSO_deep(n, ec->d, ec->deep),
			ecPreSOA_deep(n, ec->d, ec->deep),
			ecPreSOH_deep(n, ec->d, ec->deep),
			ecPreSI_deep(n, ec->d, ec->deep, max_h),
			ecpPreSO_deep(n, ec->f->deep, max_w),
			ecpPreSOA_deep(n, ec->f->deep, max_w),
			ecMulPreSO_deep(n, ec->d, ec->deep, n),
			ecMulPreSOA_deep(n, ec->d, ec->deep, n),
			ecMulPreSOH_deep(n, ec->d, ec->deep, n),
			ecMulPreSI_deep(n, ec->d, ec->deep, n)),
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
			printf("  ecMulA:                   %u cycles/pt [%u pts/sec]\n",
				(unsigned)(ticks / reps),
				(unsigned)tmSpeed(reps, ticks));
		}
		// ecpPre+ecMulPre[SO]
		for (w = MAX2(3, min_w); w <= max_w; ++w)
		{
			for (i = 0, ticks = tmTicks(); i < reps; ++i)
			{
				prngCOMBOStepR(d, no, combo_state);
				ecpPreSO(pre, ec->base, w, ec, stack);
				ecMulPreSO(pt, pre, ec, d, n, stack);
			}
			ticks = tmTicks() - ticks;
			printf("  ecpPre+ecMulPre[SO,w=%u]:  %u cycles/pt [%u pts/sec]\n",
				(unsigned)w,
				(unsigned)(ticks / reps),
				(unsigned)tmSpeed(reps, ticks));
		}
		// ecpPre+ecMulPre[SOA]
		for (w = MAX2(3, min_w); w <= max_w; ++w)
		{
			for (i = 0, ticks = tmTicks(); i < reps; ++i)
			{
				prngCOMBOStepR(d, no, combo_state);
				ecpPreSOA(pre, ec->base, w, ec, stack);
				ecMulPreSOA(pt, pre, ec, d, n, stack);
			}
			ticks = tmTicks() - ticks;
			printf("  ecpPre+ecMulPre[SOA,w=%u]: %u cycles/pt [%u pts/sec]\n",
				(unsigned)w,
				(unsigned)(ticks / reps),
				(unsigned)tmSpeed(reps, ticks));
		}
		// ecMulPre[SO]
		for (w = min_w; w <= max_w; ++w)
		{
			ecPreSO(pre, ec->base, w, ec, stack);
			for (i = 0, ticks = tmTicks(); i < reps; ++i)
			{
				prngCOMBOStepR(d, no, combo_state);
				ecMulPreSO(pt, pre, ec, d, n, stack);
			}
			ticks = tmTicks() - ticks;
			printf("  ecMulPre[SO,w=%u]:         %u cycles/pt [%u pts/sec]\n",
				(unsigned)w,
				(unsigned)(ticks / reps),
				(unsigned)tmSpeed(reps, ticks));
		}
		// ecMulPre[SOA]
		for (w = min_w; w <= max_w; ++w)
		{
			ecPreSOA(pre, ec->base, w, ec, stack);
			for (i = 0, ticks = tmTicks(); i < reps; ++i)
			{
				prngCOMBOStepR(d, no, combo_state);
				ecMulPreSOA(pt, pre, ec, d, n, stack);
			}
			ticks = tmTicks() - ticks;
			printf("  ecMulPre[SOA,w=%u]:        %u cycles/pt [%u pts/sec]\n",
				(unsigned)w,
				(unsigned)(ticks / reps),
				(unsigned)tmSpeed(reps, ticks));
		}
		// ecMulPre[SOH]
		for (w = min_w; w <= max_w; ++w)
		{
			size_t h = (B_OF_O(no) + w - 1) / w;
			ecPreSOH(pre, ec->base, w, h, ec, stack);
			for (i = 0, ticks = tmTicks(); i < reps; ++i)
			{
				prngCOMBOStepR(d, no, combo_state);
				ecMulPreSOH(pt, pre, ec, d, n, stack);
			}
			ticks = tmTicks() - ticks;
			printf("  ecMulPre[SOH,w=%u]:        %u cycles/pt [%u pts/sec]\n",
				(unsigned)w,
				(unsigned)(ticks / reps),
				(unsigned)tmSpeed(reps, ticks));
		}
		// ecMulPre[SI]
		for (w = min_w; w <= max_w; ++w)
		{
			size_t h = (B_OF_O(no) + w - 1) / w;
			ecPreSI(pre, ec->base, w, h, ec, stack);
			for (i = 0, ticks = tmTicks(); i < reps; ++i)
			{
				prngCOMBOStepR(d, no, combo_state);
				ecMulPreSI(pt, pre, ec, d, n, stack);
			}
			ticks = tmTicks() - ticks;
			printf("  ecMulPre[SI,w=%u]:         %u cycles/pt [%u pts/sec]\n",
				(unsigned)w,
				(unsigned)(ticks / reps),
				(unsigned)tmSpeed(reps, ticks));
		}
		// ecPre[SO]
		for (w = min_w; w <= max_w; ++w)
		{
			for (i = 0, ticks = tmTicks(); i < reps; ++i)
				ecPreSO(pre, ec->base, w, ec, stack);
			ticks = tmTicks() - ticks;
			printf("  ecPre[SO,w=%u]:            %u cycles/pre [%u pre/sec]\n",
				(unsigned)w,
				(unsigned)(ticks / reps),
				(unsigned)tmSpeed(reps, ticks));
		}
		// ecpPre[SO]
		for (w = MAX2(3, min_w); w <= max_w; ++w)
		{
			for (i = 0, ticks = tmTicks(); i < reps; ++i)
				ecpPreSO(pre, ec->base, w, ec, stack);
			ticks = tmTicks() - ticks;
			printf("  ecpPre[SO,w=%u]:           %u cycles/pre [%u pre/sec]\n",
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
	if (bignParamsStd(params, "1.2.112.0.2.0.34.101.45.3.1") != ERR_OK ||
		bignEcCreate(&ec, params) != ERR_OK)
		return FALSE;
	// оценка
	ret = ecpBenchEc(ec);
	// завершение
	bignEcClose(ec);
	return ret;
}
