/*
*******************************************************************************
\file ecp_bench.c
\brief Benchmarks for elliptic curves over prime fields
\project bee2/test
\created 2013.10.17
\version 2026.01.29
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <stdio.h>
#include <bee2/core/blob.h>
#include <bee2/core/prng.h>
#include <bee2/core/tm.h>
#include <bee2/core/util.h>
#include <bee2/math/ec.h>
#include <crypto/bign/bign_lcl.h>

/*
*******************************************************************************
Потребности в стеке
*******************************************************************************
*/

bool_t ecpBench()
{
	bign_params params[1];
	ec_o* ec;
	void* state;
	octet* combo_state;		/* [prngCOMBO_keep()] */
	word* pt;				/* [2 * n] */
	word* d;				/* [n] */
	ec_pre_t* pre;			/* [64 якобиевы точки] */
	void* stack;
	// загрузить параметры
	if (bignParamsStd(params, "1.2.112.0.2.0.34.101.45.3.1") != ERR_OK ||
		bignEcCreate(&ec, params) != ERR_OK)
		return FALSE;
	// заблокировать утроение точек
	ec->tpl = 0;
	// создать состояние
	state = blobCreate2(
		prngCOMBO_keep(),
		O_OF_W(2 * ec->f->n),
		O_OF_W(ec->f->n),
		sizeof(ec_pre_t) + O_OF_W(64 * 3 * ec->f->n),
		utilMax(5,
			ecMulA_deep(ec->f->n, ec->d, ec->deep, ec->f->n),
			ecPreSNZ_deep(ec->f->n, ec->d, ec->deep),
			ecMulPreSNZ_deep(ec->f->n, ec->d, ec->deep, ec->f->n),
			ecPreSNZA_deep(ec->f->n, ec->d, ec->deep),
			ecMulPreSNZA_deep(ec->f->n, ec->d, ec->deep, ec->f->n)),
		SIZE_MAX,
		&combo_state, &pt, &d, &pre, &stack);
	if (state == 0)
	{
		bignEcClose(ec);
		return FALSE;
	}
	// создать генератор COMBO
	prngCOMBOStart(combo_state, utilNonce32());
	// оценить число кратных точек в секунду
	printf("ecpBench::\n");
	{
		const size_t reps = 200;
		size_t w;
		size_t i;
		tm_ticks_t ticks;
		// ecMulA
		{
			for (i = 0, ticks = tmTicks(); i < reps; ++i)
			{
				prngCOMBOStepR(d, ec->f->no, combo_state);
				ecMulA(pt, ec->base, ec, d, ec->f->n, stack);
			}
			ticks = tmTicks() - ticks;
			printf("  ecMulA:                   %u cycles/pt [%u pts/sec]\n",
				(unsigned)(ticks / reps),
				(unsigned)tmSpeed(reps, ticks));
		}
		// ecPre+MulPre[SNZ]
		for (w = 3; w <= 6; ++w)
		{
			for (i = 0, ticks = tmTicks(); i < reps; ++i)
			{
				prngCOMBOStepR(d, ec->f->no, combo_state);
				ecPreSNZ(pre, ec->base, w, ec, stack);
				ecMulPreSNZ(pt, pre, ec, d, ec->f->n, stack);
			}
			ticks = tmTicks() - ticks;
			printf("  ecPre+ecMulPre[SNZ,w=%u]:  %u cycles/pt [%u pts/sec]\n",
				(unsigned)w,
				(unsigned)(ticks / reps),
				(unsigned)tmSpeed(reps, ticks));
		}
		// ecPre+MulPre[SNZA]
		for (w = 4; w <= 6; ++w)
		{
			for (i = 0, ticks = tmTicks(); i < reps; ++i)
			{
				prngCOMBOStepR(d, ec->f->no, combo_state);
				ecPreSNZA(pre, ec->base, w, ec, stack);
				ecMulPreSNZA(pt, pre, ec, d, ec->f->n, stack);
			}
			ticks = tmTicks() - ticks;
			printf("  ecPre+ecMulPre[SNZA,w=%u]: %u cycles/pt [%u pts/sec]\n",
				(unsigned)w,
				(unsigned)(ticks / reps),
				(unsigned)tmSpeed(reps, ticks));
		}
		// ecMulPre[SNZ]
		for (w = 3; w <= 6; ++w)
		{
			ecPreSNZ(pre, ec->base, w, ec, stack);
			for (i = 0, ticks = tmTicks(); i < reps; ++i)
			{
				prngCOMBOStepR(d, ec->f->no, combo_state);
				ecMulPreSNZ(pt, pre, ec, d, ec->f->n, stack);
			}
			ticks = tmTicks() - ticks;
			printf("  ecMulPre[SNZ,w=%u]:        %u cycles/pt [%u pts/sec]\n",
				(unsigned)w,
				(unsigned)(ticks / reps),
				(unsigned)tmSpeed(reps, ticks));
		}
		// ecMulPre[SNZA]
		for (w = 3; w <= 6; ++w)
		{
			ecPreSNZA(pre, ec->base, w, ec, stack);
			for (i = 0, ticks = tmTicks(); i < reps; ++i)
			{
				prngCOMBOStepR(d, ec->f->no, combo_state);
				ecMulPreSNZA(pt, pre, ec, d, ec->f->n, stack);
			}
			ticks = tmTicks() - ticks;
			printf("  ecMulPre[SNZA,w=%u]:       %u cycles/pt [%u pts/sec]\n",
				(unsigned)w,
				(unsigned)(ticks / reps),
				(unsigned)tmSpeed(reps, ticks));
		}
	}
	// завершение
	blobClose(state);
	bignEcClose(ec);
	return TRUE;
}
