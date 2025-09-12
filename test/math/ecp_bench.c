/*
*******************************************************************************
\file ecp_bench.c
\brief Benchmarks for elliptic curves over prime fields
\project bee2/test
\created 2013.10.17
\version 2025.09.08
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
	octet* combo_state;
	word* pt;
	word* d;
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
		ecMulA_deep(ec->f->n, ec->d, ec->deep, ec->f->n),
		SIZE_MAX,
		&combo_state, &pt, &d, &stack);
	if (state == 0)
		return FALSE;
	// создать генератор COMBO
	prngCOMBOStart(combo_state, utilNonce32());
	// оценить число кратных точек в секунду
	{
		const size_t reps = 1000;
		size_t i;
		tm_ticks_t ticks;
		// эксперимент
		for (i = 0, ticks = tmTicks(); i < reps; ++i)
		{
			prngCOMBOStepR(d, ec->f->no, combo_state);
			ecMulA(pt, ec->base, ec, d, ec->f->n, stack);
		}
		ticks = tmTicks() - ticks;
		// печать результатов
		printf("ecpBench: %u cycles/mulpoint [%u mulpoints/sec]\n",  
			(unsigned)(ticks / reps),
			(unsigned)tmSpeed(reps, ticks));
	}
	// завершение
	bignEcClose(ec);
	return TRUE;
}
