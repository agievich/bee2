/*
*******************************************************************************
\file ecp_bench.c
\brief Benchmarks for elliptic curves over prime fields
\project bee2/test
\created 2013.10.17
\version 2020.02.05
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <stdio.h>
#include <bee2/core/mem.h>
#include <bee2/core/prng.h>
#include <bee2/core/stack.h>
#include <bee2/core/tm.h>
#include <bee2/core/util.h>
#include <crypto/bign_lcl.h>
#include <bee2/math/ecp.h>
#include <bee2/math/gfp.h>

/*
*******************************************************************************
Потребности в стеке
*******************************************************************************
*/

static size_t _ecpBench_deep(size_t n, size_t f_deep, size_t ec_d, 
	size_t ec_deep)
{
	return O_OF_W(3 * n) + prngCOMBO_keep() +
		ecMulA_deep(n, ec_d, ec_deep, n);
}

bool_t ecpBench()
{
	// описание кривой
	bign_params params[1];
	// состояние
	octet state[6000];
	ec_o* ec;
	octet* combo_state;
	word* pt;
	word* d;
	void* stack;
	// загрузить параметры и создать описание кривой
	ASSERT(bignStart_keep(128, _ecpBench_deep) <= sizeof(state));
	if (bignStdParams(params, "1.2.112.0.2.0.34.101.45.3.1") != ERR_OK ||
		bignStart(state, params) != ERR_OK)
		return FALSE;
	// раскладка состояния
	ec = (ec_o*)state;
	ec->tpl = 0;
	combo_state = objEnd(ec, octet);
	pt = (word*)(combo_state + prngCOMBO_keep());
	d = pt + 2 * ec->f->n;
	stack = d + ec->f->n;
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
	// все нормально
	return TRUE;
}
