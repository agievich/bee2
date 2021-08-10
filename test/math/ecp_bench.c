/*
*******************************************************************************
\file ecp_bench.c
\brief Benchmarks for elliptic curves over prime fields
\project bee2/test
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\author (C) Vlad Semenov [semenov.vlad.by@gmail.com]
\created 2013.10.17
\version 2020.12.20
\license This program is released under the GNU General Public License
version 3. See Copyright Notices in bee2/info.h.
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

extern size_t testReps;
extern size_t ecW;
extern bool_t ecPrecompA;
bool_t ecpBench()
{
	// описание кривой
	bign_params params[1];
	// состояние
	octet state[40*6000];
	ec_o* ec;
	octet* combo_state;
	word* pt, *pta;
	word* d;
	size_t nj, reps;
	void* stack;
	char params_oid[] = "1.2.112.0.2.0.34.101.45.3.0";
	// загрузить параметры и создать описание кривой
	ASSERT(bignStart_keep(256, _ecpBench_deep) <= sizeof(state));
	for(; ++params_oid[sizeof(params_oid)-2] < '4';) {
		if (bignStdParams(params, params_oid) != ERR_OK ||
			bignStart(state, params) != ERR_OK)
			return FALSE;
		printf("ecpBench: %s\n", params_oid);
		// раскладка состояния
		ec = (ec_o*)state;
		ec->tpl = 0;
		nj = ec->d * ec->f->n;
		combo_state = objEnd(ec, octet);
		pt = (word*)(combo_state + prngCOMBO_keep());
		d = pt + 2 * ec->f->n;
		stack = d + ec->f->n;
		reps = testReps*1024*1024 / params->l / params->l;
		// оценить число кратных точек в секунду
		pta = ec->base;
		for(;;)
		{
			size_t i;
			tm_ticks_t ticks;
			// создать генератор COMBO
			prngCOMBOStart(combo_state, utilNonce32());
			// эксперимент
			for (i = 0, ticks = tmTicks(); i < reps; ++i)
			{
				prngCOMBOStepR(d, ec->f->no, combo_state);
				ecMulA(pt, pta, ec, d, ec->f->n, stack);
			}
			ticks = tmTicks() - ticks;
			// печать результатов
			printf("ecpBench::%s: %u cycles / mulpoint [%u mulpoints / sec]\n",
				pta == ec->base ? "base": "rand",
				(unsigned)(ticks / reps),
				(unsigned)tmSpeed(reps, ticks));
			if(pta == pt) break;
			pta = pt;
		}
		// скорость предвычислений
		{
			word *c = (word*)stack;
			void *stack2 = (word*)(c + (nj << ecW) + nj+nj);
			size_t i;
			tm_ticks_t ticks;
			// эксперимент
			if(ecPrecompA)
				for (i = 0, ticks = tmTicks(); i < reps; ++i)
					ecpSmallMultA(c, pt, ec->base, ecW, ec, stack2);
			else
				for (i = 0, ticks = tmTicks(); i < reps; ++i)
					ecpSmallMultJ(c, pt, ec->base, ecW, ec, stack2);
			ticks = tmTicks() - ticks;
			// печать результатов
			printf("ecpBench::%s: %u cycles / rep [%u reps / sec]\n",
				ecPrecompA ? "smulsa" : "smulsj",
				(unsigned)(ticks / reps),
				(unsigned)tmSpeed(reps, ticks));
		}
	}
	// все нормально
	return TRUE;
}
