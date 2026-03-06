/*
*******************************************************************************
\file ecp_bench.c
\brief Benchmarks for elliptic curves over prime fields
\project bee2/test
\created 2013.10.17
\version 2026.03.06
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
#include <bee2/math/ww.h>
#include <crypto/bign/bign_lcl.h>

/*
*******************************************************************************
Оценка производительности на заданной кривой

\expect Функции ecMulPreXX() регулярны на кривой ec. Поэтому скаляр d
не рандомизируется, а вместо среднего времени замеряется минимальное.

\remark Битовая длина скаляра функции ecMulPreSO2() примерно в два раза меньше
длин скаляров других функций. Такая логика соответствует применению
ecMulPreSO2() в реализации протоколов Bake.
*******************************************************************************
*/

static bool_t ecpBenchEc(const ec_o* ec)
{
	const size_t n = ec->f->n;
	const size_t m = wwWordSize(ec->order, n + 1);
	const size_t mo = wwOctetSize(ec->order, m);
	const size_t min_w = 5;
	const size_t max_w = 7;
	const size_t min_h = (B_OF_O(mo) + max_w - 1) / max_w;
	const size_t max_h = (B_OF_O(mo) + min_w - 1) / min_w;
	const size_t max_pre_count = min_h * SIZE_BIT_POS(max_w - 1);
	const size_t reps = 200;
	void* state;
	octet* combo_state;		/* [prngCOMBO_keep()] */
	word* pt;				/* [2 * n] */
	word* d;				/* [m] */
	ec_pre_t* pre;			/* [max_pre_count проективных точек] */
	void* stack;
	// создать состояние
	state = blobCreate2(
		prngCOMBO_keep(),
		O_OF_W(2 * n),
		O_OF_W(m),
		sizeof(ec_pre_t) + O_OF_W(max_pre_count * ec->d * n),
		utilMax(12,
			ecMulA_deep(n, ec->d, ec->deep, m),
			ecPreSO_deep(n, ec->d, ec->deep),
			ecPreSOA_deep(n, ec->d, ec->deep),
			ecPreOD_deep(n, ec->d, ec->deep),
			ecPreSI_deep(n, ec->d, ec->deep, max_h),
			ecpPreSOJ_deep(n, ec->f->deep),
			ecpPreSOA_deep(n, ec->f->deep, max_w),
			ecMulPreSO_deep(n, ec->d, ec->deep, m),
			ecMulPreSO2_deep(n, ec->d, ec->deep, m),
			ecMulPreSOA_deep(n, ec->d, ec->deep, m),
			ecMulPreOD_deep(n, ec->d, ec->deep, m),
			ecMulPreSI_deep(n, ec->d, ec->deep, m)),
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
				prngCOMBOStepR(d, mo, combo_state);
				ecMulA(pt, ec->base, ec, d, m, stack);
			}
			ticks = tmTicks() - ticks;
			printf("  ecMulA:                   %u cycles/pt [%u pts/sec]\n",
				(unsigned)(ticks / reps),
				(unsigned)tmSpeed(reps, ticks));
		}
		// ecpPre+ecMulPre[SO]
		for (w = MAX2(3, min_w); w <= max_w; ++w)
		{
			wwSetW(d, m, 1);
			for (i = 0, ticks = (tm_ticks_t)-1; i < reps; ++i)
			{
				tm_ticks_t t = tmTicks();
				ecpPreSOJ(pre, ec->base, w, ec, stack);
				ecMulPreSO(pt, pre, ec, d, m, stack);
				if ((t = tmTicks() - t) < ticks)
					ticks = t;
			}
			printf("  ecpPre+ecMulPre[SO,w=%u]:  %u cycles/pt [%u pts/sec]\n",
				(unsigned)w,
				(unsigned)ticks,
				(unsigned)tmSpeed(1, ticks));
		}
		// ecPre+MulPre[SO2]
		for (w = min_w; w <= max_w; ++w)
		{
			const size_t mb = (B_OF_O(mo) / 2 / w) * w;
			if (mb < w)
				continue;
			wwSetW(d, m, 1);
			wwSetBit(d, mb, TRUE);
			for (i = 0, ticks = (tm_ticks_t)-1; i < reps; ++i)
			{
				tm_ticks_t t = tmTicks();
				ecpPreSOJ(pre, ec->base, w, ec, stack);
				ecMulPreSO2(pt, pre, ec, d, m, stack);
				if ((t = tmTicks() - t) < ticks)
					ticks = t;
			}
			printf("  ecpPre+ecMulPre[SO2,w=%u]: %u cycles/pt [%u pts/sec]\n",
				(unsigned)w,
				(unsigned)ticks,
				(unsigned)tmSpeed(1, ticks));
		}
		// ecpPre+ecMulPre[SOA]
		for (w = MAX2(3, min_w); w <= max_w; ++w)
		{
			wwSetW(d, m, 1);
			for (i = 0, ticks = (tm_ticks_t)-1; i < reps; ++i)
			{
				tm_ticks_t t = tmTicks();
				ecpPreSOA(pre, ec->base, w, ec, stack);
				ecMulPreSOA(pt, pre, ec, d, m, stack);
				if ((t = tmTicks() - t) < ticks)
					ticks = t;
			}
			printf("  ecpPre+ecMulPre[SOA,w=%u]: %u cycles/pt [%u pts/sec]\n",
				(unsigned)w,
				(unsigned)ticks,
				(unsigned)tmSpeed(1, ticks));
		}
		// ecMulPre[OD]
		for (w = min_w; w <= max_w; ++w)
		{
			size_t h = (B_OF_O(mo) + w - 1) / w;
			ecPreOD(pre, ec->base, w, h, ec, stack);
			wwSetW(d, m, 1);
			for (i = 0, ticks = (tm_ticks_t)-1; i < reps; ++i)
			{
				tm_ticks_t t = tmTicks();
				ecMulPreOD(pt, pre, ec, d, m, stack);
				if ((t = tmTicks() - t) < ticks)
					ticks = t;
			}
			printf("  ecMulPre[OD,w=%u]:         %u cycles/pt [%u pts/sec]\n",
				(unsigned)w,
				(unsigned)ticks,
				(unsigned)tmSpeed(1, ticks));
		}
		// ecMulPre[SI]
		for (w = min_w; w <= max_w; ++w)
		{
			size_t h = (B_OF_O(mo) + w - 1) / w;
			ecPreSI(pre, ec->base, w, h, ec, stack);
			wwSetW(d, m, 1);
			for (i = 0, ticks = (tm_ticks_t)-1; i < reps; ++i)
			{
				tm_ticks_t t = tmTicks();
				ecMulPreSI(pt, pre, ec, d, m, stack);
				if ((t = tmTicks() - t) < ticks)
					ticks = t;
			}
			printf("  ecMulPre[SI,w=%u]:         %u cycles/pt [%u pts/sec]\n",
				(unsigned)w,
				(unsigned)ticks,
				(unsigned)tmSpeed(1, ticks));
		}
		// ecPre[SO]
		for (w = min_w; w <= max_w; ++w)
		{
			for (i = 0, ticks = (tm_ticks_t)-1; i < reps; ++i)
			{
				tm_ticks_t t = tmTicks();
				ecPreSO(pre, ec->base, w, ec, stack);
				if ((t = tmTicks() - t) < ticks)
					ticks = t;
			}
			printf("  ecPre[SO,w=%u]:            %u cycles/pre [%u pre/sec]\n",
				(unsigned)w,
				(unsigned)ticks,
				(unsigned)tmSpeed(1, ticks));
		}
		// ecpPre[SO]
		for (w = MAX2(3, min_w); w <= max_w; ++w)
		{
			for (i = 0, ticks = (tm_ticks_t)-1; i < reps; ++i)
			{
				tm_ticks_t t = tmTicks();
				ecpPreSOJ(pre, ec->base, w, ec, stack);
				if ((t = tmTicks() - t) < ticks)
					ticks = t;
			}
			printf("  ecpPre[SO,w=%u]:           %u cycles/pre [%u pre/sec]\n",
				(unsigned)w,
				(unsigned)ticks,
				(unsigned)tmSpeed(1, ticks));
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
