/*
*******************************************************************************
\file ecp_test.c
\brief Tests for elliptic curves over prime fields
\project bee2/test
\created 2017.05.29
\version 2026.02.12
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <bee2/core/blob.h>
#include <bee2/core/util.h>
#include <bee2/math/ecp.h>
#include <bee2/math/ww.h>
#include <bee2/math/zz.h>
#include <crypto/bign/bign_lcl.h>

/*
*******************************************************************************
Тестирование на заданной кривой
*******************************************************************************
*/

static bool_t ecpTestEc(const ec_o* ec)
{
	// размерности
	const size_t n = ec->f->n;
	const size_t min_w = 3;
	const size_t max_w = 6;
	const size_t max_pre_count = SIZE_BIT_POS(max_w - 1);
	// состояние
	void* state;
	ec_pre_t* pre;	/* [max_pre_count проективных точек] */
	word* pt0;		/* [ec->d * n] */
	word* pt1;		/* [ec->d * n] */
	word* d;		/* [n + 1] */
	void* stack;
	// другие переменные
	size_t w;
	size_t i;
	// создать состояние
	state = blobCreate2(
		sizeof(ec_pre_t) + O_OF_W(max_pre_count * ec->d * n),
		O_OF_W(ec->d * n),
		O_OF_W(ec->d * n),
		O_OF_W(n + 1),
		utilMax(10,
			ecpIsValid_deep(n, ec->f->deep),
			ecpGroupSeemsValid_deep(n, ec->f->deep),
			ecpGroupIsSafe_deep(n),
			ec->deep,
			ecpIsOnA_deep(n, ec->f->deep),
			ecpAddAA_deep(n, ec->f->deep),
			ecpSubAA_deep(n, ec->f->deep),
			ecMulA_deep(n, ec->d, ec->deep, n),
			ecpPreSNZ_deep(n, ec->f->deep, max_w),
			ecpPreSNZA_deep(n, ec->f->deep, max_w)),
		SIZE_MAX,
		&pre, &pt0, &pt1, &d, &stack);
	if (state == 0)
		return FALSE;
	// корректная кривая?
	// корректная группа?
	// надежная группа?
	if (!ecpIsValid(ec, stack) ||
		!ecpGroupSeemsValid(ec, stack) ||
		!ecpGroupIsSafe(ec, 40, stack))
	{
		blobClose(state);
		return FALSE;
	}
	// утроить базовую точку разными способами
	{
		// d <- 3
		d[0] = 3;
		// удвоить и сложить
		if (!ecpIsOnA(ec->base, ec, stack) ||
			!ecpAddAA(pt0, ec->base, ec->base, ec, stack) ||
			!ecpAddAA(pt0, pt0, ec->base, ec, stack) ||
		// дважды удвоить и вычесть
			!ecpAddAA(pt1, ec->base, ec->base, ec, stack) ||
			!ecpAddAA(pt1, pt1, pt1, ec, stack) ||
			!ecpSubAA(pt1, pt1, ec->base, ec, stack) ||
			!wwEq(pt0, pt1, 2 * n) ||
			(ecpNegA(pt1, pt1, ec), ecpAddAA(pt1, pt0, pt1, ec, stack)) ||
		// вычислить кратную точку
			!ecMulA(pt1, ec->base, ec, d, 1, stack) ||
			!wwEq(pt0, pt1, 2 * n))
		{
			blobClose(state);
			return FALSE;
		}
	}
	// предвычисления по схеме SNZ
	for (w = min_w; w <= max_w; ++w)
	{
		// pre[0..2^w) <- (1, 3, ..., 2^w-1)base
		ecpPreSNZ(pre, ec->base, w, ec, stack);
		// pt0 <- \sum_{i = 0}^{2^w-1} 2^{2^{w-1}-1-i} pre[i]
		wwCopy(pt0, ecPrePt(pre, 0, ec), ec->d * n);
		for (i = 1; i < SIZE_BIT_POS(w - 1); ++i)
		{
			ecDbl(pt0, pt0, ec, stack);
			ecAdd(pt0, pt0, ecPrePt(pre, i, ec), ec, stack);
		}
		// pt0 == \sum_{i = 0}^{2^w-1} (2i + 1) 2^{2^{w-1}-1-i} base?
		wwSetW(d, n, 1);
		for (i = 1; i < SIZE_BIT_POS(w - 1); ++i)
		{
			wwShHi(d, n, 1);
			zzAddW2(d, n, (word)(2 * i + 1));
		}
		if (!ecToA(pt0, pt0, ec, stack) ||
			!ecMulA(pt1, ec->base, ec, d, n, stack) ||
			!wwEq(pt0, pt1, 2 * n))
		{
			blobClose(state);
			return FALSE;
		}
	}
	// предвычисления по схеме SNZA
	for (w = min_w; w <= max_w; ++w)
	{
		// pre[0..2^w) <- (1, 3, ..., 2^w-1)base
		if (!ecpPreSNZA(pre, ec->base, w, ec, stack))
		{
			blobClose(state);
			return FALSE;
		}
		// pt0 <- pre[1] - pre[0]
		ecNegA(pt0, ecPrePtA(pre, 0, ec), ec, stack);
		if (!ecpAddAA(pt0, pt0, ecPrePtA(pre, 1, ec), ec, stack))
		{
			blobClose(state);
			return FALSE;
		}
		// pre[i+1] - pre[i] == pt0?
		for (i = 1; i + 1 < SIZE_BIT_POS(w - 1); ++i)
		{
			ecNegA(pt1, ecPrePtA(pre, i, ec), ec, stack);
			if (!ecpAddAA(pt1, pt1, ecPrePtA(pre, i + 1, ec), ec, stack) ||
				!wwEq(pt0, pt1, 2 * n))
			{
				blobClose(state);
				return FALSE;
			}
		}
		// pt0 == 2 base?
		if (!ecpAddAA(pt1, ec->base, ec->base, ec, stack) ||
			!wwEq(pt0, pt1, 2 * n))
		{
			blobClose(state);
			return FALSE;
		}
	}
	// все хорошо
	blobClose(state);
	return TRUE;
}

/*
*******************************************************************************
Тестирование на кривой bign-curve256v1
*******************************************************************************
*/

bool_t ecpTest()
{
	bool_t ret;
	bign_params params[1];
	ec_o* ec;
	// создать кривую
	if (bignParamsStd(params, "1.2.112.0.2.0.34.101.45.3.1") != ERR_OK ||
		bignEcCreate(&ec, params) != ERR_OK)
		return FALSE;
	// оценка
	ret = ecpTestEc(ec);
	// завершение
	bignEcClose(ec);
	return ret;
}
