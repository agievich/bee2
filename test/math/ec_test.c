/*
*******************************************************************************
\file ec_test.c
\brief Tests for elliptic curves
\project bee2/test
\created 2026.02.12
\version 2026.03.05
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <bee2/core/blob.h>
#include <bee2/core/hex.h>
#include <bee2/core/mem.h>
#include <bee2/core/obj.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include <bee2/core/word.h>
#include <bee2/math/gfp.h>
#include <bee2/math/ecp.h>
#include <bee2/math/ww.h>
#include <bee2/math/zz.h>

/*
*******************************************************************************
Сложение / вычитание афффинных точек
*******************************************************************************
*/

#define ecAddAA_local(n, ec_d)\
/* t */		O_OF_W(ec_d * n)

static bool_t ecAddAA(word c[], const word a[], const word b[],
	const ec_o* ec, void* stack)
{
	word* t;			/* [ec->d * ec->f->n] */
	memSlice(stack,
		ecAddAA_local(ec->f->n, ec->d), SIZE_0, SIZE_MAX,
		&t, &stack);
	ecFromA(t, b, ec, stack);
	ecAddA(t, t, a, ec, stack);
	return ecToA(c, t, ec, stack);
}

static size_t ecAddAA_deep(size_t n, size_t ec_d, size_t ec_deep)
{
	return memSliceSize(
		ecAddAA_local(n, ec_d),
		ec_deep,
		SIZE_MAX);
}

#define ecSubAA_local ecAddAA_local

static bool_t ecSubAA(word c[], const word a[], const word b[],
	const ec_o* ec, void* stack)
{
	word* t;			/* [ec->d * ec->f->n] */
	memSlice(stack,
		ecSubAA_local(ec->f->n, ec->d), SIZE_0, SIZE_MAX,
		&t, &stack);
	ecNegA(t, b, ec, stack);
	ecFromA(t, t, ec, stack);
	ecAddA(t, t, a, ec, stack);
	return ecToA(c, t, ec, stack);
}

#define ecSubAA_deep ecAddAA_deep

/*
*******************************************************************************
Тестирование на заданной кривой
*******************************************************************************
*/

bool_t ecTestEc(const ec_o* ec)
{
	// размерности
	const size_t n = ec->f->n;
	const size_t no = ec->f->no;
	const size_t min_w = 1;
	const size_t max_w = 4;
	const size_t min_h = (B_OF_O(no) + max_w - 1) / max_w;
	const size_t max_h = (B_OF_O(no) + min_w - 1) / min_w;
	const size_t max_pre_count = 
		MAX2(min_h * SIZE_BIT_POS(max_w - 1), SIZE_BIT_POS(max_w - 1) + 3);
	// состояние
	void* state;
	ec_pre_t* pre;	/* [max_pre_count проективных точек] */
	word* pt0;		/* [ec->d * n] */
	word* pt1;		/* [ec->d * n] */
	word* pt2;		/* [ec->d * n] */
	word* pt3;		/* [ec->d * n] */
	word* pt4;		/* [ec->d * n] */
	word* pt5;		/* [ec->d * n] */
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
		O_OF_W(ec->d * n),
		O_OF_W(ec->d * n),
		O_OF_W(ec->d * n),
		O_OF_W(ec->d * n),
		O_OF_W(n + 1),
		utilMax(15,
			ec->deep,
			ecHasOrderA_deep(n, ec->d, ec->deep, n),
			ecAddAA_deep(n, ec->d, ec->deep),
			ecSubAA_deep(n, ec->d, ec->deep),
			ecMulA_deep(n, ec->d, ec->deep, n),
			ecPreSO_deep(n, ec->d, ec->deep),
			ecPreSOA_deep(n, ec->d, ec->deep),
			ecPreSI_deep(n, ec->d, ec->deep, max_h),
			ecPreOD_deep(n, ec->d, ec->deep),
			ecMulPreSO_deep(n, ec->d, ec->deep, n),
			ecMulPreSO2_deep(n, ec->d, ec->deep, n),
			ecMulPreSOA_deep(n, ec->d, ec->deep, n),
			ecMulPreOD_deep(n, ec->d, ec->deep, n),
			ecMulPreSI_deep(n, ec->d, ec->deep, n),
			ecAddMulA_deep(n, ec->d, ec->deep, 4,
				(size_t)1, (size_t)2, (size_t)3, (size_t)4)),
		SIZE_MAX,
		&pre, &pt0, &pt1, &pt2, &pt3, &pt4, &pt5, &d, &stack);
	if (state == 0)
		return FALSE;
	// работоспособная кривая?
	// работоспособная группа?
	// надежная группа?
	// базовая точка имеет порядок q?
	if (!ecIsOperable(ec) ||
		!ecIsOperable2(ec) ||
		!ecGroupIsOperable(ec) ||
		!ecHasOrderA(ec->base, ec, ec->order, n + 1, stack))
	{
		blobClose(state);
		return FALSE;
	}
	// утроить базовую точку разными способами
	{
		// d <- 3
		d[0] = 3;
		// удвоить и сложить
		if (!ecAddAA(pt0, ec->base, ec->base, ec, stack) ||
			!ecAddAA(pt0, pt0, ec->base, ec, stack) ||
			// дважды удвоить и вычесть
			!ecAddAA(pt1, ec->base, ec->base, ec, stack) ||
			!ecAddAA(pt1, pt1, pt1, ec, stack) ||
			!ecSubAA(pt1, pt1, ec->base, ec, stack) ||
			!wwEq(pt0, pt1, 2 * n) ||
			(ecNegA(pt1, pt1, ec, stack), ecAddAA(pt1, pt0, pt1, ec, stack)) ||
			// вычислить кратную точку
			!ecMulA(pt1, ec->base, ec, d, 1, stack) ||
			!wwEq(pt0, pt1, 2 * n) ||
			// утроить напрямую
			!ec->froma || !ec->tpl || !ec->toa ||
			(ec->froma(pt1, ec->base, ec, stack),
				ec->tpl(pt1, pt1, ec, stack),
				ec->toa(pt1, pt1, ec, stack),
				!wwEq(pt0, pt1, 2 * n)))
		{
			blobClose(state);
			return FALSE;
		}
	}
	// удвоение со сложением с аффинной точкой
	if (ec->dbladda)
	{
		// pt0 <- 2 base + base
		ecFromA(pt1, ec->base, ec, stack);
		ec->dbladda(pt0, pt1, ec->base, ec, stack);
		// pt3 <- 3 base
		ecAddAA(pt3, ec->base, ec->base, ec, stack);
		ecAddAA(pt3, pt3, ec->base, ec, stack);
		// pt0 == pt3?
		if (!ecToA(pt0, pt0, ec, stack) || !wwEq(pt0, pt3, 2 * n))
		{
			blobClose(state);
			return FALSE;
		}
		// pt0 <- 2(-base) + base
		ecNeg(pt1, pt1, ec, stack);
		ec->dbladda(pt0, pt1, ec->base, ec, stack);
		// pt3 <- -base
		ecNegA(pt3, ec->base, ec, stack);
		// pt0 == pt3?
		if (!ecToA(pt0, pt0, ec, stack) || !wwEq(pt0, pt3, 2 * n))
		{
			blobClose(state);
			return FALSE;
		}
		// pt0 <- 2O + base
		ecSetO(pt1, ec);
		ec->dbladda(pt0, pt1, ec->base, ec, stack);
		// pt0 == base?
		if (!ecToA(pt0, pt0, ec, stack) || !wwEq(pt0, ec->base, 2 * n))
		{
			blobClose(state);
			return FALSE;
		}
		// pt0 <- 2(2base) + base
		ecDblA(pt1, ec->base, ec, stack);
		ec->dbladda(pt0, pt1, ec->base, ec, stack);
		// pt0 == 5 base?
		d[0] = 5;
		if (!ecMulA(pt3, ec->base, ec, d, 1, stack) ||
			!ecToA(pt0, pt0, ec, stack) ||
			!wwEq(pt0, pt3, 2 * n))
		{
			blobClose(state);
			return FALSE;
		}
	}
	// установка знака
	if (ec->sgn)
	{
		ecFromA(pt0, ec->base, ec, stack);
		wwCopy(pt1, pt0, 3 * n);
		ecSgn(pt0, 0, ec, stack);
		if (!wwEq(pt0, pt1, 3 * n))
		{
			blobClose(state);
			return FALSE;
		}
		ecSgn(pt0, 1, ec, stack);
		ecNeg(pt1, pt1, ec, stack);
		if (!wwEq(pt0, pt1, 3 * n))
		{
			blobClose(state);
			return FALSE;
		}
	}
	// установка знака аффинной точки
	if (ec->sgna)
	{
		wwCopy(pt0, ec->base, 2 * n);
		ecSgnA(pt0, 0, ec, stack);
		if (!wwEq(pt0, ec->base, 2 * n))
		{
			blobClose(state);
			return FALSE;
		}
		ecSgnA(pt0, 1, ec, stack);
		ecNegA(pt1, ec->base, ec, stack);
		if (!wwEq(pt0, pt1, 2 * n))
		{
			blobClose(state);
			return FALSE;
		}
	}
	// финишное сложение
	if (ec->finadd)
	{
		// (pt1, pt2, pt3, pt4) <- (base, 2 base, 3 base, 4 base)
		ecFromA(pt1, ec->base, ec, stack);
		ecAddA(pt2, pt1, ec->base, ec, stack);
		ecAddA(pt3, pt2, ec->base, ec, stack);
		ecAddA(pt4, pt3, ec->base, ec, stack);
		// pt0 <- pt1 + pt2 = 3 base, pt0 == pt3?
		ec->finadd(pt0, pt1, pt2, ec, stack);
		ecToA(pt5, pt3, ec, stack);
		if (!wwEq(pt0, pt5, 2 * n))
		{
			blobClose(state);
			return FALSE;
		}
		// pt0 <- pt1 + pt3 == 4 base, pt0 == pt4?
		ec->finadd(pt0, pt1, pt3, ec, stack);
		ecToA(pt5, pt4, ec, stack);
		if (!wwEq(pt0, pt5, 2 * n))
		{
			blobClose(state);
			return FALSE;
		}
		// pt0 <- pt2 + pt2 == 4 base, pt0 == pt4?
		ec->finadd(pt0, pt2, pt2, ec, stack);
		ecToA(pt5, pt4, ec, stack);
		if (!wwEq(pt0, pt5, 2 * n))
		{
			blobClose(state);
			return FALSE;
		}
		// pt0 <- pt1 + pt1 == 2 base, pt0 == pt2?
		ec->finadd(pt0, pt1, pt1, ec, stack);
		ecToA(pt5, pt2, ec, stack);
		if (!wwEq(pt0, pt5, 2 * n))
		{
			blobClose(state);
			return FALSE;
		}
	}
	// финишное сложение с аффинной точкой
	if (ec->finadda)
	{
		// (pt1, pt2, pt3, pt4) <- (base, 2 base, 3 base, 4 base)
		ecFromA(pt1, ec->base, ec, stack);
		ecAddA(pt2, pt1, ec->base, ec, stack);
		ecAddA(pt3, pt2, ec->base, ec, stack);
		ecAddA(pt4, pt3, ec->base, ec, stack);
		// pt0 <- pt1 + pt2 = 3 base, pt0 == pt3?
		ecToA(pt5, pt2, ec, stack);
		ec->finadda(pt0, pt1, pt5, ec, stack);
		ecToA(pt5, pt3, ec, stack);
		if (!wwEq(pt0, pt5, 2 * n))
		{
			blobClose(state);
			return FALSE;
		}
		// pt0 <- pt1 + pt3 == 4 base, pt0 == pt4?
		ecToA(pt5, pt3, ec, stack);
		ec->finadda(pt0, pt1, pt5, ec, stack);
		ecToA(pt5, pt4, ec, stack);
		if (!wwEq(pt0, pt5, 2 * n))
		{
			blobClose(state);
			return FALSE;
		}
		// pt0 <- pt2 + pt2 == 4 base, pt0 == pt4?
		ecToA(pt5, pt2, ec, stack);
		ec->finadda(pt0, pt2, pt5, ec, stack);
		ecToA(pt5, pt4, ec, stack);
		if (!wwEq(pt0, pt5, 2 * n))
		{
			blobClose(state);
			return FALSE;
		}
		// pt0 <- pt1 + pt1 == 2 base, pt0 ==? pt2
		ec->finadda(pt0, pt1, ec->base, ec, stack);
		ecToA(pt5, pt2, ec, stack);
		if (!wwEq(pt0, pt5, 2 * n))
		{
			blobClose(state);
			return FALSE;
		}
	}
	// предвычисления по схеме SO
	for (w = min_w; w <= max_w; ++w)
	{
		// pre[0..2^w) <- (1, 3, ..., 2^w-1)base
		ecPreSO(pre, ec->base, w, ec, stack);
		// pt0 <- \sum_{i=0}^{2^{w-1}-1} 2^{2^{w-1}-1-i} pre[i]
		wwCopy(pt0, ecPrePt(pre, 0, ec), ec->d * n);
		for (i = 1; i < SIZE_BIT_POS(w - 1); ++i)
		{
			ecDbl(pt0, pt0, ec, stack);
			ecAdd(pt0, pt0, ecPrePt(pre, i, ec), ec, stack);
		}
		// pt0 == \sum_{i=0}^{2^{w-1}-1} (2i+1)2^{2^{w-1}-1-i} base?
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
	// предвычисления по схеме SOA
	for (w = min_w; w <= max_w; ++w)
	{
		size_t i;
		// pre[0..2^w) <- (1, 3, ..., 2^w-1)base
		if (!ecPreSOA(pre, ec->base, w, ec, stack) ||
			!wwEq(ecPrePtA(pre, 0, ec), ec->base, 2 * n))
		{
			blobClose(state);
			return FALSE;
		}
		// пропустить проверки при w = 1
		if (w == 1)
			continue;
		// pt0 <- pre[1] - pre[0]
		ecNegA(pt0, ecPrePtA(pre, 0, ec), ec, stack);
		if (!ecAddAA(pt0, pt0, ecPrePtA(pre, 1, ec), ec, stack))
		{
			blobClose(state);
			return FALSE;
		}
		// pre[i+1] - pre[i] == pt0?
		for (i = 1; i + 1 < SIZE_BIT_POS(w - 1); ++i)
		{
			ecNegA(pt1, ecPrePtA(pre, i, ec), ec, stack);
			if (!ecAddAA(pt1, pt1, ecPrePtA(pre, i + 1, ec), ec, stack) ||
				!wwEq(pt0, pt1, 2 * n))
			{
				blobClose(state);
				return FALSE;
			}
		}
		// pt0 == 2 base?
		if (!ecAddAA(pt1, ec->base, ec->base, ec, stack) ||
			!wwEq(pt0, pt1, 2 * n))
		{
			blobClose(state);
			return FALSE;
		}
	}
	// предвычисления по схеме SI
	for (w = min_w; w <= max_w; ++w)
	{
		const size_t h = (B_OF_O(no) + w - 1) / w;
		size_t i;
		// pre[0..2^{w-1}) <- (1, 3, ..., 2^{w-1}-1)base
		ecPreSI(pre, ec->base, w, h, ec, stack);
		// pre[0] == \sum_{i=0}^{w-1} (2^h)^i base?
		wwSetZero(d, n + 1);
		for (i = 0; i < w; ++i)
			wwSetBit(d, h * i, TRUE);
		if (!ecMulA(pt1, ec->base, ec, d, n, stack) ||
			!wwEq(ecPrePt(pre, 0, ec), pt1, 2 * n))
		{
			blobClose(state);
			return FALSE;
		}
		// pt0 <- \sum_{i = 0}^{2^{w-1}-1} pre[i]
		ecFromA(pt0, ecPrePtA(pre, 0, ec), ec, stack);
		for (i = 1; i < SIZE_BIT_POS(w - 1); ++i)
			ecAddA(pt0, pt0, ecPrePtA(pre, i, ec), ec, stack);
		// pt0 == (2^{h(w-1)} * 2^{w-1}) base?
		ASSERT((h + 1) * (w - 1) < B_OF_W(n + 1));
		wwSetZero(d, n + 1);
		wwSetBit(d, (h + 1) * (w - 1), TRUE);
		if (!ecToA(pt0, pt0, ec, stack) ||
			!ecMulA(pt1, ec->base, ec, d, n + 1, stack) ||
			!wwEq(pt0, pt1, 2 * n))
		{
			blobClose(state);
			return FALSE;
		}
	}
	// сумма кратных точек: ecMulA vs ecAddMulA
	if (n >= 4)
	{
		if (!ecAddMulA(pt0, ec, stack, 4,
			ec->base, ec->order, (size_t)1,
			ec->base, ec->order, (size_t)2,
			ec->base, ec->order, (size_t)3,
			ec->base, ec->order, (size_t)4))
		{
			blobClose(state);
			return FALSE;
		}
		wwCopy(d, ec->order, n);
		d[4] = zzAddW2(d + 3, 1, zzAdd2(d, ec->order, 3));
		d[4] += zzAddW2(d + 2, 2, zzAdd2(d, ec->order, 2));
		d[4] += zzAddW2(d + 1, 3, zzAdd2(d, ec->order, 1));
		if (!ecMulA(pt1, ec->base, ec, d, 5, stack) ||
			!wwEq(pt0, pt1, 2 * n))
		{
			blobClose(state);
			return FALSE;
		}
	}
	// четный порядок?
	if (ec->order[0] % 2 == 0)
	{
		blobClose(state);
		return TRUE;
	}
	// кратная точка: ecMulA vs ecMulPreSO
	for (w = min_w; w <= max_w; ++w)
	{
		const size_t m = wwWordSize(ec->order, n + 1);
		wwCopy(d, ec->order, m);
		zzSubW2(d, m, 1);
		ecPreSO(pre, ec->base, w, ec, stack);
		while (!wwIsZero(d, m))
		{
			if (!ecMulPreSO(pt0, pre, ec, d, m, stack) ||
				!ecMulA(pt1, ec->base, ec, d, m, stack) ||
				!wwEq(pt0, pt1, 2 * n))
			{
				blobClose(state);
				return FALSE;
			}
			wwShLo(d, m, 31);
		}
		if (ecMulPreSO(pt0, pre, ec, d, m, stack) ||
			ecMulA(pt1, ec->base, ec, d, m, stack))
		{
			blobClose(state);
			return FALSE;
		}
	}
	// кратная точка: ecMulA vs ecMulPreSO2
	for (w = min_w; w <= max_w; ++w)
	{
		const size_t m = wwWordSize(ec->order, n + 1);
		const size_t mb = (wwBitSize(ec->order, m) / 3 / w) * w;
		if (mb <= w)
			continue;
		wwCopy(d, ec->order, m);
		wwTrimHi(d, m, mb);
		wwSetBit(d, mb, TRUE);
		ecPreSO(pre, ec->base, w, ec, stack);
		while (0 <= wwCmpW(d, m, 2))
		{
			if (!ecMulPreSO2(pt0, pre, ec, d, m, stack) ||
				!ecMulA(pt1, ec->base, ec, d, m, stack) ||
				!wwEq(pt0, pt1, 2 * n))
			{
				blobClose(state);
				return FALSE;
			}
			wwShLo(d, m, 11);
		}
	}
	// кратная точка: ecMulA vs ecMulPreSOA
	for (w = min_w; w <= max_w; ++w)
	{
		const size_t m = wwWordSize(ec->order, n + 1);
		wwCopy(d, ec->order, m);
		zzSubW2(d, m, 1);
		if (!ecPreSOA(pre, ec->base, w, ec, stack))
		{
			blobClose(state);
			return FALSE;
		}
		while (!wwIsZero(d, m))
		{
			if (!ecMulPreSOA(pt0, pre, ec, d, m, stack) ||
				!ecMulA(pt1, ec->base, ec, d, m, stack) ||
				!wwEq(pt0, pt1, 2 * n))
			{
				blobClose(state);
				return FALSE;
			}
			wwShLo(d, m, 23);
		}
		if (ecMulPreSOA(pt0, pre, ec, d, m, stack) ||
			ecMulA(pt1, ec->base, ec, d, m, stack))
		{
			blobClose(state);
			return FALSE;
		}
	}
	// кратная точка: ecMulA vs ecMulPreOD
	for (w = min_w; w <= max_w; ++w)
	{
		const size_t m = wwWordSize(ec->order, n + 1);
		const size_t h = (B_OF_O(no) + w - 1) / w;
		wwCopy(d, ec->order, m);
		zzSubW2(d, m, 1);
		if (!ecPreOD(pre, ec->base, w, h, ec, stack))
		{
			blobClose(state);
			return FALSE;
		}
		while (!wwIsZero(d, m))
		{
			if (!ecMulPreOD(pt0, pre, ec, d, m, stack) ||
				!ecMulA(pt1, ec->base, ec, d, m, stack) ||
				!wwEq(pt0, pt1, 2 * m))
			{
				blobClose(state);
				return FALSE;
			}
			wwShLo(d, m, 34);
		}
		if (ecMulPreOD(pt0, pre, ec, d, m, stack) ||
			ecMulA(pt1, ec->base, ec, d, m, stack))
		{
			blobClose(state);
			return FALSE;
		}
	}
	// кратная точка: ecMulA vs ecMulPreSI
	for (w = min_w; w <= max_w; ++w)
	{
		const size_t m = wwWordSize(ec->order, n + 1);
		const size_t h = (B_OF_O(no) + w - 1) / w;
		wwCopy(d, ec->order, m);
		zzSubW2(d, m, 1);
		if (!ecPreSI(pre, ec->base, w, h, ec, stack))
		{
			blobClose(state);
			return FALSE;
		}
		while (!wwIsZero(d, m))
		{
			if (!ecMulPreSI(pt0, pre, ec, d, m, stack) ||
				!ecMulA(pt1, ec->base, ec, d, m, stack) ||
				!wwEq(pt0, pt1, 2 * n))
			{
				blobClose(state);
				return FALSE;
			}
			wwShLo(d, m, 15);
		}
		if (ecMulPreSI(pt0, pre, ec, d, m, stack) ||
			ecMulA(pt1, ec->base, ec, d, m, stack))
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
Проверочная кривая:
- p -- простое, p = 3 (mod 4);
- a = p - 3;
- q, порядок группы точек, -- простое число;
- xbase = 0, ybase = b^((p + 1) / 4) mod p (ybase^2 = b mod p).

\remark Вычисление порядка группы в PARI/GP:
\code
	p = 2^256 - 189
	a = p - 3
	b = 5304
	E = ellinit([a, b], p)
	ellcard(E)
\endcode

При a = p - 5 порядок группы точек становится равным 2 * q1, где
	q1 = 2^2 * 3 * 7 * 277847 * 282129349161734992975487682047 *
		17585131690472517417114517434596060246881.
Точка (xbase = 0, ybase) остается лежать на кривой, имея порядок q1.

\remark 
Определение порядка точки в PARI/GP:
\code
	y = lift(Mod(b, p)^((p + 1)/4))
	ellorder(E, [0, y])
\endcode
*******************************************************************************
*/

static const size_t no = 32;
static char p[] = 
	"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF43";
static char a[] = 
	"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF40";
static char b[] = 
	"00000000000000000000000000000000000000000000000000000000000014B8";
static char q[] = 
	"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D1229165911507C328526818EC4E11D";
static char xbase[] = 
	"0000000000000000000000000000000000000000000000000000000000000000";
static char ybase[] = 
	"B0E9804939D7C2E931D4CE052CCC6B6B692514CCADBA44940484EEA5F52D9268";
static size_t cofactor = 1;

static char q1[] =
	"010000000000000000000000000000000063d339dd2fc92a1634b0ce9864ab0ef4";

/*
*******************************************************************************
Тестирование
*******************************************************************************
*/

bool_t ecTest()
{
	// размерности
	const size_t n = W_OF_O(no);
	const size_t f_keep = gfpCreate_keep(no);
	const size_t f_deep = gfpCreate_deep(no);
	const size_t ec_keep = ecpCreateJ_keep(n);
	const size_t ec_deep = ecpCreateJ_deep(n, f_deep);
	// состояние
	void* state;
	ec_o* ec;		/* [ec_keep] */
	qr_o* f;		/* [f_keep] */
	octet* t;		/* [3 * no] */
	void* stack;
	// создать состояние
	state = blobCreate2(
		ec_keep,
		f_keep,
		3 * no + 1,
		utilMax(7,
			gfpCreate_deep(no),
			ecpCreateJ_deep(n, f_deep),
			ecGroupCreate_deep(f_deep),
			ecpIsValid_deep(n, f_deep),
			ecpGroupSeemsValid_deep(n, f_deep),
			ecpGroupIsSafe_deep(n),
			ec_deep),
		SIZE_MAX,
		&ec, &f, &t, &stack);
	if (state == 0)
		return FALSE;
	// создать f = GF(p)
	hexToRev(t, p);
	if (!gfpCreate(f, t, no, stack))
	{
		blobClose(state);
		return FALSE;
	}
	// создать ec = EC_{a,b}(f)
	hexToRev(t, a), hexToRev(t + no, b);
	if (!ecpCreateJ(ec, f, t, t + no, TRUE, stack) || ec->d != 3) 
	{
		blobClose(state);
		return FALSE;
	}
	// создать группу точек ec
	hexToRev(t, xbase), hexToRev(t + no, ybase), hexToRev(t + 2 * no, q);
	if (!ecGroupCreate(ec, t, t + no, t + 2 * no, no, cofactor, stack))
	{
		blobClose(state);
		return FALSE;
	}
	// присоединить f к ec
	objAppend(ec, f, 0);
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
	// выполнить тесты
	if (!ecTestEc(ec))
	{
		blobClose(state);
		return FALSE;
	}
	// вывести f = GF(p) за пределы ec
	objCopy(f, objPtr(ec, 0, qr_o));
	// создать ec = EC_{a-2, b}(f)
	hexToRev(t, a), t[0] -= 2, hexToRev(t + no, b);
	if (!ecpCreateJ(ec, f, t, t + no, FALSE, stack))
	{
		blobClose(state);
		return FALSE;
	}
	// заново присоединить f к ec
	objAppend(ec, f, 0);
	// заново создать группу точек ec:
	// - точка (xbase = 0, ybase) лежит на ec;
	// - порядок группы меняется на q1.
	ASSERT(strLen(q1) == 2 * no + 2);
	hexToRev(t, xbase), hexToRev(t + no, ybase), hexToRev(t + 2 * no, q1);
	if (!ecGroupCreate(ec, t, t + no, t + 2 * no, no + 1, cofactor, stack))
	{
		blobClose(state);
		return FALSE;
	}
	// корректная кривая?
	// корректная группа?
	// группа перестала быть надежной?
	if (!ecpIsValid(ec, stack) ||
		!ecpGroupSeemsValid(ec, stack) ||
		ecpGroupIsSafe(ec, 40, stack))
	{
		blobClose(state);
		return FALSE;
	}
	// заблокировать функции интерфейсов ec_finadd_i, ec_finadda_i
	ec->finadd = 0, ec->finadda = 0;
	// выполнить тесты
	if (!ecTestEc(ec))
	{
		blobClose(state);
		return FALSE;
	}
	// все хорошо
	blobClose(state);
	return TRUE;
}
