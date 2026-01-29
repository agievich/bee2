/*
*******************************************************************************
\file ecp_test.c
\brief Tests for elliptic curves over prime fields
\project bee2/test
\created 2017.05.29
\version 2026.01.29
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <bee2/core/blob.h>
#include <bee2/core/hex.h>
#include <bee2/core/mem.h>
#include <bee2/core/obj.h>
#include <bee2/core/util.h>
#include <bee2/math/gfp.h>
#include <bee2/math/ecp.h>
#include <bee2/math/ww.h>
#include <bee2/math/zz.h>

/*
*******************************************************************************
Проверочная кривая
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

/*
*******************************************************************************
Тестирование
*******************************************************************************
*/

bool_t ecpTest()
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
	ec_pre_t* pre;	/* [64 якобиевы точки] */
	word* pt0;		/* [3 * n] */
	word* pt1;		/* [3 * n] */
	word* pt2;		/* [3 * n] */
	word* pt3;		/* [3 * n] */
	word* pt4;		/* [3 * n] */
	word* pt5;		/* [3 * n] */
	word* d;		/* [n + 1] */
	void* stack;
	// создать состояние
	state = blobCreate2(
		ec_keep,
		f_keep,
		3 * no,
		(sizeof(ec_pre_t) + O_OF_W(64 * 3 * n)) | SIZE_HI,
		O_OF_W(3 * n),
		O_OF_W(3 * n),
		O_OF_W(3 * n),
		O_OF_W(3 * n),
		O_OF_W(3 * n),
		O_OF_W(3 * n),
		O_OF_W(n + 1),
		utilMax(17,
			gfpCreate_deep(no),
			ecpCreateJ_deep(n, f_deep),
			ecGroupCreate_deep(f_deep),
			ecpIsValid_deep(n, f_deep),
			ecpGroupSeemsValid_deep(n, f_deep),
			ecpGroupIsSafe_deep(n),
			ecHasOrderA_deep(n, 3, ec_deep, n),
			ec_deep,
			ecpIsOnA_deep(n, f_deep),
			ecpAddAA_deep(n, f_deep),
			ecpSubAA_deep(n, f_deep),
			ecMulA_deep(n, 3, ec_deep, n),
			ecPreSNZ_deep(n, 3, ec_deep),
			ecMulPreSNZ_deep(n, 3, ec_deep, n),
			ecPreSNZA_deep(n, 3, ec_deep),
			ecMulPreSNZA_deep(n, 3, ec_deep, n),
			ecAddMulA_deep(n, 3, ec_deep, 4, (size_t)1, (size_t)2, (size_t)3, (size_t)4)),
		SIZE_MAX,
		&ec, &f, &t, &pre, &pt0, &pt1, &pt2, &pt3, &pt4, &pt5, &d, &stack);
	if (state == 0)
		return FALSE;
	// создать f = GF(p)
	hexToRev(t, p);
	if (!gfpCreate(f, t, no, stack))
	{
		blobClose(state);
		return FALSE;
	}
	// создать ec = EC_{ab}(f)
	hexToRev(t, a), hexToRev(t + no, b);
	if (!ecpCreateJ(ec, f, t, t + no, stack) || ec->d != 3) 
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
	// базовая точка имеет порядок q?
	if (!ecpIsValid(ec, stack) ||
		!ecpGroupSeemsValid(ec, stack) ||
		!ecpGroupIsSafe(ec, 40, stack) ||
		!ecHasOrderA(ec->base, ec, ec->order, n, stack))
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
	// финишное сложение
	if (ec->finadd)
	{
		// (pt1, pt2, pt3, pt4) <- (base, 2 base, 3 base, 4 base)
		ecFromA(pt1, ec->base, ec, stack);
		ecAddA(pt2, pt1, ec->base, ec, stack);
		ecAddA(pt3, pt2, ec->base, ec, stack);
		ecAddA(pt4, pt3, ec->base, ec, stack);
		// pt0 <- pt1 + pt2 = 3 base, pt0 == pt3?
		ec->finadd(pt0, pt1, pt2, 0, ec, stack);
		ecToA(pt5, pt3, ec, stack);
		if (!wwEq(pt0, pt5, 2 * n))
		{
			blobClose(state);
			return FALSE;
		}
		// pt0 <- -(pt1 + pt3) == -4 base, pt0 == -pt4?
		ec->finadd(pt0, pt1, pt3, 1, ec, stack);
		ecNeg(pt5, pt4, ec, stack);
		ecToA(pt5, pt5, ec, stack);
		if (!wwEq(pt0, pt5, 2 * n))
		{
			blobClose(state);
			return FALSE;
		}
		// pt0 <- -(pt2 + pt2) == -4 base, pt0 == -pt4?
		ec->finadd(pt0, pt2, pt2, 1, ec, stack);
		if (!wwEq(pt0, pt5, 2 * n))
		{
			blobClose(state);
			return FALSE;
		}
		// pt0 <- pt1 + pt1 == 2 base, pt0 == pt2?
		ec->finadd(pt0, pt1, pt1, 0, ec, stack);
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
		ec->finadda(pt0, pt1, pt5, 0, ec, stack);
		ecToA(pt5, pt3, ec, stack);
		if (!wwEq(pt0, pt5, 2 * n))
		{
			blobClose(state);
			return FALSE;
		}
		// pt0 <- -(pt1 + pt3) == -4 base, pt0 == -pt4?
		ecToA(pt5, pt3, ec, stack);
		ec->finadda(pt0, pt1, pt5, 1, ec, stack);
		ecNeg(pt5, pt4, ec, stack);
		ecToA(pt5, pt5, ec, stack);
		if (!wwEq(pt0, pt5, 2 * n))
		{
			blobClose(state);
			return FALSE;
		}
		// pt0 <- -(pt2 + pt2) == -4 base, pt0 == -pt4?
		ecToA(pt5, pt2, ec, stack);
		ec->finadda(pt0, pt2, pt5, 1, ec, stack);
		ecNeg(pt5, pt4, ec, stack);
		ecToA(pt5, pt5, ec, stack);
		if (!wwEq(pt0, pt5, 2 * n))
		{
			blobClose(state);
			return FALSE;
		}
		// pt0 <- pt1 + pt1 == 2 base, pt0 ==? pt2
		ec->finadda(pt0, pt1, ec->base, 0, ec, stack);
		ecToA(pt5, pt2, ec, stack);
		if (!wwEq(pt0, pt5, 2 * n))
		{
			blobClose(state);
			return FALSE;
		}
	}
	// удвоение и сложение с аффинной точкой
	if (ec->dbladda)
	{
		// pt0 <- 2 base + base
		ecFromA(pt1, ec->base, ec, stack);
		ec->dbladda(pt0, pt1, ec->base, ec, stack);
		// pt3 <- 3 base
		ecpAddAA(pt3, ec->base, ec->base, ec, stack);
		ecpAddAA(pt3, pt3, ec->base, ec, stack);
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
		ecpNegA(pt3, ec->base, ec);
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
		d[0] = 5, ecMulA(pt3, ec->base, ec, d, 1, stack);
		if (!ecToA(pt0, pt0, ec, stack) || !wwEq(pt0, pt3, 2 * n))
		{
			blobClose(state);
			return FALSE;
		}
	}
	// предвычисления по схеме SNZ
	{
		size_t i;
		// pt[0..64) <- (1, 3, ..., 31, -31, ..., -3, -1)base
		ecPreSNZ(pre, ec->base, 6, ec, stack);
		// pt[i] == -pt[63 - i]?
		for (i = 0; i < 32; ++i)
		{
			ecNeg(pt0, ecPrePt(pre, 63 - i, ec), ec, stack);
			ecNeg(pt0, pt0, ec, stack);
			ecAdd(pt0, pt0, ecPrePt(pre, i, ec), ec, stack);
			if (ecToA(pt0, pt0, ec, stack))
			{
				blobClose(state);
				return FALSE;
			}
		}
		// pt0 <- \sum_{i = 0}^31 2^{31 - i} pt[i]
		wwCopy(pt0, ecPrePt(pre, 0, ec), 3 * n);
		for (i = 1; i < 32; ++i)
		{
			ecDbl(pt0, pt0, ec, stack);
			ecAdd(pt0, pt0, ecPrePt(pre, i, ec), ec, stack);
		}
		// pt0 == \sum_{i = 0}^31 (2i + 1) 2^{31 - i} base?
		wwSetW(d, n, 1);
		for (i = 1; i < 32; ++i)
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
	{
		size_t i;
		// pt[0..64) <- (1, 3, ..., 31, -31, ..., -3, -1)base
		if (!ecPreSNZA(pre, ec->base, 6, ec, stack))
		{
			blobClose(state);
			return FALSE;
		}
		// pt[i] == -pt[63 - i]?
		for (i = 0; i < 32; ++i)
		{
			ecNegA(pt0, ecPrePtA(pre, 63 - i, ec), ec, stack);
			ecNegA(pt0, pt0, ec, stack);
			if (ecpAddAA(pt0, pt0, ecPrePtA(pre, i, ec), ec, stack))
			{
				blobClose(state);
				return FALSE;
			}
		}
		// pt0 <- pt[1] - pt[0]
		ecNegA(pt0, ecPrePtA(pre, 0, ec), ec, stack);
		if (!ecpAddAA(pt0, pt0, ecPrePtA(pre, 1, ec), ec, stack))
		{
			blobClose(state);
			return FALSE;
		}
		// pt[i+1] - pt[i] == pt0?
		for (i = 1; i + 1 < 32; ++i)
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
	// кратная точка: ecMulA vs ecMulPreSNZ
	{
		size_t w;
		for (w = 5; w <= 6; ++w)
		{
			wwCopy(d, ec->order, n);
			zzSubW2(d, n, 1);
			ecPreSNZ(pre, ec->base, w, ec, stack);
			while (!wwIsZero(d, n))
			{
				if (!ecMulPreSNZ(pt0, pre, ec, d, n, stack) ||
					!ecMulA(pt1, ec->base, ec, d, n, stack) ||
					!wwEq(pt0, pt1, 2 * n))
				{
					blobClose(state);
					return FALSE;
				}
				wwShLo(d, n, 11);
			}
			if (ecMulPreSNZ(pt0, pre, ec, d, n, stack) ||
				ecMulA(pt1, ec->base, ec, d, n, stack))
			{
				blobClose(state);
				return FALSE;
			}
		}
	}
	// кратная точка: ecMulA vs ecMulPreSNZA
	{
		size_t w;
		for (w = 5; w <= 6; ++w)
		{
			wwCopy(d, ec->order, n);
			zzSubW2(d, n, 1);
			ecPreSNZA(pre, ec->base, w, ec, stack);
			while (!wwIsZero(d, n))
			{
				if (!ecMulPreSNZA(pt0, pre, ec, d, n, stack) ||
					!ecMulA(pt1, ec->base, ec, d, n, stack) ||
					!wwEq(pt0, pt1, 2 * n))
				{
					blobClose(state);
					return FALSE;
				}
				wwShLo(d, n, 23);
			}
			if (ecMulPreSNZA(pt0, pre, ec, d, n, stack) ||
				ecMulA(pt1, ec->base, ec, d, n, stack))
			{
				blobClose(state);
				return FALSE;
			}
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
	// вывести f = GF(p) за пределы ec
	objCopy(f, objPtr(ec, 0, qr_o));
	// создать ec = EC_{a-1, b}(f)
	hexToRev(t, a), --t[0], hexToRev(t + no, b);
	if (!ecpCreateJ(ec, f, t, t + no, stack))
	{
		blobClose(state);
		return FALSE;
	}
	// заново присоединить f к ec
	objAppend(ec, f, 0);
	// точка (xbase = 0, ybase) все еще лежит на ec: ybase^2 = b
	hexToRev(t, xbase), hexToRev(t + no, ybase);
	wwFrom(ec->base, t, no), wwFrom(ec->base + n, t + no, no);
	ASSERT(wwIsZero(ec->base, n));
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
			!wwEq(pt0, pt1, 2 * n) ||
			(ec->froma(pt1, ec->base, ec, stack),
				ec->tpl(pt1, pt1, ec, stack),
				ec->toa(pt1, pt1, ec, stack),
				!wwEq(pt0, pt1, 2 * n)))
		{
			blobClose(state);
			return FALSE;
		}
	}
	// все хорошо
	blobClose(state);
	return TRUE;
}
