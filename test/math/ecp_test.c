/*
*******************************************************************************
\file ecp_test.c
\brief Tests for elliptic curves over prime fields
\project bee2/test
\created 2017.05.29
\version 2026.01.27
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
	word* pts;		/* [6 * 3 * n] */
	word* pt0;		/*   [3 * n] */
	word* pt1;		/*   [3 * n] */
	word* pt2;		/*   [3 * n] */
	word* pt3;		/*   [3 * n] */
	word* pt4;		/*   [3 * n] */
	word* pt5;		/*   [3 * n] */
	word* d;		/* [n] */
	void* stack;
	// создать состояние
	state = blobCreate2(
		ec_keep,
		f_keep,
		3 * no,
		O_OF_W(6 * 3 * n) | SIZE_HI,
		O_OF_W(n),
		utilMax(13,
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
			ecMulA2_deep(n, 3, ec_deep, n)),
		SIZE_MAX,
		&ec, &f, &t, &pts, &d, &stack);
	if (state == 0)
		return FALSE;
	pt0 = pts, pt1 = pt0 + 3 * n, pt2 = pt1 + 3 * n, pt3 = pt2 + 3 * n,
		pt4 = pt3 + 3 * n, pt5 = pt4 + 3 * n;
	// создать f = GF(p)
	hexToRev(t, p);
	if (!gfpCreate(f, t, no, stack))
		return FALSE;
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
	// ecMulA() vs ecMulA2()
	{
		wwCopy(d, ec->order, n);
		zzSubW2(d, n, 1);
		while (!wwIsZero(d, n))
		{
			if (!ecMulA2(pt0, ec->base, ec, d, n, stack) ||
				!ecMulA(pt1, ec->base, ec, d, n, stack) ||
				!wwEq(pt0, pt1, 2 * n))
				return FALSE;
			wwShLo(d, n, 1);
		}
		if (ecMulA(pt0, ec->base, ec, d, n, stack) ||
			ecMulA2(pt1, ec->base, ec, d, n, stack))
			return FALSE;
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
	if (FALSE)
	{
		// (pt0, pt1, pt2, pt3) <- (base, 3 base, 5 base, 7 base)
		ecpPreSNZ(pts, ec->base, 3, ec, stack);
		// pt0 == base?
		ecToA(pt4, pt0, ec, stack);
		if (!wwEq(pt5, ec->base, 2 * n))
		{
			blobClose(state);
			return FALSE;
		}
		// pt1 == 3 base?
		d[0] = 3, ecMulA(pt5, ec->base, ec, d, 1, stack);
		ecToA(pt4, pt1, ec, stack);
		if (!wwEq(pt4, pt5, 2 * n))
		{
			blobClose(state);
			return FALSE;
		}
		// pt2 == 5 base?
		d[0] = 5, ecMulA(pt5, ec->base, ec, d, 1, stack);
		ecToA(pt4, pt2, ec, stack);
		if (!wwEq(pt4, pt5, 2 * n))
		{
			blobClose(state);
			return FALSE;
		}
		// pt3 == 7 base?
		d[0] = 7, ecMulA(pt5, ec->base, ec, d, 1, stack);
		ecToA(pt4, pt3, ec, stack);
		if (!wwEq(pt4, pt5, 2 * n))
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
