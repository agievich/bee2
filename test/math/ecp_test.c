/*
*******************************************************************************
\file ecp_test.c
\brief Tests for elliptic curves over prime fields
\project bee2/test
\created 2017.05.29
\version 2025.09.08
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
static u32 cofactor = 1;

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
	ec_o* ec;
	qr_o* f;
	octet* t;
	void* stack;
	// создать состояние
	state = blobCreate2(
		ec_keep,
		f_keep,
		5 * no,
		utilMax(12,
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
			ecMulA_deep(n, 3, ec_deep, 1)),
		SIZE_MAX,
		&ec, &f, &t, &stack);
	if (state == 0)
		return FALSE;
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
	// базовая точнка имеет порядок q?
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
		word* pts = (word*)t;
		word d = 3;
		// удвоить и сложить
		if (!ecpIsOnA(ec->base, ec, stack) ||
			!ecpAddAA(pts, ec->base, ec->base, ec, stack) ||
			!ecpAddAA(pts, pts, ec->base, ec, stack) ||
		// дважды удвоить и вычесть
			!ecpAddAA(pts + 2 * n, ec->base, ec->base, ec, stack) ||
			!ecpAddAA(pts + 2 * n, pts + 2 * n, pts + 2 * n, ec, stack) ||
			!ecpSubAA(pts + 2 * n, pts + 2 * n, ec->base, ec, stack) ||
			!memEq(pts, pts + 2 * n, 2 * n) ||
			(ecpNegA(pts + 2 * n, pts + 2 * n, ec),
				ecpAddAA(pts + 2 * n, pts, pts + 2 * n, ec, stack)) ||
		// вычислить кратную точку
			!ecMulA(pts + 2 * n, ec->base, ec, &d, 1, stack) ||
			!memEq(pts, pts + 2 * n, 2 * n) ||
		// утроить напрямую
			!ec->froma || !ec->tpl || !ec->toa ||
			(ec->froma(pts + 2 * n, ec->base, ec, stack),
				ec->tpl(pts + 2 * n, pts + 2 * n, ec, stack),
				ec->toa(pts + 2 * n, pts + 2 * n, ec, stack),
				!memEq(pts, pts + 2 * n, 2 * n)))
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
		word* pts = (word*)t;
		word d = 3;
		// удвоить и сложить
		if (!ecpIsOnA(ec->base, ec, stack) ||
			!ecpAddAA(pts, ec->base, ec->base, ec, stack) ||
			!ecpAddAA(pts, pts, ec->base, ec, stack) ||
		// дважды удвоить и вычесть
			!ecpAddAA(pts + 2 * n, ec->base, ec->base, ec, stack) ||
			!ecpAddAA(pts + 2 * n, pts + 2 * n, pts + 2 * n, ec, stack) ||
			!ecpSubAA(pts + 2 * n, pts + 2 * n, ec->base, ec, stack) ||
			!memEq(pts, pts + 2 * n, 2 * n) ||
			(ecpNegA(pts + 2 * n, pts + 2 * n, ec),
				ecpAddAA(pts + 2 * n, pts, pts + 2 * n, ec, stack)) ||
		// вычислить кратную точку
			!ecMulA(pts + 2 * n, ec->base, ec, &d, 1, stack) ||
			!memEq(pts, pts + 2 * n, 2 * n) ||
			(ec->froma(pts + 2 * n, ec->base, ec, stack),
				ec->tpl(pts + 2 * n, pts + 2 * n, ec, stack),
				ec->toa(pts + 2 * n, pts + 2 * n, ec, stack),
				!memEq(pts, pts + 2 * n, 2 * n)))
		{
			blobClose(state);
			return FALSE;
		}
	}
	// все хорошо
	blobClose(state);
	return TRUE;
}
