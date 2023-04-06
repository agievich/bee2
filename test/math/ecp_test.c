/*
*******************************************************************************
\file ecp_test.c
\brief Tests for elliptic curves over prime fields
\project bee2/test
\created 2017.05.29
\version 2023.03.30
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

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
	const size_t ec_keep = ecpCreateJ_keep(n);
	const size_t f_deep = gfpCreate_deep(no);
	// состояние и стек
	octet state[2048];
	octet stack[2048];
	octet t[32 * 5];
	// поле и эк
	qr_o* f;
	ec_o* ec;
	// подготовить память
	if (sizeof(state) < f_keep + ec_keep ||
		sizeof(stack) < f_deep ||
		sizeof(t) < 3 * no)
		return FALSE;
	// создать f = GF(p)
	hexToRev(t, p);
	f = (qr_o*)(state + ec_keep);
	if (!gfpCreate(f, t, no, stack))
		return FALSE;
	// создать ec = EC_{ab}(f)
	hexToRev(t, a), hexToRev(t + no, b);
	ec = (ec_o*)state;
	if (sizeof(stack) < ecpCreateJ_deep(n, f_deep) ||
		!ecpCreateJ(ec, f, t, t + no, stack))
		return FALSE;
	// создать группу точек ec
	hexToRev(t, xbase), hexToRev(t + no, ybase), hexToRev(t + 2 * no, q);
	if (sizeof(stack) < ecCreateGroup_deep(f_deep) ||
		!ecCreateGroup(ec, t, t + no, t + 2 * no, no, cofactor, stack))
		return FALSE;
	// присоединить f к ec
	objAppend(ec, f, 0);
	// корректная кривая?
	if (sizeof(stack) < ecpIsValid_deep(n, f_deep) ||
		!ecpIsValid(ec, stack))
		return FALSE;
	// корректная группа?
	if (sizeof(stack) < ecpSeemsValidGroup_deep(n, f_deep) ||
		!ecpSeemsValidGroup(ec, stack))
		return FALSE;
	// надежная группа?
	if (sizeof(stack) < ecpIsSafeGroup_deep(n) ||
		!ecpIsSafeGroup(ec, 40, stack))
		return FALSE;
	// базовая точка имеет порядок q?
	if (sizeof(stack) < ecHasOrderA_deep(n, ec->d, ec->deep, n) ||
		!ecHasOrderA(ec->base, ec, ec->order, n, stack))
		return FALSE;
	// утроить базовую точку разными способами
	if (sizeof(t) < (2 + ec->d) * no ||
		sizeof(stack) < utilMax(5,
			ec->deep,
			ecpIsOnA_deep(n, f_deep),
			ecpAddAA_deep(n, f_deep),
			ecpSubAA_deep(n, f_deep),
			ecMulA_deep(n, ec->d, ec->deep, 1)))
		return FALSE;
	{
		word* pts = (word*)t;
		word d = 3;
		// удвоить и сложить
		if (!ecpIsOnA(ec->base, ec, stack) ||
			!ecpAddAA(pts, ec->base, ec->base, ec, stack) ||
			!ecpAddAA(pts, pts, ec->base, ec, stack))
			return FALSE;
		// дважды удвоить и вычесть
		if (!ecpAddAA(pts + 2 * n, ec->base, ec->base, ec, stack) ||
			!ecpAddAA(pts + 2 * n, pts + 2 * n, pts + 2 * n, ec, stack) ||
			!ecpSubAA(pts + 2 * n, pts + 2 * n, ec->base, ec, stack) ||
			!memEq(pts, pts + 2 * n, 2 * n))
			return FALSE;
		ecpNegA(pts + 2 * n, pts + 2 * n, ec);
		if (ecpAddAA(pts + 2 * n, pts, pts + 2 * n, ec, stack))
			return FALSE;
		// вычислить кратную точку
		if (!ecMulA(pts + 2 * n, ec->base, ec, &d, 1, stack) ||
			!memEq(pts, pts + 2 * n, 2 * n))
			return FALSE;
		// утроить напрямую
		if (!ec->froma || !ec->tpl || !ec->toa)
			return FALSE;
		ec->froma(pts + 2 * n, ec->base, ec, stack);
		ec->tpl(pts + 2 * n, pts + 2 * n, ec, stack);
		ec->toa(pts + 2 * n, pts + 2 * n, ec, stack);
		if (!memEq(pts, pts + 2 * n, 2 * n))
			return FALSE;
	}
	// вывести f = GF(p) за пределы ec
	f = (qr_o*)(state + ec_keep);
	memMove(f, objPtr(ec, 0, qr_o), f_keep);
	// создать ec = EC_{a-1, b}(f)
	hexToRev(t, a), --t[0], hexToRev(t + no, b);
	ec = (ec_o*)state;
	if (sizeof(stack) < ecpCreateJ_deep(n, f_deep) ||
		!ecpCreateJ(ec, f, t, t + no, stack))
		return FALSE;
	// присоединить f к ec
	objAppend(ec, f, 0);
	// точка (xbase = 0, ybase) все еще лежит на ec: ybase^2 = b
	hexToRev(t, xbase), hexToRev(t + no, ybase);
	wwFrom(ec->base, t, no), wwFrom(ec->base + n, t + no, no);
	ASSERT(wwIsZero(ec->base, n));
	// утроить базовую точку разными способами
	if (sizeof(t) < (2 + ec->d) * no ||
		sizeof(stack) < utilMax(5,
			ec->deep,
			ecpIsOnA_deep(n, f_deep),
			ecpAddAA_deep(n, f_deep),
			ecpSubAA_deep(n, f_deep),
			ecMulA_deep(n, ec->d, ec->deep, 1)))
		return FALSE;
	{
		word* pts = (word*)t;
		word d = 3;
		// удвоить и сложить
		if (!ecpIsOnA(ec->base, ec, stack) ||
			!ecpAddAA(pts, ec->base, ec->base, ec, stack) ||
			!ecpAddAA(pts, pts, ec->base, ec, stack))
			return FALSE;
		// дважды удвоить и вычесть
		if (!ecpAddAA(pts + 2 * n, ec->base, ec->base, ec, stack) ||
			!ecpAddAA(pts + 2 * n, pts + 2 * n, pts + 2 * n, ec, stack) ||
			!ecpSubAA(pts + 2 * n, pts + 2 * n, ec->base, ec, stack) ||
			!memEq(pts, pts + 2 * n, 2 * n))
			return FALSE;
		ecpNegA(pts + 2 * n, pts + 2 * n, ec);
		if (ecpAddAA(pts + 2 * n, pts, pts + 2 * n, ec, stack))
			return FALSE;
		// вычислить кратную точку
		if (!ecMulA(pts + 2 * n, ec->base, ec, &d, 1, stack) ||
			!memEq(pts, pts + 2 * n, 2 * n))
			return FALSE;
		// утроить напрямую
		if (!ec->froma || !ec->tpl || !ec->toa)
			return FALSE;
		ec->froma(pts + 2 * n, ec->base, ec, stack);
		ec->tpl(pts + 2 * n, pts + 2 * n, ec, stack);
		ec->toa(pts + 2 * n, pts + 2 * n, ec, stack);
		if (!memEq(pts, pts + 2 * n, 2 * n))
			return FALSE;
	}
	// все нормально
	return TRUE;
}
