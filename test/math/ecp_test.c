/*
*******************************************************************************
\file ecp_test.c
\brief Tests for elliptic curves over prime fields
\project bee2/test
\created 2017.05.29
\version 2017.08.23
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <bee2/core/hex.h>
#include <bee2/core/obj.h>
#include <bee2/core/util.h>
#include <bee2/math/gfp.h>
#include <bee2/math/ecp.h>

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
	// состояние и стек
	octet state[2048];
	octet stack[2048];
	octet t[96];
	// поле и эк
	qr_o* f;
	ec_o* ec;
	// хватает памяти?
	ASSERT(f_keep + ec_keep <= sizeof(state));
	ASSERT(ec_deep  <= sizeof(stack));
	// создать f = GF(p)
	hexToRev(t, p);
	f = (qr_o*)(state + ec_keep);
	if (!gfpCreate(f, t, no, stack))
		return FALSE;
	// создать ec = EC_{ab}(f)
	hexToRev(t, a), hexToRev(t + 32, b);
	ec = (ec_o*)state;
	if (!ecpCreateJ(ec, f, t, t + 32, stack))
		return FALSE;
	// создать группу точек ec
	hexToRev(t, xbase), hexToRev(t + 32, ybase), hexToRev(t + 64, q);
	if (!ecCreateGroup(ec, t, t + 32, t + 64, no, cofactor, stack))
		return FALSE;
	// присоединить f к ec
	objAppend(ec, f, 0);
	// корректная кривая?
	ASSERT(ecpIsValid_deep(n, f_deep) <= sizeof(stack));
	if (!ecpIsValid(ec, stack))
		return FALSE;
	// корректная группа?
	ASSERT(ecpSeemsValidGroup_deep(n, f_deep) <= sizeof(stack));
	if (!ecpSeemsValidGroup(ec, stack))
		return FALSE;
	// надежная группа?
	ASSERT(ecpIsSafeGroup_deep(n) <= sizeof(stack));
	if (!ecpIsSafeGroup(ec, 40, stack))
		return FALSE;
	// базовая точка имеет порядок q?
	ASSERT(ecHasOrderA_deep(n, ec->d, ec_deep, n) <= sizeof(stack));
	if (!ecHasOrderA(ec->base, ec, ec->order, n, stack))
		return FALSE;
	// все нормально
	return TRUE;
}
