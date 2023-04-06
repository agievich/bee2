/*
*******************************************************************************
\file prng_test.c
\brief Tests for pseudorandom number generators
\project bee2/test
\created 2014.06.30
\version 2023.03.29
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <bee2/core/mem.h>
#include <bee2/core/hex.h>
#include <bee2/core/prng.h>
#include <bee2/core/util.h>

/*
*******************************************************************************
Тестирование
*******************************************************************************
*/

bool_t prngTest()
{
	octet buf[128];
	char state[256];
	// подготовить память
	if (sizeof(state) < prngSTB_keep())
		return FALSE;
	// prngSTB
	prngSTBStart(state, 0);
	prngSTBStepR(buf, 128, state);
	if (!hexEq(buf, 
		"402971E923BFD0B621E230D4CBFAF010"
		"E2D1F32D5C76B58AE05AB02BB85B2A10"
		"67F8DC6FFFF51932D956E3B3749884C5"
		"623331D616FF391C8AF12556A0CBA754"
		"79F682F6DD86DACB59346C50DD01CFAF"
		"6255D350C3B7392C8F6AA11496BBD25D"
		"D80C0173331A9C0DF721884E4E2773C5"
		"7FE4E23824E31FC902F1C7A09EB1C312"))
		return FALSE;
	// все нормально
	return TRUE;
}
