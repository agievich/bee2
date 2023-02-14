/*
*******************************************************************************
\file util_test.c
\brief Tests for utilities
\project bee2/test
\created 2017.01.17
\version 2021.05.18
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <stdio.h>
#include <bee2/core/util.h>

/*
*******************************************************************************
Информация о runtime-среде и настройках
*******************************************************************************
*/

const char* utilInfo()
{
	static char descr[128];
	sprintf(descr, "%s,B_PER_W=%d,B_PER_S=%d,%s",
		(OCTET_ORDER == LITTLE_ENDIAN) ? "LITTLE_ENDIAN" : "BIG_ENDIAN",
		B_PER_W, B_PER_S,
#ifdef SAFE_FAST
		"FAST"
#else
		"SAFE"
#endif
		);
	return descr;
}

/*
*******************************************************************************
Тестирование

Тест для FNV32: http://isthe.com/chongo/tech/comp/fnv/##zero-hash##67. 
*******************************************************************************
*/

static size_t _ctr = 5;

static void destroy1()
{
	volatile size_t x = (_ctr == 2) ? 1 : 0;
	// увы, результат проверки станет известен только on_exit
	_ctr = 1 / x;
}

static void destroy2()
{
	_ctr--;
}

bool_t utilTest()
{
	printf("utilVersion: %s [%s]\n", utilVersion(), utilInfo());
	if (utilMin(5, SIZE_1, (size_t)2, (size_t)3, SIZE_1, SIZE_0) != 0 ||
		utilMax(5, SIZE_1, (size_t)2, (size_t)3, SIZE_1, SIZE_0) != 3)
		return FALSE;
	// деструкторы
	if (!utilOnExit(destroy1) || !utilOnExit(destroy2) ||
		!utilOnExit(destroy2) || !utilOnExit(destroy2))
		return FALSE;
	// контрольные суммы
	if (utilCRC32("123456789", 9, 0) != 0xCBF43926)
		return FALSE;
	if (utilFNV32("3pjNqM", 6, 0x811C9DC5) != 0)
		return FALSE;
	// все нормально
	return TRUE;
}
