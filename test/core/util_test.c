/*
*******************************************************************************
\file util_test.c
\brief Tests for utilities
\project bee2/test
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2017.01.17
\version 2019.06.11
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
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

bool_t utilTest()
{
	printf("utilVersion: %s [%s]\n", utilVersion(), utilInfo());
	if (utilMin(5, SIZE_1, (size_t)2, (size_t)3, SIZE_1, SIZE_0) != 0 ||
		utilMax(5, SIZE_1, (size_t)2, (size_t)3, SIZE_1, SIZE_0) != 3)
		return FALSE;
	if (utilCRC32("123456789", 9, 0) != 0xCBF43926)
		return FALSE;
	if (utilFNV32("3pjNqM", 6, 0x811C9DC5) != 0)
		return FALSE;
	// все нормально
	return TRUE;
}
