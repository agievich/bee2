/*
*******************************************************************************
\file util-test.c
\brief Tests for utilities
\project bee2/test
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2017.01.17
\version 2017.01.17
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include <stdio.h>
#include <bee2/core/util.h>

/*
*******************************************************************************
Тестирование

Тест для FNV32: http://isthe.com/chongo/tech/comp/fnv/##zero-hash##67. 
*******************************************************************************
*/

bool_t utilTest()
{
	printf("utilVersion: %s\n", utilVersion());
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
