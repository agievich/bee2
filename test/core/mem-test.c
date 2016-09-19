/*
*******************************************************************************
\file mem-test.c
\brief Tests for memory functions
\project bee2/test
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2014.02.01
\version 2016.09.19
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include <bee2/core/mem.h>
#include <bee2/core/hex.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>

/*
*******************************************************************************
Тестирование
*******************************************************************************
*/

bool_t memTest()
{
	octet buf[1024];
	octet buf1[1024];
	size_t i;
	// pre
	ASSERT(sizeof(buf) == sizeof(buf1));
	if (!memIsValid(buf, sizeof(buf)) || !memIsValid(0, 0))
		return FALSE;
	// заполнение / копирование
	memSet(buf, 12, sizeof(buf));
	memCopy(buf1, buf, sizeof(buf));
	for (i = 0; i < sizeof(buf); ++i)
	{
		if (buf1[i] != buf[i])
			return FALSE;
		buf[i] = buf1[i] = i % 256u;
	}
	memMove(buf, buf + 1, sizeof(buf) - 1);
	memMove(buf1 + 1, buf1, sizeof(buf1) - 1);
	for (i = 0; i < sizeof(buf) - 2; ++i)
	{
		if (buf1[i + 2] != buf[i])
			return FALSE;
	}
	memCopy(buf1, 0, 0);
	memMove(buf1, 0, 0);
	// сравнение
	hexTo(buf, "000102030405060708090A0B0C0D0E0F");
	hexTo(buf1, "F00102030405060708090A0B0C0D0EFF");
	if (memEq(buf + 1, buf1 + 1, 15) ||
		FAST(memEq)(buf + 1, buf1 + 1, 15) ||
		memEq(buf + 8, buf1 + 8, 8) ||
		FAST(memEq)(buf + 8, buf1 + 8, 8) ||
		!memEq(buf + 1, buf1 + 1, 8) ||
		!FAST(memEq)(buf + 1, buf1 + 1, 8) ||
		!memEq(buf + 1, buf1 + 1, 14) ||
		!FAST(memEq)(buf + 1, buf1 + 1, 14) ||
		memCmp(buf, buf1, 7) != -1 ||
		FAST(memCmp)(buf, buf1, 7) != -1 ||
		memCmp(buf, buf1, 15) != -1 ||
		FAST(memCmp)(buf, buf1, 15) != -1 ||
		memCmp(buf1, buf, 15) != 1 ||
		FAST(memCmp)(buf1, buf, 15) != 1 ||
		memCmp(buf, buf1, 8) != -1 ||
		FAST(memCmp)(buf, buf1, 8) != -1 ||
		memCmp(buf1, buf, 8) != 1 ||
		FAST(memCmp)(buf1, buf, 8) != 1 ||
		memCmp(buf + 1, buf1 + 1, 8) != 0 ||
		FAST(memCmp)(buf + 1, buf1 + 1, 8) != 0 ||
		memCmp(buf + 1, buf1 + 1, 14) != 0 ||
		FAST(memCmp)(buf + 1, buf1 + 1, 14) != 0)
		return FALSE;
	hexTo(buf, "F001020304050607");
	hexTo(buf1, "00010203040506F7");
	if (memCmp(buf, buf1, 8) != -1 ||
		FAST(memCmp)(buf, buf1, 8) != -1 ||
		memCmp(buf1, buf, 8) != 1 ||
		FAST(memCmp)(buf1, buf, 8) != 1)
		return FALSE;
	hexTo(buf, "01010101010101010102");
	if (memIsRep(buf, 7, 0x01) != TRUE ||
		FAST(memIsRep)(buf, 7, 0x01) != TRUE ||
		memIsRep(buf, 8, 0x01) != TRUE ||
		FAST(memIsRep)(buf, 8, 0x01) != TRUE ||
		memIsRep(buf, 9, 0x01) != TRUE ||
		FAST(memIsRep)(buf, 9, 0x01) != TRUE ||
		memIsRep(buf, 10, 0x01) == TRUE ||
		FAST(memIsRep)(buf, 10, 0x01) == TRUE)
		return FALSE;
	// все нормально
	return TRUE;
}
