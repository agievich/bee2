/*
*******************************************************************************
\file mem_test.c
\brief Tests for memory functions
\project bee2/test
\created 2014.02.01
\version 2025.08.27
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <bee2/core/mem.h>
#include <bee2/core/hex.h>
#include <bee2/core/util.h>

/*
*******************************************************************************
Тестирование

\remark Если не инициализировать буфер buf, то компилятор GCC при обработке 
вызова memIsValid(buf, sizeof(buf)) выдаст предупреждение 
-Wmaybe-uninitialized:
> In addition, passing a pointer (or in C++, a reference) to an uninitialized 
object to a const-qualified function argument is also diagnosed by this 
warning (https://gcc.gnu.org/onlinedocs/gcc/Warning-Options.html).
*******************************************************************************
*/

bool_t memTest()
{
	octet buf[16];
	octet buf1[16];
	octet buf2[16];
	octet buf3[3 * sizeof(mem_align_t)];
	void* p;
	void* p1;
	void* p2;
	void* p3;
	size_t i;
	// pre
	CASSERT(sizeof(buf) == sizeof(buf1));
	memSetZero(buf, sizeof(buf));
	if (!memIsValid(buf, sizeof(buf)) || !memIsValid(0, 0))
		return FALSE;
	// alloc (считаем, что памяти хватает)
	p = memAlloc(100);
	if (!p)
		return FALSE;
	memSet(p, 7, 100);
	if (!(p1 = memRealloc(p, 102)) || 
		!memIsRep(p = p1, 100, 7) ||
		!(p1 = memRealloc(p, 90)) || 
		!memIsRep(p = p1, 90, 7) ||
		(p = memRealloc(p, 0)))
	{
		memFree(p);
		return FALSE;
	}
	memFree(p);
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
	hexTo(buf,  "000102030405060708090A0B0C0D0E0F");
	hexTo(buf1, "F00102030405060708090A0B0C0D0EFF");
	if (memIsZero(buf, 15) ||
		FAST(memIsZero)(buf, 15) ||
		FAST(memIsZero)(buf, 3) ||
		memEq(buf + 1, buf1 + 1, 15) ||
		FAST(memEq)(buf + 1, buf1 + 1, 15) ||
		memEq(buf + 8, buf1 + 8, 8) ||
		FAST(memEq)(buf + 8, buf1 + 8, 8) ||
		!memEq(buf + 1, buf1 + 1, 8) ||
		!FAST(memEq)(buf + 1, buf1 + 1, 8) ||
		!memEq(buf + 1, buf1 + 1, 14) ||
		!FAST(memEq)(buf + 1, buf1 + 1, 14) ||
		memCmp(buf, buf1, 7) != -1 ||
		FAST(memCmp)(buf, buf1, 7) != -1 ||
		memCmpRev(buf, buf1, 7) != -1 ||
		FAST(memCmpRev)(buf, buf1, 7) != -1 ||
		memCmp(buf, buf1, 15) != -1 ||
		FAST(memCmp)(buf, buf1, 15) != -1 ||
		memCmpRev(buf, buf1, 15) != -1 ||
		FAST(memCmpRev)(buf, buf1, 15) != -1 ||
		memCmp(buf1, buf, 15) != 1 ||
		FAST(memCmp)(buf1, buf, 15) != 1 ||
		memCmpRev(buf1, buf, 15) != 1 ||
		FAST(memCmpRev)(buf1, buf, 15) != 1 ||
		memCmp(buf, buf1, 8) != -1 ||
		FAST(memCmp)(buf, buf1, 8) != -1 ||
		memCmpRev(buf, buf1, 8) != -1 ||
		FAST(memCmpRev)(buf, buf1, 8) != -1 ||
		memCmp(buf1, buf, 8) != 1 ||
		FAST(memCmp)(buf1, buf, 8) != 1 ||
		memCmpRev(buf1, buf, 8) != 1 ||
		FAST(memCmpRev)(buf1, buf, 8) != 1 ||
		memCmp(buf + 1, buf1 + 1, 8) != 0 ||
		FAST(memCmp)(buf + 1, buf1 + 1, 8) != 0 ||
		memCmp(buf + 1, buf1 + 1, 14) != 0 ||
		FAST(memCmp)(buf + 1, buf1 + 1, 14) != 0 ||
		memCmpRev(buf + 1, buf1 + 1, 8) != 0 ||
		FAST(memCmpRev)(buf + 1, buf1 + 1, 8) != 0 ||
		memCmpRev(buf + 1, buf1 + 1, 14) != 0 ||
		FAST(memCmpRev)(buf + 1, buf1 + 1, 14) != 0)
		return FALSE;
	memRev(buf, 15);
	if (memNonZeroSize(buf, 15) != 14)
		return FALSE;
	hexTo(buf,  "F001020304050607");
	hexTo(buf1, "00010203040506F7");
	if (memCmp(buf, buf1, 8) != 1 ||
		FAST(memCmp)(buf, buf1, 8) != 1 ||
		memCmp(buf1, buf, 8) != -1 ||
		FAST(memCmp)(buf1, buf, 8) != -1 ||
		memCmpRev(buf, buf1, 8) != -1 ||
		FAST(memCmpRev)(buf, buf1, 8) != -1 ||
		memCmpRev(buf1, buf, 8) != 1 ||
		FAST(memCmpRev)(buf1, buf, 8) != 1)
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
	// join
	hexTo(buf, "0001020304050607");
	memJoin(buf, buf + 1, 3, buf + 3, 4);
	if (!hexEq(buf, "01020303040506"))
		return FALSE;
	hexTo(buf, "0001020304050607");
	memJoin(buf, buf + 1, 3, buf + 1, 4);
	if (!hexEq(buf, "01020301020304"))
		return FALSE;
	hexTo(buf, "0001020304050607");
	memJoin(buf, buf + 3, 4, buf + 2, 2);
	if (!hexEq(buf, "030405060203"))
		return FALSE;
	hexTo(buf, "0001020304050607");
	memJoin(buf + 2, buf, 4, buf + 4, 2);
	if (!hexEq(buf + 2, "000102030405"))
		return FALSE;
	// xor
	hexTo(buf, "000102030405060708");
	hexTo(buf1, "F0F1F2F3F4F5F6F7F8");
	memXor(buf2, buf, buf1, 9);
	if (!memIsRep(buf2, 9, 0xF0))
		return FALSE;
	memXor2(buf2, buf1, 9);
	memXor2(buf2, buf, 8);
	if (!memIsRep(buf2, 8, 0) || buf2[8] != 0x08)
		return FALSE;
	// разметка
	if (memSlice(0, 
			SIZE_1, &p, 
			SIZE_1 | SIZE_HI, &p1, 
			SIZE_1, NULL, 
			SIZE_1, NULL, 
			SIZE_MAX) != 2 * sizeof(mem_align_t) + 1)
		return FALSE;
	if (memSlice(buf3, 
			SIZE_1, &p, 
			SIZE_1 | SIZE_HI, &p1, 
			SIZE_0, &p2,
			SIZE_0, &p3,
			SIZE_MAX) != sizeof(mem_align_t) ||
		p != buf3 || p1 != p || p2 != p3)
		return FALSE;
	if (memSlice(buf3, 
			SIZE_1 | SIZE_HI, &p, 
			SIZE_1 | SIZE_HI, &p1, 
			SIZE_MAX) != 1 || 
		p != buf3 || p1 != p)
		return FALSE;
	if (memSlice(buf3, 
			SIZE_1, &p, 
			SIZE_1, &p1, 
			SIZE_1, &p2, 
			SIZE_1 | SIZE_HI, NULL, 
			SIZE_MAX) != 2 * sizeof(mem_align_t) + 1 || 
		p != buf3 || p1 == p || p2 == p1)
		return FALSE;
	// все нормально
	return TRUE;
}
