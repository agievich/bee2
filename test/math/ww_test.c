/*
*******************************************************************************
\file u64_test.c
\brief Tests for operations on arbitrary length words
\project bee2/test
\created 2023.03.31
\version 2025.07.24
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <bee2/core/util.h>
#include <bee2/math/ww.h>

/*
*******************************************************************************
Тестирование
*******************************************************************************
*/

bool_t wwTest()
{
	word a[8];
	word b[8];
	word c[8];
	// заполнение и сравнение
	if ((wwSetW(a, COUNT_OF(a), 0), FALSE) ||
			!wwIsZero(a, 8) || !FAST(wwIsZero)(a, 8) ||
		(wwSetZero(a, COUNT_OF(a)), FALSE) ||
			!wwIsZero(a, 8) || !FAST(wwIsZero)(a, 8) ||
		(wwSetW(a, COUNT_OF(a), 0x36), FALSE) ||
			wwIsZero(a, 8) || FAST(wwIsZero)(a, 8) ||
			!wwIsW(a, 8, 0x36) || !FAST(wwIsW)(a, 8, 0x36) ||
			wwIsW(a, 8, 0x5C) || FAST(wwIsW)(a, 8, 0x5C) ||
			wwCmpW(a, 8, 0x36) != 0 || FAST(wwCmpW)(a, 8, 0x36) != 0 ||
			wwCmpW(a, 8, 0x5C) >=0 || FAST(wwCmpW)(a, 8, 0x5C) >= 0 ||
		(wwRepW(a, COUNT_OF(a), 0x36), FALSE) ||
			wwIsZero(a, 8) || FAST(wwIsZero)(a, 8) ||
			!wwIsRepW(a, 8, 0x36) || !FAST(wwIsRepW)(a, 8, 0x36) ||
			wwIsRepW(a, 8, 0x5C) || FAST(wwIsRepW)(a, 8, 0x5C))
		return FALSE;
	// копирование и сравнение
	if ((wwCopy(a, a, 8), FALSE) ||
			!wwEq(a, a, 8) || !FAST(wwEq)(a, a, 8) ||
		(wwRepW(b, 8, 0x5C), FALSE) ||
			wwEq(a, b, 8) || FAST(wwEq)(a, b, 8) ||
			wwCmp(a, b, 8) >= 0 || FAST(wwCmp)(a, b, 8) >= 0 ||
			wwCmp2(a, 8, b, 7) <= 0 || FAST(wwCmp2)(a, 8, b, 7) <= 0 ||
		(wwSwap(a, b, 8), FALSE) ||
			wwCmp(a, b, 8) <= 0 || FAST(wwCmp)(a, b, 8) <= 0 ||
			wwCmp2(a, 7, b, 8) >= 0 || FAST(wwCmp2)(a, 7, b, 8) >= 0)
		return FALSE;
	// операции с битами
	ASSERT(wwIsRepW(b, 8, 0x36));
	if (wwTestBit(b, 0) || !wwTestBit(b, 1) ||
		wwTestBit(b, 0 + B_PER_W) || !wwTestBit(b, 1 + B_PER_W) ||
		wwTestBit(b, B_PER_W - 1) || wwTestBit(b, 2 * B_PER_W - 1) ||
		wwGetBits(b, B_PER_W, 6) != 0x36 ||
		wwGetBits(b, B_PER_W + 1, 5) != (0x36 >> 1) ||
		(wwSetBit(b, B_PER_W - 1, TRUE), FALSE) ||
			!wwTestBit(b, B_PER_W - 1) ||
		(wwFlipBit(b, B_PER_W - 1), FALSE) ||
			wwTestBit(b, B_PER_W - 1) ||
		(wwSetBit(b, B_PER_W - 1, FALSE), FALSE) ||
			wwTestBit(b, B_PER_W - 1) ||
		(wwSetBits(b, B_PER_W - 2, 7, 0x36), FALSE) ||
			wwGetBits(b, B_PER_W - 2, 7) != 0x36)
		return FALSE;
	// XOR
	if ((wwXor(c, a, b, 8), wwXor2(c, a, 8), wwXor2(c, b, 8), FALSE) ||
			!wwIsZero(c, 8) ||
		(wwCopy(c, b, 8), wwXor(c, c, c, 8), FALSE) ||
			!wwIsZero(c, 8) ||
		(wwCopy(c, a, 8), wwXor2(c, c, 8), FALSE) ||
			!wwIsZero(c, 8))
		return FALSE;
	// нулевые разряды
	ASSERT(wwIsRepW(a, 8, 0x5C) && wwIsZero(c, 8));
	if (wwLoZeroBits(a, 8) != 2 ||
		wwHiZeroBits(a, 8) != B_PER_W - 7 ||
		wwLoZeroBits(c, 8) != B_PER_W * 8 ||
		wwLoZeroBits(c, 8) != B_PER_W * 8 ||
		(wwCopy(b, a, 8), wwTrimHi(b, 8, 6 * B_PER_W + 3), FALSE) ||
			wwHiZeroBits(b, 8) != 2 * B_PER_W - 3 ||
		(wwTrimLo(b, 8, B_PER_W + 5), FALSE) ||
			wwLoZeroBits(b, 8) != B_PER_W + 6)
		return FALSE;
	// сдвиги
	ASSERT(wwIsRepW(a, 8, 0x5C));
	if (wwShHiCarry(a, 8, B_PER_W, 0x5C) != 0x5C ||
		!wwIsRepW(a, 8, 0x5C) ||
		wwShLoCarry(a, 8, B_PER_W, 0x5C) != 0x5C ||
		!wwIsRepW(a, 8, 0x5C) ||
		wwShHiCarry(a, 8, B_PER_W - 1, 0x5C) != (0x5C >> 1) ||
		!wwIsRepW(a, 8, 0x5C >> 1) ||
		wwShLoCarry(a, 8, B_PER_W - 1, 0x5C >> 1) != 0x5C ||
		!wwIsRepW(a, 8, 0x5C) ||
		(wwShHi(a, 8, B_PER_W), FALSE) ||
			!wwIsRepW(a + 1, 7, 0x5C) || a[0] != 0 ||
		(wwShLo(a, 8, 2 * B_PER_W), FALSE) ||
			!wwIsRepW(a, 6, 0x5C) || a[6] != 0 || a[7] != 0 ||
		(wwShHi(a, 6, 2 * B_PER_W - 1), FALSE) ||
			!wwIsRepW(a + 2, 4, 0x5C >> 1) ||
		(wwShLo(a + 2, 4, 2 * B_PER_W - 1), FALSE) ||
			!wwIsRepW(a + 2, 2, 0x5C))
		return FALSE;
	// все нормально
	return TRUE;
}
