/*
*******************************************************************************
\file u16_test.c
\brief Tests for operations on 16-bit words
\project bee2/test
\created 2017.01.11
\version 2025.07.24
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <bee2/core/u16.h>

/*
*******************************************************************************
Тестирование
*******************************************************************************
*/

bool_t u16Test()
{
	u16 w = 0x0102;
	u16 a[2] = {0x0102, 0x0201};
	octet b[4];
	// rot
	if (u16RotHi(w, 1) != 0x0204 ||
		u16RotHi(w, 4) != 0x1020 ||
		u16RotHi(w, 8) != 0x0201 ||
		u16RotLo(u16RotHi(w, 7), 7) != w ||
		u16RotLo(u16RotHi(w, 9), 9) != w ||
		u16RotLo(u16RotHi(w, 13), 13) != w)
		return FALSE;
	// reverse
	if (u16Rev(w) != a[1] || u16Rev(a[1]) != w)
		return FALSE;
	u16Rev2(a, 2), u16Rev2(a, 2);
	if (a[0] != w || a[1] != u16Rev(w))
		return FALSE;
	// bit reverse
	if (u16Bitrev(w) != 0x4080|| u16Bitrev(u16Bitrev(w)) != w)
		return FALSE;
	// weight / parity
	if (u16Weight(0) != 0 || u16Parity(0) || !u16Parity(1) ||
		u16Weight(0xA001) != 3 || !u16Parity(0xA001) ||
		u16Weight(0xFFFF) != 16 || u16Parity(0xFFFF) ||
		u16Weight(0xFFF8) != 13)
		return FALSE;
	// CTZ / CLZ
	if (u16CTZ(0) != 16 || FAST(u16CTZ)(0) != 16 ||
		u16CLZ(0) != 16 || FAST(u16CLZ)(0) != 16 ||
		u16CTZ(1) != 0 || FAST(u16CTZ)(1) != 0 ||
		u16CLZ(1) != 15 || FAST(u16CLZ)(1) != 15 ||
		u16CTZ(0xFFF8) != 3 || FAST(u16CTZ)(0xFFF8) != 3 ||
		u16CLZ(0xFFF8) != 0 || FAST(u16CLZ)(0xFFF8) != 0
		)
		return FALSE;
	// shuffle
	if (u16Deshuffle(0) != 0 || u16Deshuffle(1) != 1 ||
		u16Deshuffle(2) != 0x0100 ||
		u16Deshuffle(0xAAAA) != 0xFF00 || 
		u16Shuffle(u16Deshuffle(0x3210)) != 0x3210 ||
		u16Deshuffle(u16Shuffle(0xDCBA)) != 0xDCBA)
		return FALSE;
	// negInv
	if (u16NegInv(1) != U16_MAX ||
		u16NegInv(5) != 13107 || u16NegInv(13107) != 5)
		return FALSE;
	// from / to
	u16To(b, 3, a), u16From(a, b, 3);
	if (a[0] != w || a[1] != 0x0001)
		return FALSE;
	// все нормально
	return TRUE;
}
