/*
*******************************************************************************
\file u32_test.c
\brief Tests for operations on 32-bit words
\project bee2/test
\created 2017.01.11
\version 2019.07.08
\license This program is released under the GNU General Public License
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include <bee2/core/u32.h>

/*
*******************************************************************************
Тестирование
*******************************************************************************
*/

bool_t u32Test()
{
	u32 w = 0x01020304;
	u32 a[2] = {0x01020304, 0x04030201};
	octet b[8];
	// rot
	if (u32RotHi(w, 1) != 0x02040608 ||
		u32RotHi(w, 4) != 0x10203040 ||
		u32RotHi(w, 8) != 0x02030401 ||
		u32RotLo(u32RotHi(w, 7), 7) != w ||
		u32RotLo(u32RotHi(w, 19), 19) != w ||
		u32RotLo(u32RotHi(w, 23), 23) != w)
		return FALSE;
	// reverse
	if (u32Rev(w) != a[1] || u32Rev(a[1]) != w)
		return FALSE;
	u32Rev2(a, 2), u32Rev2(a, 2);
	if (a[0] != w || a[1] != u32Rev(w))
		return FALSE;
	// weight / parity
	if (u32Weight(0) != 0 || u32Parity(0) || !u32Parity(1) ||
		u32Weight(0xA001) != 3 || !u32Parity(0xA001) ||
		u32Weight(0xFFFF) != 16 || u32Parity(0xFFFF) ||
		u32Weight(0xF000A001) != 7 || !u32Parity(0xF000A001) ||
		u32Weight(0x0E00A001) != 6 || u32Parity(0x0E00A001) ||
		u32Weight(0xFFFFFFFF) != 32 || u32Parity(0xFFFFFFFF))
		return FALSE;
	// CTZ / CLZ
	if (SAFE(u32CTZ)(0) != 32 || FAST(u32CTZ)(0) != 32 ||
		SAFE(u32CLZ)(0) != 32 || FAST(u32CLZ)(0) != 32 ||
		SAFE(u32CTZ)(1) != 0 ||	FAST(u32CTZ)(1) != 0 ||
		SAFE(u32CLZ)(1) != 31 || FAST(u32CLZ)(1) != 31 ||
		SAFE(u32CTZ)(0xFFF8) != 3 || FAST(u32CTZ)(0xFFF8) != 3 ||
		SAFE(u32CLZ)(0xFFF8) != 16 || FAST(u32CLZ)(0xFFF8) != 16 ||
		SAFE(u32CTZ)(0x7FFFE000) != 13 || FAST(u32CTZ)(0x7FFFE000) != 13 ||
		SAFE(u32CLZ)(0x7FFFE000) != 1 || FAST(u32CLZ)(0x7FFFE000) != 1)
		return FALSE;
	// shuffle
	if (u32Deshuffle(0) != 0 || u32Deshuffle(1) != 1 || 
		u32Deshuffle(2) != 0x00010000 ||
		u32Deshuffle(0xAAAAAAAA) != 0xFFFF0000 ||
		u32Shuffle(u32Deshuffle(0x76543210)) != 0x76543210 ||
		u32Deshuffle(u32Shuffle(0x10FEDCBA)) != 0x10FEDCBA)
		return FALSE;
	// negInv
	if (u32NegInv(1) != U32_MAX || 
		u32NegInv(5) != 858993459 || u32NegInv(858993459) != 5)
		return FALSE;
	// from / to
	u32To(b, 7, a), u32From(a, b, 7);
	if (a[0] != w || a[1] != 0x00030201)
		return FALSE;
	// все нормально
	return TRUE;
}
