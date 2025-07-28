/*
*******************************************************************************
\file u64_test.c
\brief Tests for operations on 64-bit words
\project bee2/test
\created 2017.01.11
\version 2025.07.24
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <bee2/core/u64.h>

/*
*******************************************************************************
Тестирование
*******************************************************************************
*/

bool_t u64Test()
{
#ifdef U64_SUPPORT
	u64 w = 0x0102030405060708;
	u64 a[2] = {0x0102030405060708, 0x0807060504030201};
	octet b[16];
	// rot
	if (u64RotHi(w, 1) != 0x020406080A0C0E10 ||
		u64RotHi(w, 4) != 0x1020304050607080 ||
		u64RotHi(w, 8) != 0x0203040506070801 ||
		u64RotLo(u64RotHi(w, 7), 7) != w ||
		u64RotLo(u64RotHi(w, 19), 19) != w ||
		u64RotLo(u64RotHi(w, 43), 43) != w)
		return FALSE;
	// reverse
	if (u64Rev(w) != a[1] || u64Rev(a[1]) != w)
		return FALSE;
	u64Rev2(a, 2), u64Rev2(a, 2);
	if (a[0] != w || a[1] != u64Rev(w))
		return FALSE;
	// bit reverse
	if (u64Bitrev(w) != 0x10E060A020C04080 || u64Bitrev(u64Bitrev(w)) != w)
		return FALSE;
	// weight / parity
	if (u64Weight(0) != 0 || u64Parity(0) || !u64Parity(1) ||
		u64Weight(0xA001) != 3 || !u64Parity(0xA001) ||
		u64Weight(0xFFFF) != 16 || u64Parity(0xFFFF) ||
		u64Weight(0xF000A001) != 7 || !u64Parity(0xF000A001) ||
		u64Weight(0x0E00A001) != 6 || u64Parity(0x0E00A001) ||
		u64Weight(0xFFFFFFFF) != 32 || u64Parity(0xFFFFFFFF) ||
		u64Weight(0xAA0180EEF000A001) != 19 ||
		!u64Parity(0xAA0180EEF000A001) ||
		u64Weight(0x730085060E00A001) != 16 ||
		u64Parity(0x730085060E00A001) ||
		u64Weight(0xFFFFFFFFFFFFFFFF) != 64 ||
		u64Parity(0xFFFFFFFFFFFFFFFF))
		return FALSE;
	// CTZ / CLZ
	if (u64CTZ(0) != 64 || FAST(u64CTZ)(0) != 64 ||
		u64CLZ(0) != 64 || FAST(u64CLZ)(0) != 64 ||
		u64CTZ(1) != 0 || FAST(u64CTZ)(1) != 0 ||
		u64CLZ(1) != 63 || FAST(u64CLZ)(1) != 63 ||
		u64CTZ(0xFFF8) != 3 || FAST(u64CTZ)(0xFFF8) != 3 ||
		u64CLZ(0xFFF8) != 48 || FAST(u64CLZ)(0xFFF8) != 48 ||
		u64CTZ(0x7FFFE000) != 13 || FAST(u64CTZ)(0x7FFFE000) != 13 ||
		u64CLZ(0x7FFFE000) != 33 || FAST(u64CLZ)(0x7FFFE000) != 33 ||
		u64CTZ(0x0000003FFDDF8000) != 15 ||
		FAST(u64CTZ)(0x0000003FFDDF8000) != 15 ||
		u64CLZ(0x0000003FFDDF8000) != 26 ||
		FAST(u64CLZ)(0x0000003FFDDF8000) != 26)
		return FALSE;
	// shuffle
	if (u64Deshuffle(0) != 0 || u64Deshuffle(1) != 1 ||
		u64Deshuffle(2) != 0x0000000100000000 ||
		u64Deshuffle(0xAAAAAAAAAAAAAAAA) != 0xFFFFFFFF00000000 ||
		u64Shuffle(u64Deshuffle(0xFEDCBA9876543210)) != 0xFEDCBA9876543210 ||
		u64Deshuffle(u64Shuffle(0x9876543210FEDCBA)) != 0x9876543210FEDCBA)
		return FALSE;
	// negInv
	if (u64NegInv(1) != U64_MAX ||
		u64NegInv(5) != 3689348814741910323 || 
		u64NegInv(3689348814741910323) != 5)
		return FALSE;
	// from / to
	u64To(b, 15, a), u64From(a, b, 15);
	if (a[0] != w || a[1] != 0x0007060504030201)
		return FALSE;
	// shuffle (константы crypto/bash-f)
	w = 0x3BF5080AC8BA94B1;
	w = u64Deshuffle(w);
	if ((u32)w != 0x5F008465 || (u32)(w >> 32) != 0x7C23AF8C)
		return FALSE;
#endif
	// все нормально
	return TRUE;
}
