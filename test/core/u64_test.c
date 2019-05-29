/*
*******************************************************************************
\file u64_test.c
\brief Tests for operations on 64-bit words
\project bee2/test
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2017.01.11
\version 2017.01.11
\license This program is released under the GNU General Public License
version 3. See Copyright Notices in bee2/info.h.
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
	// reverse
	if (u64Rev(w) != a[1] || u64Rev(a[1]) != w)
		return FALSE;
	u64Rev2(a, 2), u64Rev2(a, 2);
	if (a[0] != w || a[1] != u64Rev(w))
		return FALSE;
	// rot
	if (u64RotHi(w, 1) != 0x020406080A0C0E10 ||
		u64RotHi(w, 4) != 0x1020304050607080 || 
		u64RotHi(w, 8) != 0x0203040506070801 ||
		u64RotLo(u64RotHi(w, 7), 7) != w ||
		u64RotLo(u64RotHi(w, 19), 19) != w ||
		u64RotLo(u64RotHi(w, 43), 43) != w)
		return FALSE;
	// from / to
	u64To(b, 15, a), u64From(a, b, 15);
	if (a[0] != w || a[1] != 0x0007060504030201)
		return FALSE;
#endif
	// все нормально
	return TRUE;
}
