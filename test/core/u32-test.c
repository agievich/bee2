/*
*******************************************************************************
\file u32-test.c
\brief Tests for operations on 32-bit words
\project bee2/test
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2017.01.11
\version 2017.01.11
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
	// reverse
	if (u32Rev(w) != a[1] || u32Rev(a[1]) != w)
		return FALSE;
	u32Rev2(a, 2), u32Rev2(a, 2);
	if (a[0] != w || a[1] != u32Rev(w))
		return FALSE;
	// rot
	if (u32RotHi(w, 1) != 0x02040608 ||
		u32RotHi(w, 4) != 0x10203040 || 
		u32RotHi(w, 8) != 0x02030401 ||
		u32RotLo(u32RotHi(w, 7), 7) != w ||
		u32RotLo(u32RotHi(w, 19), 19) != w ||
		u32RotLo(u32RotHi(w, 23), 23) != w)
		return FALSE;
	// from / to
	u32To(b, 7, a), u32From(a, b, 7);
	if (a[0] != w || a[1] != 0x00030201)
		return FALSE;
	// все нормально
	return TRUE;
}
