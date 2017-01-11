/*
*******************************************************************************
\file u16-test.c
\brief Tests for operations on 16-bit words
\project bee2/test
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2017.01.11
\version 2017.01.11
\license This program is released under the GNU General Public License
version 3. See Copyright Notices in bee2/info.h.
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
	// reverse
	if (u16Rev(w) != a[1] || u16Rev(a[1]) != w)
		return FALSE;
	u16Rev2(a, 2), u16Rev2(a, 2);
	if (a[0] != w || a[1] != u16Rev(w))
		return FALSE;
	// rot
	if (u16RotHi(w, 1) != 0x0204 ||
		u16RotHi(w, 4) != 0x1020 || 
		u16RotHi(w, 8) != 0x0201 ||
		u16RotLo(u16RotHi(w, 7), 7) != w ||
		u16RotLo(u16RotHi(w, 9), 9) != w ||
		u16RotLo(u16RotHi(w, 13), 13) != w)
		return FALSE;
	// from / to
	u16To(b, 3, a), u16From(a, b, 3);
	if (a[0] != w || a[1] != 0x0001)
		return FALSE;
	// все нормально
	return TRUE;
}
