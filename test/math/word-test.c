/*
*******************************************************************************
\file word-test.c
\brief Tests for operations on machine words
\project bee2/test
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2015.05.22
\version 2015.10.28
\license This program is released under the GNU General Public License
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include <bee2/core/u16.h>
#include <bee2/core/u32.h>
#ifdef U64_SUPPORT
	#include <bee2/core/u64.h>
#endif
#include <bee2/core/word.h>

/*
*******************************************************************************
Тестирование
*******************************************************************************
*/

bool_t wordTest()
{
	u16 a = 0x0102;
	u32 b = 0x01020304;
#ifdef U64_SUPPORT
	u64 c = 0x0102030405060708;
#endif
	// reverse
	if (u16Rev(a) != 0x0201 ||
		u16Rev(u16Rev(a)) != a ||
		u32Rev(b) != 0x04030201 ||
		u32Rev(u32Rev(b)) != b
#ifdef U64_SUPPORT
		||
		u64Rev(c) != 0x0807060504030201 ||
		u64Rev(u64Rev(c)) != c
#endif
	)
		return FALSE;
	// weight / parity
	if (wordWeight(0) != 0 ||
		wordParity(0) ||
		!wordParity(1) ||
		wordWeight(0xA001) != 3 ||
		!wordParity(0xA001) ||
		wordWeight(0xFFFF) != 16 ||
		wordParity(0xFFFF) 
#if (B_PER_W >= 32)
		||
		wordWeight(0xF000A001) != 7 ||
		!wordParity(0xF000A001) ||
		wordWeight(0x0E00A001) != 6 ||
		wordParity(0x0E00A001) ||
		wordWeight(0xFFFFFFFF) != 32 ||
		wordParity(0xFFFFFFFF)
#endif
#if (B_PER_W == 64)
		||
		wordWeight(0xAA0180EEF000A001) != 19 ||
		!wordParity(0xAA0180EEF000A001) ||
		wordWeight(0x730085060E00A001) != 16 ||
		wordParity(0x730085060E00A001) ||
		wordWeight(0xFFFFFFFFFFFFFFFF) != 64 ||
		wordParity(0xFFFFFFFFFFFFFFFF)
#endif
	)
		return FALSE;
	// CTZ / CLZ
	if (wordCTZ(0) != B_PER_W ||
		wordCLZ(0) != B_PER_W ||
		wordCTZ(1) != 0 ||
		wordCLZ(1) != B_PER_W - 1 ||
		wordCTZ(0xFFF8) != 3 ||
		wordCLZ(0xFFF8) != B_PER_W - 16
#if (B_PER_W >= 32)
		||
		wordCTZ(0x7FFFE000) != 13 ||
		wordCLZ(0x7FFFE000) != B_PER_W - 31
#endif
#if (B_PER_W == 64)
		||
		wordCTZ(0x0000003FFDDF8000) != 15 ||
		wordCLZ(0x0000003FFDDF8000) != 26
#endif
		)
		return FALSE;
	// все нормально
	return TRUE;
}
