/*
*******************************************************************************
\file word_test.c
\brief Tests for operations on machine words
\project bee2/test
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2015.05.22
\version 2017.01.11
\license This program is released under the GNU General Public License
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include <bee2/core/word.h>

/*
*******************************************************************************
Тестирование
*******************************************************************************
*/

bool_t wordTest()
{
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
		FAST(wordCTZ)(0) != B_PER_W ||
		wordCLZ(0) != B_PER_W ||
		FAST(wordCLZ)(0) != B_PER_W ||
		wordCTZ(1) != 0 ||
		FAST(wordCTZ)(1) != 0 ||
		wordCLZ(1) != B_PER_W - 1 ||
		FAST(wordCLZ)(1) != B_PER_W - 1 ||
		wordCTZ(0xFFF8) != 3 ||
		FAST(wordCTZ)(0xFFF8) != 3 ||
		wordCLZ(0xFFF8) != B_PER_W - 16 ||
		FAST(wordCLZ)(0xFFF8) != B_PER_W - 16 
#if (B_PER_W >= 32)
		||
		wordCTZ(0x7FFFE000) != 13 ||
		FAST(wordCTZ)(0x7FFFE000) != 13 ||
		wordCLZ(0x7FFFE000) != B_PER_W - 31 ||
		FAST(wordCLZ)(0x7FFFE000) != B_PER_W - 31
#endif
#if (B_PER_W == 64)
		||
		wordCTZ(0x0000003FFDDF8000) != 15 ||
		FAST(wordCTZ)(0x0000003FFDDF8000) != 15 ||
		wordCLZ(0x0000003FFDDF8000) != 26 ||
		FAST(wordCLZ)(0x0000003FFDDF8000) != 26
#endif
		)
		return FALSE;
	// все нормально
	return TRUE;
}
