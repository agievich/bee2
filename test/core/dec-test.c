/*
*******************************************************************************
\file dec-test.c
\brief Tests for decimal strings
\project bee2/test
\author (С) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2015.11.09
\version 2015.11.11
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include <bee2/core/dec.h>
#include <bee2/core/str.h>
#include <bee2/core/u32.h>
#ifdef U64_SUPPORT
	#include <bee2/core/u64.h>
#endif

/*
*******************************************************************************
Тестирование
*******************************************************************************
*/

bool_t decTest()
{
	char dec[21];
	// u32
	decFromU32(dec, 10, U32_MAX);
	if (!strEq(dec, "4294967295") ||
		decToU32(dec) != U32_MAX)
		return FALSE;
#ifdef U64_SUPPORT
	// u64
	decFromU64(dec, 20, U64_MAX);
	if (!strEq(dec, "18446744073709551615") ||
		decToU64(dec) != U64_MAX)
		return FALSE;
#endif
	// check digits
	if (decLuhnCalc("7992739871") != '3' ||
		!decLuhnVerify("79927398713") ||
		decLuhnVerify("69927398713") ||
		decDammCalc("572") != '4' ||
		!decDammVerify("5724") ||
		decDammVerify("5274"))
		return FALSE;
	// все нормально
	return TRUE;
}
