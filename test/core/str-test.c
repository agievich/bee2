/*
*******************************************************************************
\file str-test.c
\brief Tests for strings
\project bee2/test
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2017.01.12
\version 2017.01.12
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include <bee2/core/str.h>

/*
*******************************************************************************
Тестирование
*******************************************************************************
*/

bool_t strTest()
{
	char str[] = "123456";
	char buf[16];
	// len
	if (!strIsValid(str) ||
		strLen(str) + 1 != sizeof(str) ||
		strLen2(str, sizeof(str)) != strLen(str) ||
		strLen2(str, sizeof(str) + 1) != strLen(str))
		return FALSE;
	// cmp
	strCopy(buf, str);
	if (strCmp(buf, str) != 0 || !strEq(buf, str))
		return FALSE;
	// props
	if (!strIsAlphanumeric(str) ||
		strIsAlphanumeric("1234?") ||
		!strStartsWith(str, "12") ||
		strStartsWith(str, "13") ||
		!strEndsWith(str, "56") ||
		strEndsWith(str, "57"))
		return FALSE;
	// rev
	strRev(str);
	if (!strEq(str, "654321"))
		return FALSE;
	// все нормально
	return TRUE;
}
