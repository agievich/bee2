/*
*******************************************************************************
\file str_test.c
\brief Tests for strings
\project bee2/test
\created 2017.01.12
\version 2025.04.18
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
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
	if (strIsValid(0) || !strIsNullOrValid(0) || 
		!strIsValid(str) ||
		strLen(str) + 1 != sizeof(str))
		return FALSE;
	// cmp
	strCopy(buf, str);
	if (strCmp(buf, str) != 0 || !strEq(buf, str))
		return FALSE;
	// props
	if (!strIsNumeric(str) ||
		strIsNumeric("1234?") ||
		!strIsAlphanumeric(str) ||
		strIsAlphanumeric("1234?") || 
		!strIsAlphanumeric("1234aAz") ||
		!strIsPrintable(str) ||
		!strIsPrintable("12?=:") ||
		strIsPrintable("12&=:") ||
		strIsPrintable("1@2=:") ||
		!strContains(str, '2') ||
		strContains(str, '7') ||
		!strStartsWith(str, "12") ||
		strStartsWith(str, "13") ||
		!strEndsWith(str, "56") ||
		strEndsWith(str, "1234567") ||
		strEndsWith(str, "57"))
		return FALSE;
	// rev
	strRev(str);
	if (!strEq(str, "654321"))
		return FALSE;
	strCopy(str, "1"), strRev(str);
	if (!strEq(str, "1"))
		return FALSE;
	strCopy(str, "12"), strRev(str);
	if (!strEq(str, "21"))
		return FALSE;
	strCopy(str, "123"), strRev(str);
	if (!strEq(str, "321"))
		return FALSE;
	// все нормально
	return TRUE;
}
