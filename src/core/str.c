/*
*******************************************************************************
\file str.c
\brief Strings
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2013.02.04
\version 2015.11.26
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/mem.h"
#include "bee2/core/str.h"
#include "bee2/core/util.h"

/*
*******************************************************************************
Проверка
*******************************************************************************
*/

bool_t strIsValid(const char* str)
{
	return memIsValid(str, strLen(str));
}

/*
*******************************************************************************
Поиск
*******************************************************************************
*/

bool_t strStartsWith(const char* str, const char* prefix)
{
	ASSERT(strIsValid(str));
	ASSERT(strIsValid(prefix));
	for(; *prefix; ++prefix, ++str)
		if (*str != *prefix)
			return FALSE;
	return TRUE;
}

bool_t strEndsWith(const char* str, const char* suffix)
{
	ASSERT(strIsValid(str));
	ASSERT(strIsValid(suffix));
	if (strLen(str) < strLen(suffix))
		return FALSE;
	for(str += strLen(str) - strLen(suffix); *suffix; ++suffix, ++str)
		if (*str != *suffix)
			return FALSE;
	return TRUE;
}

/*
*******************************************************************************
Операции
*******************************************************************************
*/

void strRev(char* str)
{
	size_t i, j;
	ASSERT(strIsValid(str));
	for (i = 0, j = strLen(str); i < j;)
	{
		str[i] ^= str[--j];
		str[j] ^= str[i];
		str[i++] ^= str[j];
	}
}
