/*
*******************************************************************************
\file str.c
\brief Strings
\project bee2 [cryptographic library]
\author (С) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2013.02.04
\version 2014.09.17
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

bool_t strIsHex(const char* str)
{
	ASSERT(strIsValid(str));
	for (; *str; ++str)
	{
		if (*str >= '0' && *str <= '9' ||
			*str >= 'a' && *str <= 'f' ||
			*str >= 'A' && *str <= 'F')
			continue;
		return FALSE;
	}
	return TRUE;
}
