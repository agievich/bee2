/*
*******************************************************************************
\file str.c
\brief Strings
\project bee2 [cryptographic library]
\author (С) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2013.02.04
\version 2015.11.09
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

void strRev(char* str)
{
	register size_t i;
	register size_t j;
	ASSERT(strIsValid(str));
	for (i = 0, j = strLen(str); i < j;)
	{
		str[i] ^= str[--j];
		str[j] ^= str[i];
		str[i++] ^= str[j];
	}
}
