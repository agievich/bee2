/*
*******************************************************************************
\file dec.c
\brief Decimal strings
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2015.11.09
\version 2015.11.11
\license This program is released under the GNU General Public License
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/dec.h"
#include "bee2/core/mem.h"
#include "bee2/core/str.h"
#include "bee2/core/util.h"
#include "bee2/core/word.h"

/*
*******************************************************************************
Проверка
*******************************************************************************
*/

bool_t decIsValid(const char* dec)
{
	if (!strIsValid(dec))
		return FALSE;
	for (; *dec; ++dec)
		if (*dec < '0' || *dec > '9')
			return FALSE;
	return TRUE;
}

/*
*******************************************************************************
Характеристики
*******************************************************************************
*/

size_t decCLZ(const char* dec)
{
	register size_t clz = 0;
	ASSERT(decIsValid(dec));
	while (*dec == '0')
		++dec, ++clz;
	return clz;
}

/*
*******************************************************************************
Преобразования
*******************************************************************************
*/

void decFromU32(char* dec, size_t count, register u32 num)
{
	ASSERT(memIsValid(dec, count + 1));
	dec[count] = '\0';
	while (count--)
		dec[count] = num % 10 + '0', num /= 10;
}

u32 decToU32(const char* dec)
{
	register u32 num = 0;
	ASSERT(decIsValid(dec));
	while (*dec)
		num *= 10, num += *dec - '0', ++dec;
	return num;
}

#ifdef U64_SUPPORT

void decFromU64(char* dec, size_t count, register u64 num)
{
	ASSERT(memIsValid(dec, count + 1));
	dec[count] = '\0';
	while (count--)
		dec[count] = num % 10 + '0', num /= 10;
}

u64 decToU64(const char* dec)
{
	register u64 num = 0;
	ASSERT(decIsValid(dec));
	while (*dec)
		num *= 10, num += *dec - '0', ++dec;
	return num;
}

#endif // U64_SUPPORT

/*
*******************************************************************************
Контрольные цифры
*******************************************************************************
*/

static const word luhn_table[10] = {0, 2, 4, 6, 8, 1, 3, 5, 7, 9};

char decLuhnCalc(const char* dec)
{
	register word cd = 0;
	size_t i;
	ASSERT(decIsValid(dec));
	for (i = strLen(dec); i--;) 
	{
		cd += luhn_table[dec[i] - '0'];
		if (i)
			cd += dec[--i] - '0';
	}
	cd %= 10, cd = ((cd << 3) + cd) % 10;
	return (char)cd + '0';
}

bool_t decLuhnVerify(const char* dec)
{
	register word cd = 0;
	size_t i;
	ASSERT(decIsValid(dec));
	for (i = strLen(dec); i--;) 
	{
		cd += dec[i] - '0';
		if (i)
			cd += luhn_table[dec[--i] - '0'];
	}
	cd %= 10;
	return wordEq(cd, 0);
}

static const char damm_table[10][10] = {
	{0, 3, 1, 7, 5, 9, 8, 6, 4, 2},
	{7, 0, 9, 2, 1, 5, 4, 8, 6, 3},
	{4, 2, 0, 6, 8, 7, 1, 3, 5, 9},
	{1, 7, 5, 0, 9, 8, 3, 4, 2, 6},
	{6, 1, 2, 3, 0, 4, 5, 9, 7, 8},
	{3, 6, 7, 4, 2, 0, 9, 5, 8, 1},
	{5, 8, 6, 9, 7, 2, 0, 1, 3, 4},
	{8, 9, 4, 5, 3, 6, 2, 0, 1, 7},
	{9, 4, 3, 8, 6, 1, 7, 2, 0, 5},
	{2, 5, 8, 1, 4, 3, 6, 7, 9, 0},
};

char decDammCalc(const char* dec)
{
	register char cd = 0;
	ASSERT(decIsValid(dec));
	for (; *dec; ++dec)
		cd = damm_table[(octet)cd][(octet)(*dec - '0')];
	return cd + '0';
}

bool_t decDammVerify(const char* dec)
{
	return decDammCalc(dec) == '0';
}
