/*
*******************************************************************************
\file hex.c
\brief Hexadecimal strings
\project bee2 [cryptographic library]
\author (С) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2015.10.29
\version 2015.11.09
\license This program is released under the GNU General Public License
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/hex.h"
#include "bee2/core/mem.h"
#include "bee2/core/str.h"
#include "bee2/core/util.h"
#include "bee2/core/word.h"

/*
*******************************************************************************
Шестнадцатеричные символы

\todo Функция hexToO() нерегулярна. Поэтому нерегулярны и другие функции
hexToXXX. Регуляризировать.
*******************************************************************************
*/

static octet hexToO(const char* hex)
{
	register octet o;
	ASSERT(memIsValid(hex, 2));
	// определить старшую тетраду
	if ('0' <= *hex && *hex <= '9')
		o = *hex - '0';
	else if ('A' <= *hex && *hex <= 'F')
		o = *hex - 'A' + 10;
	else if ('a' <= *hex && *hex <= 'f')
		o = *hex - 'a' + 10;
	else
		ASSERT(0);
	// к младшей тетраде
	o <<= 4, ++hex;
	// определить младшую тетраду
	if ('0' <= *hex && *hex <= '9')
		o |= *hex - '0';
	else if ('A' <= *hex && *hex <= 'F')
		o |= *hex - 'A' + 10;
	else if ('a' <= *hex && *hex <= 'f')
		o |= *hex - 'a' + 10;
	else
		ASSERT(0);
	// результат
	return o;
}

static const char hex_symbols[] = "0123456789ABCDEF";

static void hexFromO(char* hex, register octet o)
{
	ASSERT(memIsValid(hex, 2));
	hex[0] = hex_symbols[o >> 4];
	hex[1] = hex_symbols[o & 15];
	o = 0;
}

/*
*******************************************************************************
Проверка
*******************************************************************************
*/

bool_t hexIsValid(const char* hex)
{
	if (!strIsValid(hex) || strLen(hex) % 2)
		return FALSE;
	for (; *hex; ++hex)
		if (!('0' <= *hex && *hex <= '9' ||
				'A' <= *hex && *hex <= 'F' ||
				'a' <= *hex && *hex <= 'f'))
			return FALSE;
	return TRUE;
}

/*
*******************************************************************************
Регистр
*******************************************************************************
*/

static const char hex_upper[] = "0123456789ABCDEF";
static const char hex_lower[] = "0123456789abcdef";

void hexUpper(char* hex)
{
	ASSERT(hexIsValid(hex));
	for (; *hex; ++hex)
		*hex = hex_upper[*hex - '0'];
}

void hexLower(char* hex)
{
	ASSERT(hexIsValid(hex));
	for (; *hex; ++hex)
		*hex = hex_lower[*hex - '0'];
}

/*
*******************************************************************************
Сравнения
*******************************************************************************
*/

bool_t SAFE(hexEq)(const void* buf, const char* hex)
{
	register word diff = 0;
	size_t count = strLen(hex);
	ASSERT(hexIsValid(hex));
	ASSERT(memIsValid(buf, count / 2));
	for (; count; count -= 2, hex += 2, buf = (const octet*)buf + 1)
		diff |= *(const octet*)buf ^ hexToO(hex);
	return wordEq(diff, 0);
}

bool_t FAST(hexEq)(const void* buf, const char* hex)
{
	size_t count = strLen(hex);
	ASSERT(hexIsValid(hex));
	ASSERT(memIsValid(buf, count / 2));
	for (; count; count -= 2, hex += 2, buf = (const octet*)buf + 1)
		if (*(const octet*)buf != hexToO(hex))
			return FALSE;
	return TRUE;
}

bool_t SAFE(hexEqRev)(const void* buf, const char* hex)
{
	register word diff = 0;
	size_t count = strLen(hex);
	ASSERT(hexIsValid(hex));
	ASSERT(memIsValid(buf, count / 2));
	hex = hex + count;
	for (; count; count -= 2, buf = (const octet*)buf + 1)
		diff |= *(const octet*)buf ^ hexToO(hex -= 2);
	return wordEq(diff, 0);
}

bool_t FAST(hexEqRev)(const void* buf, const char* hex)
{
	size_t count = strLen(hex);
	ASSERT(hexIsValid(hex));
	ASSERT(memIsValid(buf, count / 2));
	hex = hex + count;
	for (; count; count -= 2, buf = (const octet*)buf + 1)
		if (*(const octet*)buf != hexToO(hex -= 2))
			return FALSE;
	return TRUE;
}

/*
*******************************************************************************
Преобразования
*******************************************************************************
*/

void hexFrom(char* dest, const void* src, size_t count)
{
	ASSERT(memIsDisjoint2(src, count, dest, 2 * count + 1));
	for (; count--; dest += 2, src = (const octet*)src + 1)
		hexFromO(dest, *(const octet*)src);
	*dest = '\0';
}

void hexFromRev(char* dest, const void* src, size_t count)
{
	ASSERT(memIsDisjoint2(src, count, dest, 2 * count + 1));
	dest = dest + 2 * count;
	*dest = '\0';
	for (; count--; src = (const octet*)src + 1)
		hexFromO(dest -= 2, *(const octet*)src);
}

void hexTo(void* dest, const char* src)
{
	size_t count = strLen(src);
	ASSERT(hexIsValid(src));
	ASSERT(memIsDisjoint2(src, count + 1, dest, count / 2));
	for (; count; count -= 2, src += 2, dest = (octet*)dest + 1)
		*(octet*)dest = hexToO(src);
}

void hexToRev(void* dest, const char* src)
{
	size_t count = strLen(src);
	ASSERT(hexIsValid(src));
	ASSERT(memIsDisjoint2(src, count + 1, dest, count / 2));
	src = src + count;
	for (; count; count -= 2, dest = (octet*)dest + 1)
		*(octet*)dest = hexToO(src -= 2);
}
