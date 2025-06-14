/*
*******************************************************************************
\file hex.c
\brief Hexadecimal strings
\project bee2 [cryptographic library]
\created 2015.10.29
\version 2025.06.10
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/core/hex.h"
#include "bee2/core/mem.h"
#include "bee2/core/str.h"
#include "bee2/core/util.h"
#include "bee2/core/word.h"

/*
*******************************************************************************
Таблицы
*******************************************************************************
*/

static const char hex_upper[] = "0123456789ABCDEF";
static const char hex_lower[] = "0123456789abcdef";

static const octet hex_dec_table[256] = {
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
};

/*
*******************************************************************************
Октеты
*******************************************************************************
*/

static octet hexToO(const char* hex)
{
	register octet hi;
	register octet lo;
	ASSERT(memIsValid(hex, 2));
	hi = hex_dec_table[(octet)hex[0]];
	lo = hex_dec_table[(octet)hex[1]];
	ASSERT(hi != 0xFF && lo != 0xFF);
	return hi << 4 | lo;
}

static void hexFromOUpper(char* hex, register octet o)
{
	ASSERT(memIsValid(hex, 2));
	hex[0] = hex_upper[o >> 4];
	hex[1] = hex_upper[o & 15];
	CLEAN(o);
}

static void hexFromOLower(char* hex, register octet o)
{
	ASSERT(memIsValid(hex, 2));
	hex[0] = hex_lower[o >> 4];
	hex[1] = hex_lower[o & 15];
	CLEAN(o);
}

/*
*******************************************************************************
Проверка
*******************************************************************************
*/

bool_t hexIsValid2(const char* hex, size_t len)
{
	if (!memIsValid(hex, len) || len % 2)
		return FALSE;
	for (; len--; ++hex)
		if (hex_dec_table[(octet)*hex] == 0xFF)
			return FALSE;
	return TRUE;
}

bool_t hexIsValid(const char* hex)
{
	return strIsValid(hex) && hexIsValid2(hex, strLen(hex));
}


/*
*******************************************************************************
Регистр
*******************************************************************************
*/

void hexUpper(char* hex)
{
	ASSERT(hexIsValid(hex));
	for (; *hex; hex += 2)
		hexFromOUpper(hex, hexToO(hex));
}

void hexLower(char* hex)
{
	ASSERT(hexIsValid(hex));
	for (; *hex; hex += 2)
		hexFromOLower(hex, hexToO(hex));
}

/*
*******************************************************************************
Сравнения
*******************************************************************************
*/

bool_t SAFE(hexEq2)(const void* buf, const char* hex, size_t len)
{
	register word diff = 0;
	ASSERT(hexIsValid2(hex, len));
	ASSERT(memIsValid(buf, len / 2));
	for (; len; len -= 2, hex += 2, buf = (const octet*)buf + 1)
		diff |= *(const octet*)buf ^ hexToO(hex);
	return wordEq(diff, 0);
}

bool_t FAST(hexEq2)(const void* buf, const char* hex, size_t len)
{
	ASSERT(hexIsValid2(hex, len));
	ASSERT(memIsValid(buf, len / 2));
	for (; len; len -= 2, hex += 2, buf = (const octet*)buf + 1)
		if (*(const octet*)buf != hexToO(hex))
			return FALSE;
	return TRUE;
}

bool_t SAFE(hexEq)(const void* buf, const char* hex)
{
	ASSERT(hexIsValid(hex));
	return SAFE(hexEq2)(buf, hex, strLen(hex));
}

bool_t FAST(hexEq)(const void* buf, const char* hex)
{
	ASSERT(hexIsValid(hex));
	return FAST(hexEq2)(buf, hex, strLen(hex));
}

bool_t SAFE(hexEqRev2)(const void* buf, const char* hex, size_t len)
{
	register word diff = 0;
	ASSERT(hexIsValid(hex));
	ASSERT(memIsValid(buf, len / 2));
	hex = hex + len;
	for (; len; len -= 2, buf = (const octet*)buf + 1)
		diff |= *(const octet*)buf ^ hexToO(hex -= 2);
	return wordEq(diff, 0);
}

bool_t FAST(hexEqRev2)(const void* buf, const char* hex, size_t len)
{
	ASSERT(hexIsValid(hex));
	ASSERT(memIsValid(buf, len / 2));
	hex = hex + len;
	for (; len; len -= 2, buf = (const octet*)buf + 1)
		if (*(const octet*)buf != hexToO(hex -= 2))
			return FALSE;
	return TRUE;
}

bool_t SAFE(hexEqRev)(const void* buf, const char* hex)
{
	ASSERT(hexIsValid(hex));
	return SAFE(hexEqRev2)(buf, hex, strLen(hex));
}

bool_t FAST(hexEqRev)(const void* buf, const char* hex)
{
	ASSERT(hexIsValid(hex));
	return FAST(hexEqRev2)(buf, hex, strLen(hex));
}

/*
*******************************************************************************
Кодирование
*******************************************************************************
*/

void hexFrom(char* dest, const void* src, size_t count)
{
	ASSERT(memIsDisjoint2(src, count, dest, 2 * count + 1));
	for (; count--; dest += 2, src = (const octet*)src + 1)
		hexFromOUpper(dest, *(const octet*)src);
	*dest = '\0';
}

void hexFromRev(char* dest, const void* src, size_t count)
{
	ASSERT(memIsDisjoint2(src, count, dest, 2 * count + 1));
	dest = dest + 2 * count;
	*dest = '\0';
	for (; count--; src = (const octet*)src + 1)
		hexFromOUpper(dest -= 2, *(const octet*)src);
}

void hexTo2(void* dest, const char* src, size_t len)
{
	ASSERT(hexIsValid2(src, len));
	ASSERT(memIsDisjoint2(src, len + 1, dest, len / 2));
	for (; len; len -= 2, src += 2, dest = (octet*)dest + 1)
		*(octet*)dest = hexToO(src);
}

void hexTo(void* dest, const char* src)
{
	ASSERT(hexIsValid(src));
	hexTo2(dest, src, strLen(src));
}

void hexToRev2(void* dest, const char* src, size_t len)
{
	ASSERT(hexIsValid2(src, len));
	ASSERT(memIsDisjoint2(src, len + 1, dest, len / 2));
	src = src + len;
	for (; len; len -= 2, dest = (octet*)dest + 1)
		*(octet*)dest = hexToO(src -= 2);
}

void hexToRev(void* dest, const char* src)
{
	ASSERT(hexIsValid(src));
	hexToRev2(dest, src, strLen(src));
}
