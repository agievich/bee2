/*
*******************************************************************************
\file oid.c
\brief Object identifiers
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2013.02.04
\version 2015.11.09
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/der.h"
#include "bee2/core/mem.h"
#include "bee2/core/oid.h"
#include "bee2/core/str.h"
#include "bee2/core/u32.h"
#include "bee2/core/util.h"

/*
*******************************************************************************
Вспомогательное кодирование
*******************************************************************************
*/

static size_t oidSIDEncode(octet* buf, u32 val)
{
	size_t count = 0;
	u32 t = val;
	// длина BER-кода
	if (val)
		for (; t; t >>= 7, count++);
	else
		++count;
	// кодирование
	if (buf)
	{
		size_t i = count - 1;
		buf[i] = (t = val) & 127;
		while (i--)
			t >>= 7, buf[i] = 128 | (t & 127);
	}
	return count;
}

static size_t oidSIDDecode(char* oid, u32 val)
{
	size_t count = 0;
	u32 t = val;
	// число символов для val
	do
		t /= 10, count++;
	while (t > 0);
	// декодирование
	if (oid)
	{
		size_t i = count - 1;
		oid[i] = (t = val) % 10 + '0';
		while (i--)
			t /= 10, oid[i] = t % 10 + '0';
	}
	return count;
}

/*
*******************************************************************************
Проверка

\remark d1 инициализируется для подавления предупреждения компилятора.
*******************************************************************************
*/

bool_t oidIsValid(const char* oid)
{
	u32 val = 0;
	u32 d1 = 0;
	size_t pos = 0;
	size_t n = 0;
	// pre
	if (!strIsValid(oid))
		return FALSE;
	// цикл по символам oid
	while (1)
	{
		// закончили очередное число?
		if (oid[pos] == '.' || oid[pos] == '\0')
		{
			// пустое число? d1 > 2? d1 < 2 && d2 >= 40?
			// 40 * d1 + d2 не укладывается в u32?
			if (pos == 0 ||
				n == 0 && val > 2 ||
				n == 1 && d1 < 2 && val >= 40 ||
				n == 1 && val > U32_MAX - 40 * d1)
			{
				n = 0;
				break;
			}
			// сохранить d1
			if (n == 0)
				d1 = val;
			// закончить обработку
			n++;
			// конец строки?
			if (oid[pos] == '\0')
				break;
			// к следующему числу (пропустить .)
			oid += ++pos, pos = 0, val = 0;
			continue;
		}
		// недопустимый символ? лидирующий 0? переполнение?
		if (oid[pos] < '0' || oid[pos] > '9' ||
			pos == 1 && oid[0] == '0' ||
			val > U32_MAX / 10 ||
			val == U32_MAX / 10 && (u32)(oid[pos] - '0') > U32_MAX % 10)
		{
			n = 0;
			break;
		}
		// обработать цифру
		val *= 10;
		val += oid[pos] - '0';
		++pos;
	}
	// очистка и выход
	val = d1 = 0, pos = 0;
	return n >= 2;
}

/*
*******************************************************************************
Кодирование
*******************************************************************************
*/

size_t oidToDER(octet der[], const char* oid)
{
	u32 d1;
	u32 val = 0;
	size_t pos = 0;
	size_t count = 0;
	// корректен?
	if (!oidIsValid(oid))
		return SIZE_MAX;
	// pre
	ASSERT(oid[0] == '0' || oid[0] == '1' || oid[0] == '2');
	ASSERT(oid[1] == '.');
	// обработать d1
	d1 = oid[0] - '0';
	oid += 2;
	// цикл по символам oid
	while (1)
	{
		// закончили очередное число?
		if (oid[pos] == '.' || oid[pos] == '\0')
		{
			// закончили d2?
			if (d1 != 3)
				val += 40 * d1, d1 = 3;
			// обработать число
			count += oidSIDEncode(der ? der + count : der, val);
			// конец строки?
			if (oid[pos] == '\0')
				break;
			// к следующему числу
			oid += ++pos, pos = 0, val = 0;
			continue;
		}
		// обработать цифру
		val *= 10;
		val += oid[pos] - '0';
		++pos;
	}
	// обработать длину
	if (der)
		count = derEncode(der, 0x06, der, count);
	else
		count = derEncode(0, 0x06, 0, count);
	// очистка и выход
	d1 = val = 0, pos = 0;
	return count;
}

size_t oidFromDER(char* oid, const octet der[], size_t count)
{
	u32 d1 = 3;
	u32 val = 0;
	size_t pos = 0;
	size_t len = 0;
	u32 tag;
	// некорректный буфер? некорректный тег?
	if (!memIsValid(der, count) || count == 0)
		return SIZE_MAX;
	// найти тег и value
	count = derDecode2(&tag, &der, der, count);
	if (count == SIZE_MAX || tag != 0x06)
		return SIZE_MAX;
	// обработать sid
	for (; pos < count; ++pos)
	{
		// переполнение?
		if (val & 0xFE000000)
			return SIZE_MAX;
		// лидирующий 0?
		if (val == 0 && der[pos] == 128)
			return SIZE_MAX;
		// обработать октет sid
		val <<= 7, val |= (size_t)der[pos] & 127;
		// последний октет sid?
		if ((der[pos] & 128) == 0)
		{
			// первый sid?
			if (d1 == 3)
			{
				if (val < 40)
					d1 = 0;
				else if (val < 80)
					d1 = 1, val -= 40;
				else
					d1 = 2, val -= 80;
				len += oidSIDDecode(oid ? oid + len : oid, d1);
				d1 = 0;
			}
			// добавить ".val"
			oid ? oid[len++] = '.' : len++;
			len += oidSIDDecode(oid ? oid + len : oid, val);
			// к следующему sid
			val = 0;
		}
	}
	// очистка и выход
	d1 = val = 0, pos = 0;
	oid ? oid[len++] = '\0' : len++;
	return len;
}
