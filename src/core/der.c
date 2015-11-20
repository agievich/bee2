/*
*******************************************************************************
\file der.c
\brief Distinguished Encoding Rules
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2014.04.21
\version 2015.08.27
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/der.h"
#include "bee2/core/mem.h"
#include "bee2/core/util.h"

/*
*******************************************************************************
Поле T (тег)
*******************************************************************************
*/

static size_t derLenT(u32 tag)
{
	size_t t_count = 1;
	u32 t;
	// короткий тег (представляется одним октетом)?
	if ((tag & 31) < 31)
	{
		// старшие октеты tag ненулевые?
		if (tag >> 8 != 0)
			return SIZE_MAX;
	}
	// длинный тег
	else
	{
		t = tag >> 8;
		// длинный тег для маленького номера?
		if (t < 31)
			return SIZE_MAX;
		// число октетов для представления tag
		for (; t; t >>= 7, t_count++);
	}
	return t_count;
}

static void derEncodeT(octet der[], u32 tag, size_t t_count)
{
	ASSERT(memIsValid(der, t_count));
	ASSERT(t_count >= 1);
	// короткая форма?
	if (t_count == 1)
	{
		ASSERT((tag & 31) < 31);
		ASSERT(tag >> 8 == 0);
		der[0] = (octet)tag;
	}
	// длинная форма
	else
	{
		ASSERT((tag & 31) == 31);
		tag >>= 8;
		ASSERT(tag >= 31);
		der[--t_count] = (octet)(tag & 127);
		while (--t_count)
			tag >>= 7, der[t_count] = (octet)(tag & 127 | 128);
		ASSERT(tag == 0);
	}
}

static size_t derDecodeT(u32* tag, const octet der[], size_t count)
{
	size_t t_count = 1;
	u32 t;
	ASSERT(memIsValid(der, count));
	// первый октет
	if (count < 1)
		return SIZE_MAX;
	// короткий тег?
	if ((der[0] & 31) < 31)
		t = der[0];
	// длинный тег
	else
	{
		t = 0;
		// лидирующий ноль? номер < 31?
		if (count < 2 || der[1] == 128 || der[1] < 31)
			return SIZE_MAX;
		while (1)
		{
			// переполнение?
			if (t * 128 + der[t_count] % 128 >= ((u32)1 << 24))
				return SIZE_MAX;
			// обработать октет тега
			t = t * 128 + der[t_count] % 128;
			// последний октет?
			if (der[t_count] < 128)
				break;
			// к следующему октету
			++t_count;
			// не хватает буфера?
			if (count < t_count)
				return SIZE_MAX;
		}
		t <<= 8, t |= der[0];
	}
	// возврат 
	if (tag)
	{
		ASSERT(memIsValid(tag, 4));
		*tag = t;		
	}
	return t_count;
}

/*
*******************************************************************************
Поле L (длина)
*******************************************************************************
*/

static size_t derLenL(size_t len)
{
	size_t l_count = 1;
	// длинная форма (r | 128) || o_{r - 1} ||...|| o_0?
	if (len >= 128)
		for (; len; len >>= 8, ++l_count);
	return l_count;
}

static size_t derEncodeL(octet der[], size_t len, size_t l_count)
{
	ASSERT(memIsValid(der, l_count));
	// короткая форма?
	if (len < 128)
	{
		ASSERT(l_count == 1);
		der[0] = (octet)len;
	}
	// длинная форма
	else
	{
		size_t r = l_count - 1;
		ASSERT(r >= 1);
		der[0] = (octet)(r | 128);
		for (; r; der[r--] = (octet)len, len >>= 8);
		ASSERT(len == 0);
	}
	return l_count;
}

static size_t derDecodeL(size_t* len, const octet der[], size_t count)
{
	size_t l_count = 1;
	size_t l;
	// не хватает буфера? неявная форма (0x80)? запрещенный октет (0xFF)?
	if (count < l_count || der[0] == 128 || der[0] == 255)
		return SIZE_MAX;
	// короткая форма?
	if (der[0] < 128)
		l = der[0];
	// длинная форма
	else
	{
		size_t r = der[0] - 128;
		l_count += r;
		// не хватает буфера? переполнение?
		// нулевой старший октет кода длины? длина меньше 128?
		if (count < l_count || 
			r > O_PER_S ||
			der[1] == 0 || 
			r == 1 && der[1] < 128)
			return SIZE_MAX;
		for (l = 0, r = 1; r < l_count; ++r)
			 l <<= 8, l |= (size_t)der[r];
		// переполнение?
		if (l == SIZE_MAX)
			return SIZE_MAX;
	}
	// возврат
	if (len)
	{
		ASSERT(memIsValid(len, sizeof(size_t)));
		*len = l;
	}
	return l_count;
}

/*
*******************************************************************************
Кодирование
*******************************************************************************
*/

size_t derEncode(octet der[], u32 tag, const void* value, size_t len)
{
	size_t t_count;
	size_t l_count;
	// t_count <- len(T)
	t_count = derLenT(tag);
	if (t_count == SIZE_MAX)
		return SIZE_MAX;
	// l_count <- len(L)
	l_count = derLenL(len);
	if (l_count == SIZE_MAX)
		return SIZE_MAX;
	// кодировать?
	if (der)
	{
		ASSERT(memIsValid(value, len));
		ASSERT(memIsValid(der, t_count + l_count + len));
		// der <- TLV
		memMove(der + t_count + l_count, value, len);
		derEncodeT(der, tag, t_count);
		derEncodeL(der + t_count, len, l_count);
	}
	return t_count + l_count + len;
}

/*
*******************************************************************************
Корректность
*******************************************************************************
*/

bool_t derIsValid(const octet der[], size_t count)
{
	size_t t_count;
	size_t l_count;
	size_t len;
	// обработать T
	t_count = derDecodeT(0, der, count);
	if (t_count == SIZE_MAX)
		return FALSE;
	// обработать L
	l_count = derDecodeL(&len, der + t_count, count - t_count);
	if (l_count == SIZE_MAX)
		return FALSE;
	// проверить V
	return count == t_count + l_count + len &&
		memIsValid(der + t_count + l_count, len);
}

bool_t derIsValid2(const octet der[], size_t count, u32 tag)
{
	size_t t_count;
	size_t l_count;
	u32 t;
	size_t len;
	// обработать T
	t_count = derDecodeT(&t, der, count);
	if (t_count == SIZE_MAX || t != tag)
		return FALSE;
	// обработать L
	l_count = derDecodeL(&len, der + t_count, count - t_count);
	if (l_count == SIZE_MAX)
		return FALSE;
	// проверить V
	return count == t_count + l_count + len &&
		memIsValid(der + t_count + l_count, len);
}

/*
*******************************************************************************
Длина кода
*******************************************************************************
*/

size_t derSize(const octet der[], size_t count)
{
	size_t t_count;
	size_t l_count;
	size_t len;
	// обработать T
	t_count = derDecodeT(0, der, count);
	if (t_count == SIZE_MAX)
		return SIZE_MAX;
	// обработать L
	l_count = derDecodeL(&len, der + t_count, count - t_count);
	if (l_count == SIZE_MAX)
		return SIZE_MAX;
	// проверить V
	if (count < t_count + l_count + len ||
		!memIsValid(der + t_count + l_count, len))
		return SIZE_MAX;
	// все нормально
	return t_count + l_count + len;
}

/*
*******************************************************************************
Декодирование
*******************************************************************************
*/

size_t derDecode2(u32* tag, const octet** value, const octet der[],
	size_t count)
{
	size_t t_count;
	size_t l_count;
	size_t len;
	ASSERT(memIsValid(der, count));
	ASSERT(tag == 0 || memIsDisjoint2(tag, 4, der, count));
	// обработать T
	t_count = derDecodeT(tag, der, count);
	if (t_count == SIZE_MAX)
		return SIZE_MAX;
	// обработать L
	ASSERT(count >= t_count);
	l_count = derDecodeL(&len, der + t_count, count - t_count);
	if (l_count == SIZE_MAX || count != t_count + l_count + len)
		return SIZE_MAX;
	// вернуть указатель на value
	if (value)
	{
		ASSERT(memIsValid(value, sizeof(*value)));
		ASSERT(tag == 0 || memIsDisjoint2(tag, 4, value, sizeof(*value)));
		*value = der + t_count + l_count;
	}
	// все нормально
	return len;
}

size_t derDecode(u32* tag, void* value, const octet der[], size_t count)
{
	const octet* ptr;
	ASSERT(tag == 0 || memIsDisjoint2(tag, 4, der, count));
	count = derDecode2(tag, &ptr, der, count);
	if (count == SIZE_MAX)
		return SIZE_MAX;
	if (value)
	{
		ASSERT(memIsValid(value, count));
		ASSERT(tag == 0 || memIsDisjoint2(tag, 4, value, count));
		memMove(value, ptr, count);
	}
	return count;
}

