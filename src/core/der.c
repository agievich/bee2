/*
*******************************************************************************
\file der.c
\brief Distinguished Encoding Rules
\project bee2 [cryptographic library]
\created 2014.04.21
\version 2025.04.20
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/core/der.h"
#include "bee2/core/mem.h"
#include "bee2/core/oid.h"
#include "bee2/core/str.h"
#include "bee2/core/util.h"

/*
*******************************************************************************
Поле T (тег)

\remark Вот так можно определить класс тега:
\code
	static u32 derTClass(u32 tag)
	{
		ASSERT(derTIsValid(tag));
		for (; tag > 255; tag >>= 8);
		return tag >>= 6;
	}
\endcode

\remark Нулевой тег (UNIVERSAL 0) запрещен ("Reserved for use by the encoding 
rules").
*******************************************************************************
*/

static bool_t derTIsValid(u32 tag)
{
	if (tag == 0)
		return FALSE;
	else if (tag < 256)
	{
		// установлены 5 младших битов?
		if ((tag & 31) == 31)
			return FALSE;
	}
	// длинный код
	else
	{
		u32 t;
		u32 b;
		// установлен старший бит в последнем (младшем) октете?
		if (tag & 128)
			return FALSE;
		// пробегаем ненулевые октеты вплоть до первого (старшего)
		for (b = tag & 127, t = b, tag >>= 8; tag > 255; tag >>= 8)
		{
			// в промежуточном октете снят старший бит?
			// будет переполнение при пересчете тега-как-значения?
			if ((tag & 128) == 0 || (t >> 25) != 0)
				return FALSE;
			// пересчитать тег-как-значение
			b = tag & 127, t = t << 7, t |= b;
		}
		// можно кодировать одним октетом? меньшим числом октетов?
		// в первом (старшем) октете не установлены 5 младших битов?
		if (t < 31 || b == 0 || (tag & 31) != 31)
			return FALSE;
	}
	return TRUE;
}

static bool_t derTIsPrimitive(u32 tag)
{
	ASSERT(derTIsValid(tag));
	for (; tag > 255; tag >>= 8);
	return ((tag >> 5) & 1) == 0;
}

static bool_t derTIsConstructive(u32 tag)
{
	return !derTIsPrimitive(tag);
}

static size_t derTEnc(octet der[], u32 tag)
{
	size_t t_count = 0;
	// проверить корректность
	if (!derTIsValid(tag))
		return SIZE_MAX;
	// определить длину кода
	{
		u32 t = tag;
		for (; t; ++t_count, t >>= 8);
		if (t_count == 0)
			t_count = 1;
	}
	// кодировать
	if (der)
	{
		size_t pos = t_count;
		ASSERT(memIsValid(der, t_count));
		while (pos--)
		{
			der[pos] = (octet)tag;
			tag >>= 8;
		}
		ASSERT(tag == 0);
	}
	return t_count;
}

static size_t derTDec(u32* tag, const octet der[], size_t count)
{
	u32 t;
	size_t t_count = 1;
	// обработать длину кода
	if (count < 1)
		return SIZE_MAX;
	ASSERT(memIsValid(der, count));
	count = MIN2(4, count);
	// длинный код?
	if ((der[0] & 31) == 31)
	{
		// короткий код? лишний октет с нулем?
		if (count < 2 || (der[1] & 127) == 0)
			return FALSE;
		for (t = 0; t_count < count;)
		{
			t <<= 8, t |= der[t_count] & 127;
			// завершающий октет?
			if ((der[t_count++] & 128) == 0)
				break;
		}
		// завершающий октет не найден?
		// можно было обойтись коротким кодом?
		if (t_count == count || t < 31)
			return SIZE_MAX;
	}
	// нулевой тег?
	else if (der[0] == 0)
		return SIZE_MAX;
	// возврат 
	if (tag)
	{
		size_t pos;
		ASSERT(memIsValid(tag, 4));
		for (t = der[0], pos = 1; pos < t_count; ++pos)
			t <<= 8, t |= der[pos];
		*tag = t;		
	}
	return t_count;
}

/*
*******************************************************************************
Поле L (длина)
*******************************************************************************
*/

static size_t derLEnc(octet der[], size_t len)
{
	size_t l_count = 1;
	// определить длину кода
	{
		size_t l = len;
		// длинная форма (r | 128) || o_{r - 1} ||...|| o_0?
		if (l >= 128)
			for (; l; l >>= 8, ++l_count);
	}
	// кодировать
	if (der)
	{
		ASSERT(memIsValid(der, l_count));
		if (len < 128)
		{
			ASSERT(l_count == 1);
			der[0] = (octet)len;
		}
		else
		{
			size_t r = l_count - 1;
			ASSERT(r >= 1);
			der[0] = (octet)(r | 128);
			for (; r; der[r--] = (octet)len, len >>= 8);
			ASSERT(len == 0);
		}
	}
	return l_count;
}

static size_t derLDec(size_t* len, const octet der[], size_t count)
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
		// нулевой старший октет кода длины?
		// длина меньше 128?
		if (count < l_count || r > O_PER_S ||
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
Пара TL
*******************************************************************************
*/

size_t derTLDec(u32* tag, size_t* len, const octet der[], size_t count)
{
	size_t t_count;
	size_t l_count;
	size_t l;
	ASSERT(memIsValid(der, count));
	// обработать T
	ASSERT(tag == 0 || memIsDisjoint2(tag, 4, der, count));
	t_count = derTDec(tag, der, count);
	if (t_count == SIZE_MAX)
		return SIZE_MAX;
	// обработать L
	ASSERT(count >= t_count);
	l_count = derLDec(&l, der + t_count, count - t_count);
	if (l_count == SIZE_MAX || t_count + l_count > count)
		return SIZE_MAX;
	if (len)
	{
		ASSERT(memIsDisjoint2(len, O_PER_S, der, count));
		ASSERT(tag == 0 || memIsDisjoint2(len, O_PER_S, tag, 4));
		*len = l;
	}
	// все нормально
	return t_count + l_count;
}

/*
*******************************************************************************
Кодирование
*******************************************************************************
*/

size_t derTLEnc(octet der[], u32 tag, size_t len)
{
	size_t t_count;
	size_t l_count;
	// t_count <- len(T)
	t_count = derTEnc(0, tag);
	if (t_count == SIZE_MAX)
		return SIZE_MAX;
	// l_count <- len(L)
	l_count = derLEnc(0, len);
	if (l_count == SIZE_MAX)
		return SIZE_MAX;
	// кодировать?
	if (der)
	{
		ASSERT(memIsValid(der, t_count + l_count));
		// der <- TL
		if (derTEnc(der, tag) != t_count ||
			derLEnc(der + t_count, len) != l_count)
			return SIZE_MAX;
	}
	return t_count + l_count;
}

size_t derEnc(octet der[], u32 tag, const void* val, size_t len)
{
	size_t t_count;
	size_t l_count;
	// t_count <- len(T)
	t_count = derTEnc(0, tag);
	if (t_count == SIZE_MAX)
		return SIZE_MAX;
	// l_count <- len(L)
	l_count = derLEnc(0, len);
	if (l_count == SIZE_MAX)
		return SIZE_MAX;
	// кодировать?
	if (der)
	{
		ASSERT(memIsValid(val, len));
		ASSERT(memIsValid(der, t_count + l_count + len));
		// der <- TLV
		memMove(der + t_count + l_count, val, len);
		if (derTEnc(der, tag) != t_count ||
			derLEnc(der + t_count, len) != l_count)
			return SIZE_MAX;
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
	t_count = derTDec(0, der, count);
	if (t_count == SIZE_MAX)
		return FALSE;
	// обработать L
	l_count = derLDec(&len, der + t_count, count - t_count);
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
	t_count = derTDec(&t, der, count);
	if (t_count == SIZE_MAX || t != tag)
		return FALSE;
	// обработать L
	l_count = derLDec(&len, der + t_count, count - t_count);
	if (l_count == SIZE_MAX)
		return FALSE;
	// проверить V
	return count == t_count + l_count + len &&
		memIsValid(der + t_count + l_count, len);
}

static size_t derDecDeep(const octet der[], size_t count, size_t deep)
{
	u32 tag;
	size_t len;
	size_t c;
	// превышена глубина вложенности?
	if (deep > 32)
		return SIZE_MAX;
	// обработать TL
	c = derTLDec(&tag, &len, der, count);
	if (c == SIZE_MAX || c + len > count)
		return SIZE_MAX;
	// примитивный код?
	if (derTIsPrimitive(tag))
	{
		if (tag == 0x03)
			return derBITDec(0, &len, der, count);
		if (tag == 0x05)
			return derNULLDec(der, count);
		if (tag == 0x06)
			return derOIDDec(0, &len, der, count);
		if (tag == 0x13)
			return derPSTRDec(0, &len, der, count);
		return c + len;
	}
	// конструктивный код
	while (len)
	{
		size_t c1;
		c1 = derDecDeep(der + c, len, deep + 1);
		if (c1 == SIZE_MAX)
			return SIZE_MAX;
		c += c1, len -= c1;
	}
	return c;
}

bool_t derIsValid3(const octet der[], size_t count)
{
	return derDecDeep(der, count, 0) == count;
}

bool_t derStartsWith(const octet der[], size_t count, u32 tag)
{
	u32 t;
	return derTDec(&t, der, count) != SIZE_MAX && t == tag;
}

/*
*******************************************************************************
Декодирование
*******************************************************************************
*/

size_t derDec(u32* tag, const octet** val, size_t* len, const octet der[],
	size_t count)
{
	size_t l;
	size_t tl_count;
	// сделать len наверняка действительным
	if (!len)
		len = &l;
	// обработать TL
	tl_count = derTLDec(tag, len, der, count);
	if (tl_count == SIZE_MAX || tl_count + *len > count)
		return SIZE_MAX;
	// обработать V
	if (val)
	{
		ASSERT(memIsDisjoint2(val, sizeof(octet*), der, count));
		ASSERT(tag == 0 || memIsDisjoint2(val, sizeof(octet*), tag, 4));
		*val = der + tl_count;
	}
	// все нормально
	return tl_count + *len;
}

size_t derDec2(const octet** val, size_t* len, const octet der[],
	size_t count, u32 tag)
{
	u32 t;
	count = derDec(&t, val, len, der, count);
	if (count == SIZE_MAX || t != tag)
		return SIZE_MAX;
	return count;
}

size_t derDec3(const octet** val, const octet der[], size_t count,
	u32 tag, size_t len)
{
	u32 t;
	size_t l;
	count = derDec(&t, val, &l, der, count);
	if (count == SIZE_MAX || t != tag || l != len)
		return SIZE_MAX;
	return count;
}

size_t derDec4(const octet der[], size_t count, u32 tag, const void* val,
	size_t len)
{
	u32 t;
	const octet* v;
	size_t l;
	ASSERT(memIsValid(val, len));
	count = derDec(&t, &v, &l, der, count);
	if (count == SIZE_MAX || t != tag || l != len || !memEq(v, val, len))
		return SIZE_MAX;
	return count;
}

/*
*******************************************************************************
Тип SIZE (беззнаковый INTEGER, который укладывается в size_t):
	V = o1 o2 ... on,
где o1 -- старший октет числа, on -- младший.

\remark В o1 должен быть снят старший бит (признак отрицательности).
*******************************************************************************
*/

size_t derTSIZEEnc(octet der[], u32 tag, size_t val)
{
	size_t len = 1;
	size_t t_count;
	size_t l_count;
	// определить длину V
	{
		register size_t v = val;
		for (; v >= 256; v >>= 8, ++len);
		len += v >> 7, v = 0;
	}
	// кодировать T
	t_count = derTEnc(der, tag);
	if (t_count == SIZE_MAX)
		return SIZE_MAX;
	// кодировать L
	l_count = derLEnc(der ? der + t_count : 0, len);
	if (l_count == SIZE_MAX)
		return SIZE_MAX;
	// кодировать V
	if (der)
	{
		size_t pos = len;
		der += t_count + l_count;
		ASSERT(memIsValid(der, len));
		for (; pos--; val >>= 8)
			der[pos] = (octet)val;
	}
	return t_count + l_count + len;
}

size_t derTSIZEDec(size_t* val, const octet der[], size_t count, u32 tag)
{
	u32 t;
	size_t t_count;
	size_t l_count;
	size_t len;
	// pre
	ASSERT(memIsNullOrValid(val, O_PER_S));
	ASSERT(val == 0 || memIsDisjoint2(val, O_PER_S, der, count));
	// декодировать T
	t_count = derTDec(&t, der, count);
	if (t_count == SIZE_MAX || t != tag)
		return SIZE_MAX;
	der += t_count, count -= t_count;
	// декодировать L
	l_count = derLDec(&len, der, count);
	if (l_count == SIZE_MAX || len > O_PER_S + 1)
		return SIZE_MAX;
	der += l_count, count -= l_count;
	// декодировать V
	{
		register size_t v = 0;
		size_t pos = 0;
		// в старшем октете установлен старший бит?
		// избыточный нулевой старший октет?
		// переполнение?
		if ((der[0] & 0x80) ||
			der[0] == 0 && len > 1 && (der[1] & 0x80) == 0 ||
			len == O_PER_S + 1 && der[0] != 0)
			return SIZE_MAX;
		// декодировать
		for (; pos < len; ++pos)
			v <<= 8, v |= der[pos];
		if (val)
			*val = v;
		v = 0;
	}
	return t_count + l_count + len;
}

size_t derTSIZEDec2(const octet der[], size_t count, u32 tag, size_t val)
{
	register size_t v = val;
	count = derTSIZEDec(&val, der, count, tag);
	if (v != val)
		count = SIZE_MAX;
	v = 0;
	return count;
}

/*
*******************************************************************************
Тип UINT (беззнаковый INTEGER):
	V = o1 o2 ... on,
где o1 -- старший октет числа, on -- младший.

\remark В o1 должен быть снят старший бит (признак отрицательности).
*******************************************************************************
*/

size_t derTUINTEnc(octet der[], u32 tag, const octet* val, size_t len)
{
	size_t ex;
	size_t tl_count;
	// pre
	ASSERT(len > 0);
	ASSERT(memIsValid(val, len));
	// исключить незначащие нули V
	while (len > 1 && val[len - 1] == 0)
		--len;
	// установлен старший бит V => дополнительный нулевой октет
	ex = (val[len - 1] & 128) ? 1 : 0;
	// кодировать T и L
	tl_count = derTLEnc(der, tag, len + ex);
	if (tl_count == SIZE_MAX)
		return SIZE_MAX;
	// кодировать V
	if (der)
	{
		ASSERT(memIsValid(der, tl_count + len + ex));
		der += tl_count;
		memCopy(der, val, len);
		if (ex)
			der[len] = 0;
		memRev(der, len + ex);
	}
	return tl_count + len + ex;
}

size_t derTUINTDec(octet* val, size_t* len, const octet der[], size_t count,
	u32 tag)
{
	const octet* v;
	size_t l;
	size_t ex;
	// декодировать
	count = derDec2(&v, &l, der, count, tag);
	if (count == SIZE_MAX)
		return SIZE_MAX;
	// в значении менее одного октета?
	// установлен старший бит в первом (старшем) октете?
	// незначащий нулевой октет?
	if (l < 1 || (v[0] & 128) ||
		v[0] == 0 && l > 1 && !(v[1] & 128))
		return SIZE_MAX;
	// дополнительный нулевой октет?
	ex = (v[0] == 0 && l > 1 && (v[1] & 128)) ? 1 : 0;
	// возвратить значение
	if (val)
	{
		ASSERT(memIsValid(val, l - ex));
		ASSERT(len == 0 || memIsDisjoint2(len, O_PER_S, val, l - ex));
		memMove(val, v + ex, l - ex);
		memRev(val, l - ex);
	}
	// возвратить длину
	if (len)
	{
		ASSERT(memIsValid(len, O_PER_S));
		*len = l - ex;
	}
	return count;
}

size_t derTUINTDec2(octet* val, const octet der[], size_t count, u32 tag,
	size_t len)
{
	const octet* v;
	size_t l;
	size_t ex;
	// декодировать
	count = derDec2(&v, &l, der, count, tag);
	if (count == SIZE_MAX)
		return SIZE_MAX;
	// в значении менее одного октета?
	// установлен старший бит в первом (старшем) октете?
	// незначащий нулевой октет?
	if (l < 1 || (v[0] & 128) ||
		v[0] == 0 && l > 1 && !(v[1] & 128))
		return SIZE_MAX;
	// дополнительный нулевой октет?
	ex = (v[0] == 0 && l > 1 && (v[1] & 128)) ? 1 : 0;
	// длина не соответствует ожидаемой?
	if (l - ex != len)
		return SIZE_MAX;
	// возвратить значение
	if (val)
	{
		ASSERT(memIsValid(val, len));
		memMove(val, v + ex, len);
		memRev(val, len);
	}
	return count;
}

/*
*******************************************************************************
Тип BIT (строка битов, BIT STRING):
	V = o0 o1...on,
где oi -- октеты:
- o1 -- первый октет строки,
- on -- последний октет строки (возможно неполный);
- o0 -- число неиспользуемых битов в on.
*******************************************************************************
*/

size_t derTBITEnc(octet der[], u32 tag, const octet* val, size_t len)
{
	size_t t_count;
	size_t l_count;
	// кодировать T
	t_count = derTEnc(0, tag);
	if (t_count == SIZE_MAX)
		return SIZE_MAX;
	// кодировать L
	l_count = derLEnc(0, (len + 15) / 8);
	if (l_count == SIZE_MAX)
		return SIZE_MAX;
	// кодировать
	if (der)
	{
		// V
		memMove(der + t_count + l_count + 1, val, (len + 7) / 8);
		if (len % 8)
		{
			der[t_count + l_count + 1 + len / 8] >>= 8 - len % 8;
			der[t_count + l_count + 1 + len / 8] <<= 8 - len % 8;
			der[t_count + l_count] = 8 - len % 8;
		}
		else
			der[t_count + l_count] = 0;
		// TL
		if (derTEnc(der, tag) != t_count ||
			derLEnc(der + t_count, (len + 15) / 8) != l_count)
			return SIZE_MAX;
	}
	return t_count + l_count + (len + 15) / 8;
}

size_t derTBITDec(octet* val, size_t* len, const octet der[], size_t count,
	u32 tag)
{
	const octet* v;
	size_t l;
	// декодировать
	count = derDec2(&v, &l, der, count, tag);
	if (count == SIZE_MAX)
		return SIZE_MAX;
	// в значении менее одного октета?
	// число битов дополнения больше 7?
	// биты дополнения в несуществующем октете?
	if (l < 1 || v[0] > 7 || v[0] != 0 && l == 1) 
		return SIZE_MAX;
	// возвратить строку
	if (val)
	{
		ASSERT(memIsValid(val, l - 1));
		ASSERT(len == 0 || memIsDisjoint2(len, O_PER_S, val, l - 1));
		memMove(val, v + 1, l - 1);
	}
	// возвратить битовую длину
	if (len)
	{
		ASSERT(memIsValid(len, O_PER_S));
		*len = (l - 1) * 8 - v[0];
	}
	return count;
}

size_t derTBITDec2(octet* val, const octet der[], size_t count, u32 tag,
	size_t len)
{
	const octet* v;
	size_t l;
	// декодировать
	count = derDec2(&v, &l, der, count, tag);
	if (count == SIZE_MAX)
		return SIZE_MAX;
	// в значении менее одного октета?
	// число битов дополнения больше 7?
	// биты дополнения в несуществующем октете?
	// длина не соответствует ожидаемой?
	if (l < 1 || v[0] > 7 || v[0] != 0 && l == 1 || (l - 1) * 8 != len + v[0])
		return SIZE_MAX;
	// возвратить строку
	if (val)
		memMove(val, v + 1, l - 1);
	return count;
}

/*
*******************************************************************************
Тип OCT (строка октетов, OCTET STRING):
	V = строка октетов.
*******************************************************************************
*/

size_t derTOCTDec(octet* val, size_t* len, const octet der[], size_t count,
	u32 tag)
{
	const octet* v;
	size_t l;
	count = derDec2(&v, &l, der, count, tag);
	if (count == SIZE_MAX)
		return SIZE_MAX;
	if (val)
	{
		ASSERT(memIsValid(val, l));
		ASSERT(len == 0 || memIsDisjoint2(len, O_PER_S, val, l));
		memMove(val, v, l);
	}
	if (len)
	{
		ASSERT(memIsValid(len, O_PER_S));
		*len = l;
	}
	return count;
}

size_t derTOCTDec2(octet* val, const octet der[], size_t count, u32 tag,
	size_t len)
{
	const octet* v;
	count = derDec3(&v, der, count, tag, len);
	if (count == SIZE_MAX)
		return SIZE_MAX;
	if (val)
		memMove(val, v, len);
	return count;
}

/*
*******************************************************************************
Тип OID (идентификатор объекта, OBJECT IDENTIFIER):
	V = sid1 sid2 ... sid_n, sid_i укладываются в u32 (подробнее см. oid.h).
*******************************************************************************
*/

static size_t derSIDEnc(octet* der, u32 val)
{
	size_t count = 0;
	u32 t = val;
	// длина DER-кода
	if (val)
		for (; t; t >>= 7, count++);
	else
		++count;
	// кодирование
	if (der)
	{
		size_t pos = count - 1;
		ASSERT(memIsValid(der, count));
		der[pos] = (t = val) & 127;
		while (pos--)
			t >>= 7, der[pos] = 128 | (t & 127);
	}
	return count;
}

static size_t derSIDDec(char* oid, u32 val)
{
	size_t count = 0, pos;
	u32 t = val;
	// число символов для val
	do
		t /= 10, count++;
	while (t > 0);
	// декодирование
	if (oid)
	{
		ASSERT(memIsValid(oid, count));
		pos = count - 1;
		oid[pos] = (t = val) % 10 + '0';
		while (pos--)
			t /= 10, oid[pos] = t % 10 + '0';
	}
	return count;
}

static size_t derSIDDec2(u32 val, const char* oid)
{
	size_t count = 0, pos;
	u32 t = val;
	// число символов для val
	do
		t /= 10, count++;
	while (t > 0);
	// сравнение
	ASSERT(strIsValid(oid));
	pos = count - 1;
	if (oid[pos] != '0' + (char)((t = val) % 10))
		return SIZE_MAX;
	while (pos--)
	{
		t /= 10;
		if (oid[pos] != '0' + (char)(t % 10))
			return SIZE_MAX;
	}
	return count;
}

size_t derOIDEnc(octet der[], const char* oid)
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
			count += derSIDEnc(der ? der + count : der, val);
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
	// кодировать TL
	count = derEnc(der, 0x06, der, count);
	// очистка и выход
	d1 = val = 0, pos = 0;
	return count;
}

size_t derOIDDec(char* oid, size_t* len, const octet der[], size_t count)
{
	u32 d1 = 3;
	u32 val = 0;
	size_t l, pos, oid_len;
	// pre
	ASSERT(memIsValid(der, count));
	// проверить тег и определить значение
	count = derDec2(&der, &l, der, count, 0x06);
	if (count == SIZE_MAX)
		return SIZE_MAX;
	// обработать sid
	for (pos = oid_len = 0; pos < l; ++pos)
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
				oid_len += derSIDDec(oid ? oid + oid_len : oid, d1);
				d1 = 0;
			}
			// добавить ".val"
			oid ? oid[oid_len++] = '.' : oid_len++;
			oid_len += derSIDDec(oid ? oid + oid_len : oid, val);
			// к следующему sid
			val = 0;
		}
	}
	// очистка и выход
	d1 = val = 0, pos = l = 0;
	oid ? oid[oid_len] = '\0' : oid_len;
	if (len)
	{
		ASSERT(memIsValid(len, O_PER_S));
		ASSERT(oid == 0 || memIsDisjoint2(len, O_PER_S, oid, strLen(oid)));
		*len = oid_len;
	}
	return count;
}

size_t derOIDDec2(const octet der[], size_t count, const char* oid)
{
	u32 d1 = 3;
	u32 val = 0;
	size_t len, pos, oid_delta;
	// проверить входной буфер
	if (count == SIZE_MAX)
		return SIZE_MAX;
	ASSERT(memIsValid(der, count));
	// проверить тег и определить значение
	count = derDec2(&der, &len, der, count, 0x06);
	if (count == SIZE_MAX)
		return SIZE_MAX;
	// обработать sid
	for (pos = 0; pos < len; ++pos)
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
				oid_delta = derSIDDec2(d1, oid);
				if (oid_delta == SIZE_MAX)
					return SIZE_MAX;
				oid += oid_delta, d1 = 0;
			}
			// добавить ".val"
			if (*oid != '.')
				return SIZE_MAX;
			++oid;
			oid_delta = derSIDDec2(val, oid);
			if (oid_delta == SIZE_MAX)
				return SIZE_MAX;
			// к следующему sid
			oid += oid_delta, val = 0;
		}
	}
	// очистка и выход
	d1 = val = 0, pos = len = 0;
	if (*oid != '\0')
		return SIZE_MAX;
	return count;
}

/*
*******************************************************************************
Тип PSTR (печатаемая строка, PrintableString):
	V = строка (без завершающего нуля).
*******************************************************************************
*/

size_t derTPSTREnc(octet der[], u32 tag, const char* val)
{
	// проверить строку
	if (!strIsValid(val) || !strIsPrintable(val))
		return SIZE_MAX;
	// кодировать
	return derEnc(der, tag, val, strLen(val));
}

size_t derTPSTRDec(char* val, size_t* len, const octet der[], size_t count,
	u32 tag)
{
	const octet* v;
	size_t l;
	size_t pos;
	// декодировать
	count = derDec2(&v, &l, der, count, tag);
	if (count == SIZE_MAX)
		return SIZE_MAX;
	// проверить символы (см. strIsPrintable())
	for (pos = 0; pos < l; ++pos)
	{
		register char ch = (char)v[pos];
		if ((ch < '0' || ch > '9') &&
			(ch < 'A' || ch > 'Z') &&
			(ch < 'a' || ch > 'z') &&
			strchr(" '()+,-./:=?", ch) == 0)
		{
			ch = 0;
			return SIZE_MAX;
		}
		ch = 0;
	}
	// возвратить строку
	if (val)
	{
		ASSERT(memIsValid(val, l + 1));
		ASSERT(len == 0 || memIsDisjoint2(len, O_PER_S, val, l + 1));
		memMove(val, v, l);
		val[l] = 0;
	}
	// возвратить длину строки
	if (len)
	{
		ASSERT(memIsValid(len, O_PER_S));
		*len = l;
	}
	return count;
}

/*
*******************************************************************************
Тип SEQ (последовательность / структура, SEQUENCE):
	V = вложенные данные.

Длина V становится окончательно известна только в конце кодирования структуры.
В начале кодирования структура пуста и поэтому длина L = |V| устанавливается
равной нулю. В конце кодирования длина уточняется, вложенное содержимое
сдвигается при необходимости.
*******************************************************************************
*/

size_t derTSEQEncStart(der_anchor_t* anchor, octet der[], size_t pos, u32 tag)
{
	ASSERT(memIsValid(anchor, sizeof(der_anchor_t)));
	// проверить тег
	if (!derTIsValid(tag) || !derTIsConstructive(tag))
		return SIZE_MAX;
	// бросить якорь
	anchor->der = der;
	anchor->pos = pos;
	anchor->tag = tag;
	anchor->len = 0;
	// кодировать пустую (пока) структуру
	return derEnc(der, tag, 0, 0);
}

size_t derTSEQEncStop(octet der[], size_t pos, const der_anchor_t* anchor)
{
	size_t t_count;
	size_t l_count;
	size_t len;
	size_t l_count1;
	ASSERT(memIsValid(anchor, sizeof(der_anchor_t)));
	ASSERT(anchor->der == 0 ||
		der != 0 && anchor->der + pos == der + anchor->pos);
	// определить длину вложенных данных
	t_count = derTEnc(0, anchor->tag);
	l_count = derLEnc(0, anchor->len);
	if (anchor->pos + t_count + l_count > pos)
		return SIZE_MAX;
	len = pos - anchor->pos - t_count - l_count;
	l_count1 = derLEnc(0, len);
	// определить величину смещения вложенных данных
	pos = l_count1 - l_count;
	// сдвинуть вложенные данные и уточнить длину
	if (anchor->der)
	{
		ASSERT(anchor->der + t_count == der - len - l_count);
		memMove(der - len + pos, der - len, len);
		if (derLEnc(der - len - l_count, len) != l_count1)
			return SIZE_MAX;
	}
	return pos;
}

size_t derTSEQDecStart(der_anchor_t* anchor, const octet der[], size_t count,
	u32 tag)
{
	size_t t_count;
	size_t l_count;
	// pre
	ASSERT(memIsValid(anchor, sizeof(der_anchor_t)));
	// проверить тег
	if (!derTIsConstructive(tag))
		return SIZE_MAX;
	// бросить якорь
	anchor->der = der;
	// декодировать тег
	t_count = derTDec(&anchor->tag, der, count);
	if (t_count == SIZE_MAX || anchor->tag != tag)
		return SIZE_MAX;
	// декодировать длину
	l_count = derLDec(&anchor->len, der + t_count, count - t_count);
	if (l_count == SIZE_MAX)
		return SIZE_MAX;
	return t_count + l_count;
}

size_t derTSEQDecStop(const octet der[], const der_anchor_t* anchor)
{
	const octet* val;
	ASSERT(memIsValid(anchor, sizeof(der_anchor_t)));
	// определить начало вложенных данных
	val = anchor->der + derTEnc(0, anchor->tag) + derLEnc(0, anchor->len);
	if (val > der)
		return SIZE_MAX;
	// сравнить длину вложенных данных с сохраненной длиной
	return (der == val + anchor->len) ? 0 : SIZE_MAX;
}

