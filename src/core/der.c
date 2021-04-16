/*
*******************************************************************************
\file der.c
\brief Distinguished Encoding Rules
\project bee2 [cryptographic library]
\author Sergey Agievich [agievich@{bsu.by|gmail.com}]
\author Vlad Semenov [semenov.vlad.by@gmail.com]
\created 2014.04.21
\version 2021.04.14
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
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

static void derEncT(octet der[], u32 tag, size_t t_count)
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

static size_t derDecT(u32* tag, const octet der[], size_t count)
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

static size_t derEncL(octet der[], size_t len, size_t l_count)
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

static size_t derDecL(size_t* len, const octet der[], size_t count)
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

size_t derEnc(octet der[], u32 tag, const void* val, size_t len)
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
		ASSERT(memIsValid(val, len));
		ASSERT(memIsValid(der, t_count + l_count + len));
		// der <- TLV
		memMove(der + t_count + l_count, val, len);
		derEncT(der, tag, t_count);
		derEncL(der + t_count, len, l_count);
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
	t_count = derDecT(0, der, count);
	if (t_count == SIZE_MAX)
		return FALSE;
	// обработать L
	l_count = derDecL(&len, der + t_count, count - t_count);
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
	t_count = derDecT(&t, der, count);
	if (t_count == SIZE_MAX || t != tag)
		return FALSE;
	// обработать L
	l_count = derDecL(&len, der + t_count, count - t_count);
	if (l_count == SIZE_MAX)
		return FALSE;
	// проверить V
	return count == t_count + l_count + len &&
		memIsValid(der + t_count + l_count, len);
}

/*
*******************************************************************************
Декодирование
*******************************************************************************
*/

size_t derDec(u32* tag, const octet** val, size_t* len, const octet der[],
	size_t count)
{
	size_t t_count;
	size_t l_count;
	size_t l;
	ASSERT(memIsValid(der, count));
	// обработать T
	ASSERT(tag == 0 || memIsDisjoint2(tag, 4, der, count));
	t_count = derDecT(tag, der, count);
	if (t_count == SIZE_MAX)
		return SIZE_MAX;
	// обработать L
	ASSERT(count >= t_count);
	l_count = derDecL(&l, der + t_count, count - t_count);
	if (l_count == SIZE_MAX || t_count + l_count + l > count)
		return SIZE_MAX;
	if (len)
	{
		ASSERT(memIsDisjoint2(len, O_PER_S, der, count));
		ASSERT(tag == 0 || memIsDisjoint2(len, O_PER_S, tag, 4));
		ASSERT(val == 0 || memIsDisjoint2(len, O_PER_S, val, sizeof(octet*)));
		*len = l;
	}
	// обработать V
	if (val)
	{
		ASSERT(memIsDisjoint2(val, sizeof(octet*), der, count));
		ASSERT(tag == 0 || memIsDisjoint2(val, sizeof(octet*), tag, 4));
		*val = der + t_count + l_count;
	}
	// все нормально
	return t_count + l_count + l;
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
Кодирование целого числа (INTEGER):
- T = 0x02;
- V = o1 o2 ... on, где o1 -- старший октет числа, on -- младший.

Установка старшего бита в o1 -- признак отрицательного числа. Должно
использоваться минимальное число октетов для однозначного представления числа.

Примеры:
- der(0) = 02 01 00
- der(127) = 02 01 7F
- der(128) = 02 02 00 80
- der(256) = 02 02 01 00
- der(-128) = 02 01 80
- der(-129) = 02 02 FF 7F
*******************************************************************************
*/

size_t derEncSIZE(octet der[], size_t val)
{
	register size_t v = val;
	size_t count = 1;
	// определить длину L
	for (; v >= 256; v >>= 8, ++count);
	count += v >> 7, v = 0;
	// кодировать
	if (der)
	{
		size_t pos = count;
		ASSERT(memIsValid(der, count + 2));
		der[0] = 0x02;
		der[1] = (octet)count;
		for (; pos--; val >>= 8)
			der[2 + pos] = (octet)val;
	}
	// длина der-кода
	return count + 2;
}

size_t derDecSIZE(size_t* val, const octet der[], size_t count)
{
	register size_t v;
	size_t pos;
	// проверить длину кода
	if (count < 3)
		return SIZE_MAX;
	ASSERT(memIsValid(der, count));
	// проверить TL
	if (der[0] != 0x02 || (size_t)der[1] + 2 > count)
		return SIZE_MAX;
	// проверить V
	if ((der[2] & 0x80) || der[2] == 0 && der[1] > 1 && (der[3] & 0x80) == 0)
		return SIZE_MAX;
	// декодировать
	for (v = 0, pos = 2; pos < (size_t)der[1] + 2; ++pos)
		v = (v << 8) ^ der[pos];
	if (val)
	{
		ASSERT(memIsValid(val, O_PER_S));
		*val = v;
		v = 0;
	}
	// длина DER-кода
	return pos;
}

size_t derDecSIZE2(const octet der[], size_t count, size_t val)
{
	size_t v;
	count = derDecSIZE(&v, der, count);
	if (count == SIZE_MAX || v != val)
		return SIZE_MAX;
	return count;
}

/*
*******************************************************************************
Строка октетов (OCTET STRING):
- T = 0x04;
- V = строка октетов.
*******************************************************************************
*/

size_t derDecOCT(octet* val, size_t* len, const octet der[], size_t count)
{
	const octet* v;
	size_t l;
	count = derDec2(&v, &l, der, count, 0x04);
	if (count == SIZE_MAX)
		return SIZE_MAX;
	if (val)
		memMove(val, v, l);
	if (len)
	{
		ASSERT(memIsValid(len, O_PER_S));
		*len = l;
	}
	return count;
}

size_t derDecOCT2(octet* val, const octet der[], size_t count, size_t len)
{
	const octet* v;
	count = derDec3(&v, der, count, 0x04, len);
	if (count == SIZE_MAX)
		return SIZE_MAX;
	if (val)
		memMove(val, v, len);
	return count;
}

/*
*******************************************************************************
Идентификатор объекта (OBJECT IDENTIFIER):
- T = 0x06;
- V = sid1 sid2 ... sid_n, sid_i укладываются в u32 (подробнее см. oid.h).
*******************************************************************************
*/

static size_t derEncSID(octet* der, u32 val)
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

static size_t derDecSID(char* oid, u32 val)
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

static size_t derDecSID2(u32 val, const char* oid)
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

size_t derEncOID(octet der[], const char* oid)
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
			count += derEncSID(der ? der + count : der, val);
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
		count = derEnc(der, 0x06, der, count);
	else
		count = derEnc(0, 0x06, 0, count);
	// очистка и выход
	d1 = val = 0, pos = 0;
	return count;
}

size_t derDecOID(char* oid, size_t* len, const octet der[], size_t count)
{
	u32 d1 = 3;
	u32 val = 0;
	size_t l, pos, oid_len;
	// проверить входной буфер
	if (count == SIZE_MAX)
		return SIZE_MAX;
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
				oid_len += derDecSID(oid ? oid + oid_len : oid, d1);
				d1 = 0;
			}
			// добавить ".val"
			oid ? oid[oid_len++] = '.' : oid_len++;
			oid_len += derDecSID(oid ? oid + oid_len : oid, val);
			// к следующему sid
			val = 0;
		}
	}
	// очистка и выход
	d1 = val = 0, pos = l = 0;
	oid ? oid[oid_len++] = '\0' : oid_len++;
	if (len)
	{
		ASSERT(memIsValid(len, O_PER_S));
		*len = oid_len;
	}
	return count;
}

size_t derDecOID2(const octet der[], size_t count, const char* oid)
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
				oid_delta = derDecSID2(d1, oid);
				if (oid_delta == SIZE_MAX)
					return SIZE_MAX;
				oid += oid_delta, d1 = 0;
			}
			// добавить ".val"
			if (*oid != '.')
				return SIZE_MAX;
			++oid;
			oid_delta = derDecSID2(val, oid);
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
Последовательность (SEQUENCE), структура:
- T = 0x30;
- V = вложенное содержимое.

Длина V становится окончательно известна только в конце кодирования структуры.
В начале кодирования структура пуста и поэтому длина L = |V| устанавливается
равной нулю. В конце кодирования длина уточняется, вложенное содержимое
сдвигается при необходимости.
*******************************************************************************
*/

size_t derEncSEQStart(der_anchor* anchor, octet der[], size_t pos)
{
	ASSERT(memIsValid(anchor, sizeof(der_anchor)));
	// бросить якорь
	anchor->der = der;
	anchor->pos = pos;
	anchor->len = 0;
	// кодировать пустую (пока) структуру
	return derEnc(der, 0x30, 0, 0);
}

size_t derEncSEQStop(octet der[], size_t pos, const der_anchor* anchor)
{
	size_t t_count, l_count, len, l_count1;
	ASSERT(memIsValid(anchor, sizeof(der_anchor)));
	ASSERT(anchor->der == 0 ||
		der != 0 && anchor->der + pos == der + anchor->pos);
	// определить длину вложенных данных
	t_count = derLenT(0x30);
	l_count = derLenL(anchor->len);
	if (anchor->pos + t_count + l_count > pos)
		return SIZE_MAX;
	len = pos  - anchor->pos - t_count - l_count;
	l_count1 = derLenL(len);
	// определить величину смещения вложенных данных
	pos = l_count1 - l_count;
	// сдвинуть вложенные данные и уточнить длину
	if (anchor->der)
	{
		ASSERT(anchor->der + t_count == der - len - l_count);
		memMove(der - len + pos, der - len, len);
		derEncL(der - len - l_count, len, l_count1);
	}
	return pos;
}

size_t derDecSEQStart(der_anchor* anchor, const octet der[], size_t count)
{
	u32 tag;
	size_t t_count;
	ASSERT(memIsValid(anchor, sizeof(der_anchor)));
	// бросить якорь
	anchor->der = der;
	// декодировать тег
	t_count = derDecT(&tag, der, count);
	if (t_count == SIZE_MAX || tag != 0x30)
		return SIZE_MAX;
	// декодировать длину
	count = derDecL(&anchor->len, der + t_count, count - t_count);
	if (count == SIZE_MAX)
		return SIZE_MAX;
	return t_count + count;
}

size_t derDecSEQStop(const octet der[], const der_anchor* anchor)
{
	const octet* val;
	ASSERT(memIsValid(anchor, sizeof(der_anchor)));
	// определить начало вложенных данных
	val = anchor->der + derLenT(0x30) + derLenL(anchor->len);
	if (val > der)
		return SIZE_MAX;
	// сравнить длину вложенных данных с сохраненной длиной
	return (der == val + anchor->len) ? 0 : SIZE_MAX;
}
