/*
*******************************************************************************
\file json.c
\brief JSON
\project bee2 [cryptographic library]
\created 2025.05.07
\version 2025.05.10
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <stdarg.h>
#include <stdio.h>
#include <bee2/core/hex.h>
#include <bee2/core/json.h>
#include <bee2/core/mem.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>

/*
*******************************************************************************
Декодирование: определения

Реализованы функции разбора (Parse) и декодирования (Dec). Разбор ориентирован 
на проверку JSON-кода. При успешном разборе определяется элемент типа 
json_elem_t. При декодировании из этих элемента извлекаются данные: 
строки (со снятыми кавычками), числа, вложенные в объекты и массивы элементы.
Вложенные элементы, в свою очередь, могут быть подвергнуты разбору и (или)
декодированию. 

\remark При успешном разборе JSON-кода объекта возвращаемый элемент json_elem_t 
дает строку "{..}", которая прошла синтаксический анализ и признана 
корректной. Однако разбор не позволяет определить вложенные в объект элементы. 
Нужно использовать декодирование.

\remark При декодирование пробелов, разделителей и лексем данные не 
возвращаются, речь идет о проверке синтаксиса, что близко к разбору. Тем не 
менее, мы говорим о декодировании, поскольку разбор предполагает 
возврат элемента json_elem_t.

\warning При декодировании составных элементов контролируется глубина 
вложенности -- она не может быть неконтролируемо большой.
*******************************************************************************
*/

/* максимально допустимая глубина вложенности */
static const size_t _max_depth = 256;

/* форвардное определение функции разбора элемента */
static size_t jsonElemParse(json_elem_t* elem, const char json[], size_t count,
	size_t depth);

/*
*******************************************************************************
Декодирование: пробелы и разделители
*******************************************************************************
*/

static size_t jsonWsDec(const char json[], size_t count)
{
	size_t c;
	ASSERT(memIsValid(json, count));
	for (c = 0; c < count && strContains(" \n\r\t", json[c]); ++c);
	return c;
}

static size_t jsonDelimDec(const char json[], size_t count, char delim)
{
	size_t c;
	ASSERT(strContains(",:{}[]", delim));
	c = jsonWsDec(json, count);
	if (c == count || json[c] != delim)
		return SIZE_MAX;
	return c + 1 + jsonWsDec(json + c + 1, count - c - 1);
}

/*
*******************************************************************************
Декодирование: лексемы
*******************************************************************************
*/

static size_t jsonLexDec(json_elem_t* elem, const char json[], size_t count)
{
	const char* lex[] = { "true", "false", "null" };
	size_t c;
	size_t c1;
	size_t i;
	// pre
	ASSERT(memIsValid(json, count));
	ASSERT(memIsNullOrValid(elem, sizeof(json_elem_t)));
	// декодировать лексему
	c = jsonWsDec(json, count);
	json += c, count -= c;
	for (i = 0; i < COUNT_OF(lex); ++i)
		if ((c1 = strLen(lex[i])) <= count && strStartsWith(json, lex[i]))
			break;
	if (i == COUNT_OF(lex))
		return SIZE_MAX;
	// возврат
	if (elem)
		elem->json = json, elem->count = c1;
	return c + c1 + jsonWsDec(json + c + c1, count - c - c1);
}

/*
*******************************************************************************
Декодирование: числа
*******************************************************************************
*/

static size_t jsonSizeParse(json_elem_t* elem, const char json[], size_t count)
{
	size_t c;
	size_t c1;
	// pre
	ASSERT(memIsValid(json, count));
	ASSERT(memIsNullOrValid(elem, sizeof(json_elem_t)));
	// декодировать десятичные цифры
	c = c1 = jsonWsDec(json, count);
	for (; c < count && '0' <= json[c] && json[c] <= '9'; ++c);
	// "пустое" число? незначащий '0'?
	if (c == c1 || json[c1] == '0' && c - c1 > 1)
		return SIZE_MAX;
	// возврат
	if (elem)
		elem->json = json + c1, elem->count = c - c1;
	return c + jsonWsDec(json + c, count - c);
}

size_t jsonSizeDec(size_t* size, const char json[], size_t count)
{
	json_elem_t e;
	size_t c;
	size_t s;
	// pre
	ASSERT(memIsNullOrValid(size, O_PER_S));
	// разобрать
	c = jsonSizeParse(&e, json, count);
	if (c == SIZE_MAX)
		return SIZE_MAX;
	ASSERT(e.count > 0 && memIsValid(e.json, e.count));
	// определить число
	for (s = 0; e.count--; ++e.json)
	{
		ASSERT('0' <= e.json[0] && e.json[0] <= '9');
		if (s > SIZE_MAX / 10)
			return SIZE_MAX;
		s *= 10;
		if (s + (size_t)(e.json[0] - '0') < s)
			return SIZE_MAX;
		s += (size_t)(e.json[0] - '0');
	}
	// возврат
	if (size)
		*size = s;
	return c;
}

/*
*******************************************************************************
Декодирование: строки
*******************************************************************************
*/

static size_t jsonStrParse(json_elem_t* elem, const char json[], size_t count)
{
	size_t c;
	size_t c1;
	// pre
	ASSERT(memIsValid(json, count));
	ASSERT(memIsNullOrValid(elem, sizeof(json_elem_t)));
	// декодировать открывающую "
	c = jsonWsDec(json, count);
	if (c == count || json[c] != '"')
		return SIZE_MAX;
	c1 = c++;
	// пока не встретилась закрывающая "
	while (c < count && json[c] != '"')
	{
		if (json[c++] == '\\')
		{
			if (c == count || !strContains("\"\\/bfnrtu", json[c]))
				return SIZE_MAX;
			if (json[c++] == 'u')
			{
				if (c + 4 >= count || !hexIsValid2(json + c, 4))
					return SIZE_MAX;
				c += 4;
			}
		}
	}
	// декодировать закрывающую "
	if (c == count || json[c++] != '"')
		return SIZE_MAX;
	// возврат
	if (elem)
		elem->json = json + c1, elem->count = c - c1;
	return c + jsonWsDec(json + c, count - c);
}

size_t jsonStrDec(const char** str, size_t* len, const char json[], 
	size_t count)
{
	json_elem_t e;
	size_t c;
	// pre
	ASSERT(memIsNullOrValid(str, sizeof(const char*)));
	ASSERT(memIsNullOrValid(len, O_PER_S));
	// разобрать
	c = jsonStrParse(&e, json, count);
	if (c == SIZE_MAX)
		return SIZE_MAX;
	ASSERT(e.count >= 2 && memIsValid(e.json, e.count));
	ASSERT(e.json[0] == '"' && e.json[e.count - 1] == '"');
	// возврат
	if (str)
		*str = e.json + 1;
	if (len)
		*len = e.count - 2;
	return c;
}

/*
*******************************************************************************
Декодирование: объекты
*******************************************************************************
*/

static size_t jsonObjParse(json_elem_t* elem, const char json[], size_t count,
	size_t depth)
{
	size_t c;
	size_t c1;
	// pre
	ASSERT(memIsValid(json, count));
	ASSERT(memIsNullOrValid(elem, sizeof(json_elem_t)));
	// превышена глубина?
	if (depth > _max_depth)
		return SIZE_MAX;
	// декодировать {
	if ((c = jsonWsDec(json, count)) == SIZE_MAX)
		return SIZE_MAX;
	json += c, count -= c;
	if (json[0] != '{')
		return SIZE_MAX;
	if (elem)
		elem->json = json, elem->count = c;
	++c, ++json, --count;
	// пока не встретилась }
	while (count && json[0] != '}')
	{
		// разобрать имя
		if ((c1 = jsonStrParse(0, json, count)) == SIZE_MAX)
			return SIZE_MAX;
		c += c1, json += c1, count -= c1;
		// декодировать :
		if ((c1 = jsonDelimDec(json, count, ':')) == SIZE_MAX)
			return SIZE_MAX;
		c += c1, json += c1, count -= c1;
		// разобрать элемент
		if ((c1 = jsonElemParse(0, json, count, depth + 1)) == SIZE_MAX)
			return SIZE_MAX;
		c += c1, json += c1, count -= c1;
		// декодировать ,
		if (count && json[0] == ',')
		{
			c1 = 1 + jsonWsDec(json + 1, count - 1);
			c += c1, json += c1, count -= c1;
			if (count && json[0] == '}')
				return SIZE_MAX;
		}
	}
	// декодировать }
	if (count == 0 || json[0] != '}')
		return SIZE_MAX;
	++c, ++json, --count;
	// возврат
	if (elem)
		elem->count = c - elem->count;
	return c + jsonWsDec(json, count);
}

size_t jsonObjDec(json_elem_t elems[], const char json[], size_t count,
	const char* names[], size_t size)
{
	size_t c;
	size_t c1;
	size_t i;
	// pre
	ASSERT(memIsValid(json, count));
	ASSERT(memIsValid(names, size * sizeof(char*)));
	ASSERT(memIsValid(elems, size * sizeof(json_elem_t)));
	// подготовить elems
	memSetZero(elems, size * sizeof(json_elem_t));
	// декодировать {
	if ((c = jsonDelimDec(json, count, '{')) == SIZE_MAX)
		return SIZE_MAX;
	json += c, count -= c;
	// цикл по именам
	for (i = 0; i < size; ++i)
	{
		const char* str;
		size_t len;
		size_t pos;
		// декодировать имя
		if ((c1 = jsonStrDec(&str, &len, json, count)) == SIZE_MAX)
			return SIZE_MAX;
		c += c1, json += c1, count -= c1;
		// искать имя в names
		for (pos = 0; pos < size; ++pos)
		{
			ASSERT(strIsValid(names[pos]));
			// найдено?
			if (len == strLen(names[pos]) && memEq(str, names[pos], len))
			{
				// уже обработано?
				if (elems[pos].json != 0)
					return SIZE_MAX;
				break;
			}
		}
		// не найдено?
		if (pos == size)
			return SIZE_MAX;
		// декодировать :
		if ((c1 = jsonDelimDec(json, count, ':')) == SIZE_MAX)
			return SIZE_MAX;
		c += c1, json += c1, count -= c1;
		// декодировать элемент
		if ((c1 = jsonElemParse(elems + pos, json, count, 0)) == SIZE_MAX)
			return SIZE_MAX;
		c += c1, json += c1, count -= c1;
		// декодировать ,
		if (i + 1 < size)
		{
			if ((c1 = jsonDelimDec(json, count, ',')) == SIZE_MAX)
				return SIZE_MAX;
			c += c1, json += c1, count -= c1;
		}
	}
	// декодировать }
	if ((c1 = jsonDelimDec(json, count, '}')) == SIZE_MAX)
		return SIZE_MAX;
	// возврат
	return c + c1;
}

/*
*******************************************************************************
Декодирование: массивы
*******************************************************************************
*/

static size_t jsonArrParse(json_elem_t* elem, json_elem_t elems[], 
	size_t* size, const char json[], size_t count, size_t depth)
{
	size_t c;
	size_t c1;
	size_t s;
	// pre
	ASSERT(memIsValid(json, count));
	ASSERT(memIsNullOrValid(elem, sizeof(json_elem_t)));
	ASSERT(memIsNullOrValid(size, O_PER_S));
	// превышена глубина?
	if (depth > _max_depth)
		return SIZE_MAX;
	// декодировать [
	if ((c = jsonWsDec(json, count)) == SIZE_MAX)
		return SIZE_MAX;
	json += c, count -= c;
	if (json[0] != '[')
		return SIZE_MAX;
	if (elem)
		elem->json = json, elem->count = c;
	++c, ++json, --count;
	// пока не встретилась ]
	for (s = 0; count && json[0] != ']'; ++s)
	{
		json_elem_t e;
		// разобрать элемент
		if ((c1 = jsonElemParse(&e, json, count, depth + 1)) == SIZE_MAX)
			return SIZE_MAX;
		c += c1, json += c1, count -= c1;
		// сохранить элемент
		if (elems)
		{
			ASSERT(memIsValid(elems, (s + 1) * sizeof(json_elem_t)));
			memCopy(elems + s, &e, sizeof(json_elem_t));
		}
		// декодировать ,
		if (count && json[0] == ',')
		{
			c1 = 1 + jsonWsDec(json + 1, count - 1);
			c += c1, json += c1, count -= c1;
			if (count && json[0] == ']')
				return SIZE_MAX;
		}
	}
	// декодировать ]
	if (count == 0 || json[0] != ']')
		return SIZE_MAX;
	++c, ++json, --count;
	// возврат
	if (elem)
		elem->count = c - elem->count;
	if (size)
		*size = s;
	return c + jsonWsDec(json, count);
}

size_t jsonArrDec(json_elem_t elems[], size_t* size, const char json[],
	size_t count)
{
	return jsonArrParse(0, elems, size, json, count, 0);
}

/*
*******************************************************************************
Декодирование: элементы
*******************************************************************************
*/

static size_t jsonElemParse(json_elem_t* elem, const char json[], size_t count,
	size_t depth)
{
	size_t c;
	size_t c1;
	// pre
	ASSERT(memIsValid(json, count));
	ASSERT(memIsNullOrValid(elem, sizeof(json_elem_t)));
	// пропустить пробелы
	c = jsonWsDec(json, count);
	if (c == count)
		return SIZE_MAX;
	json += c, count -= c;
	// разобрать элемент в зависимости от типа
	if (json[0] == '{')
		c1 = jsonObjParse(elem, json, count, depth + 1);
	else if (json[0] == '[')
		c1 = jsonArrParse(elem, 0, 0, json, count, depth + 1);
	else if (json[0] == '"')
		c1 = jsonStrParse(elem, json, count);
	else if ('0' <= json[0] && json[0] <= '9')
		c1 = jsonSizeParse(elem, json, count);
	else if (strContains("tfn", json[0]))
		c1 = jsonLexDec(elem, json, count);
	else
		return SIZE_MAX;
	if (c1 == SIZE_MAX)
		return SIZE_MAX;
	// возврат
	return c + c1;
}

bool_t jsonIsValid(const char json[], size_t count)
{
	// корректный код? ничего кроме кода?
	return jsonElemParse(0, json, count, 0) == count;
}

/*
*******************************************************************************
Кодирование
*******************************************************************************
*/

size_t jsonFmtEnc(char json[], size_t size, const char* fmt, ...)
{
	va_list args;
	int c;
	// pre
	ASSERT(strIsValid(fmt));
	ASSERT(memIsNullOrValid(json, size));
	// кодировать
	if (!json || !size)
		json = 0, size = 0;
	va_start(args, fmt);
	c = vsnprintf(json, size, fmt, args);
	va_end(args);
	// ошибка или переполнение?
	if (c < 0 || json && (size_t)c >= size)
		return SIZE_MAX;
	// возврат
	return (size_t)c;
}
