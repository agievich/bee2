/*
*******************************************************************************
\file toml.c
\brief TOML files processing
\project bee2 [cryptographic library]
\created 2023.07.12
\version 2024.02.25
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/core/hex.h"
#include "bee2/core/mem.h"
#include "bee2/core/str.h"
#include "bee2/core/toml.h"
#include "bee2/core/util.h"

#include <ctype.h>

#define TOML_BUF_SIZE 1000

/*
*******************************************************************************
Специальные символы

\remark Функция tomlSpaceDec() отличается от других функций кодирования /
декодирования -- она никогда не возвращает значение SIZE_MAX, указывающее
на ошибку.
*******************************************************************************
*/

static bool_t strIsSpace(char ch)
{
	return ch != '\n' && isspace(ch);
}

static bool_t strIsAlnum(char ch) 
{
	return (bool_t)isalnum(ch);
}

static size_t tomlSpaceDec(const char* str)
{
	size_t count;
	ASSERT(strIsValid(str));
	for (count = 0; strIsSpace(str[count]); ++count);
	return count;
}

static size_t tomlDelimDec(const char* str, char delim)
{
	size_t count;
	// пропустить пробелы
	count = tomlSpaceDec(str);
	str += count;
	// разделитель?
	if (*str != delim)
		return SIZE_MAX;
	++count, ++str;
	// пропустить пробелы
	return count + tomlSpaceDec(str);
}

static size_t tomlDelimEnc(char* str, char delim)
{
	if (str)
	{
		ASSERT(memIsValid(str, 2));
		str[0] = delim, str[1] = 0;
	}
	return 1;
}

static size_t tomlLFDec(const char* str)
{
	size_t count = 0;
	bool_t lf = FALSE;
	ASSERT(strIsValid(str));
	while (1)
	{
		size_t c;
		// пропустить комментарий
		c = tomlDelimDec(str, '#');
		if (c != SIZE_MAX)
			for (count += c; str[count] && str[count] != '\n'; ++count);
		// пропустить пробелы
		else
			count += tomlSpaceDec(str);
		// конец строки?
		if (str[count] == 0)
			return count;
		// LF?
		if (str[count] == '\n')
			lf = TRUE, ++count;
		else
			break;
	}
	return lf ? count : SIZE_MAX;
}

#define tomlLFEnc(str) tomlDelimEnc(str, '\n')

/*
*******************************************************************************
Имена

\remark Декодирование bare- и quotted-имен эквивалентно их кодированию.

\remark При декодировании dotted-имени из него исключаются незначащие пробелы.
То же самое происходит при кодировании. Единственное отличие между двумя
операциями состоит в том, что при декодировании возвращается число
декодированных символов, а при кодировании -- число закодированных.

\remark При декодировании имен предваряющие и завершающие пробелы не 
пропускаются.
*******************************************************************************
*/

static size_t tomlNameBareDec(char* name, const char* str)
{
	size_t count;
	// pre
	ASSERT(strIsValid(str));
	// выделить имя
	for (count = 0; strIsAlnum(str[count]) ||
		str[count] == '_' || str[count] == '-';
		++count);
	if (!count)
		return SIZE_MAX;
	// сохранить имя
	if (name)
	{
		ASSERT(memIsValid(name, count + 1));
		memCopy(name, str, count);
		name[count] = 0;
	}
	return count;
}

static size_t tomlNameQuotedDec(char* name, const char* str)
{
	size_t count;
	// pre
	ASSERT(strIsValid(str));
	// начинается с кавычки?
	if (str[0] != '\'' && str[0] != '"')
		return SIZE_MAX;
	// искать закрывающую кавычку
	for (count = 1; str[count] != str[0]; ++count)
		if (str[count] == 0)
			return SIZE_MAX;
	++count;
	// сохранить имя
	if (name)
	{
		ASSERT(memIsValid(name, count + 1));
		memCopy(name, str, count);
		name[count] = 0;
	}
	return count;
}

static size_t tomlNameDec(char* name, const char* str)
{
	size_t count;
	size_t c;
	// пропустить пробелы
	count = tomlSpaceDec(str);
	str += count;
	// декодировать первую часть имени
	if ((c = tomlNameBareDec(name, str)) == SIZE_MAX &&
		(c = tomlNameQuotedDec(name, str)) == SIZE_MAX)
		return SIZE_MAX;
	count += c, str += c, name = name ? name + strLen(name) : 0;
	// декодировать последующие части
	while ((c = tomlDelimDec(str, '.')) != SIZE_MAX)
	{
		count += c, str += c;
		if (name)
		{
			ASSERT(memIsValid(name, 2));
			name[0] = '.', name[1] = 0, ++name;
		}
		if ((c = tomlNameBareDec(name, str)) == SIZE_MAX &&
			(c = tomlNameQuotedDec(name, str)) == SIZE_MAX)
			return SIZE_MAX;
		count += c, str += c, name = name ? name + strLen(name) : 0;
	}
	return count;
}

bool_t tomlNameIsValid(const char* name)
{
	size_t count;
	// можно декодировать => корректное имя?
	if ((count = tomlNameDec(0, name)) == SIZE_MAX)
		return FALSE;
	// ничего кроме имени?
	ASSERT(memIsValid(name + count, 1));
	return name[count] == 0;
}

static size_t tomlNameDec2(const char* str, const char* name)
{
	size_t count;
	size_t c;
	// pre
	ASSERT(strIsValid(str));
	ASSERT(tomlNameIsValid(name));
	// пропустить пробелы
	count = tomlSpaceDec(str);
	str += count;
	// декодировать первую часть имени
	VERIFY((c = tomlNameBareDec(0, name)) != SIZE_MAX ||
		(c = tomlNameQuotedDec(0, name)) != SIZE_MAX);
	if (strLen(str) < c || !memEq(str, name, c))
		return SIZE_MAX;
	count += c, str += c, name += c;
	// декодировать последующие части
	while ((c = tomlDelimDec(name, '.')) != SIZE_MAX)
	{
		name += c;
		if ((c = tomlDelimDec(str, '.')) == SIZE_MAX)
			return SIZE_MAX;
		count += c, str += c;
		VERIFY((c = tomlNameBareDec(0, name)) != SIZE_MAX ||
			(c = tomlNameQuotedDec(0, name)) != SIZE_MAX);
		if (strLen(str) < c || !memEq(str, name, c))
			return SIZE_MAX;
		count += c, str += c, name += c;
	}
	return count;
}

static size_t tomlNameEnc(char* str, const char* name)
{
	size_t count;
	size_t c;
	// pre
	ASSERT(tomlNameIsValid(name));
	// кодировать первую часть имени
	VERIFY((c = tomlNameBareDec(str, name)) != SIZE_MAX ||
		(c = tomlNameQuotedDec(str, name)) != SIZE_MAX);
	count = c, name += c, str = str ? str + strLen(str) : 0;
	// кодировать последующие части
	while ((c = tomlDelimDec(name, '.')) != SIZE_MAX)
	{
		++count, name += c;
		if (str)
		{
			ASSERT(memIsValid(str, 2));
			str[0] = '.', str[1] = 0, ++str;
		}
		VERIFY((c = tomlNameBareDec(str, name)) != SIZE_MAX ||
			(c = tomlNameQuotedDec(str, name)) != SIZE_MAX);
		count += c, name += c, str = str ? str + strLen(str) : 0;
	}
	return count;
}

/*
*******************************************************************************
Секция
*******************************************************************************
*/

static size_t tomlSectionDec(char* section, const char* str)
{
	size_t count;
	size_t c;
	// декодировать [
	count = tomlDelimDec(str, '[');
	if (count == SIZE_MAX)
		return SIZE_MAX;
	str += count;
	// декодировать имя
	c = tomlNameDec(section, str);
	if (c == SIZE_MAX)
		return SIZE_MAX;
	count += c, str += c;
	// декодировать ]
	c = tomlDelimDec(str, ']');
	if (c == SIZE_MAX)
		return SIZE_MAX;
	return count + c;
}

static size_t tomlSectionDec2(const char* str, const char* section)
{
	size_t count;
	size_t c;
	// декодировать [
	count = tomlDelimDec(str, '[');
	if (count == SIZE_MAX)
		return SIZE_MAX;
	str += count;
	// декодировать имя
	c = tomlNameDec2(str, section);
	if (c == SIZE_MAX)
		return SIZE_MAX;
	count += c, str += c;
	// декодировать ]
	c = tomlDelimDec(str, ']');
	if (c == SIZE_MAX)
		return SIZE_MAX;
	return count + c;
}

static size_t tomlSectionEnc(char* str, const char* section)
{
	size_t count;
	size_t c;
	// кодировать [
	count = tomlDelimEnc(str, '[');
	if (count == SIZE_MAX)
		return SIZE_MAX;
	str += count;
	// кодировать имя
	c = tomlNameEnc(str, section);
	if (c == SIZE_MAX)
		return SIZE_MAX;
	count += c, str += c;
	// кодировать ]
	c = tomlDelimEnc(str, ']');
	if (c == SIZE_MAX)
		return SIZE_MAX;
	return count + c;
}

/*
*******************************************************************************
Ключ

\remark Следующая функция не потребовалась:
\code
	static size_t tomlKeyDec(char* key, const char* str)
	{
		size_t count;
		size_t c;
		// декодировать имя
		count = tomlNameDec(key, str);
		if (count == SIZE_MAX)
			return SIZE_MAX;
		str += count;
		// декодировать =
		c = tomlDelimDec(str, '=');
		if (c == SIZE_MAX)
			return SIZE_MAX;
		return count + c;
	}
\endcode
*******************************************************************************
*/

static size_t tomlKeyDec2(const char* str, const char* key)
{
	size_t count;
	size_t c;
	// декодировать имя
	count = tomlNameDec2(str, key);
	if (count == SIZE_MAX)
		return SIZE_MAX;
	str += count;
	// декодировать =
	c = tomlDelimDec(str, '=');
	if (c == SIZE_MAX)
		return SIZE_MAX;
	return count + c;
}

static size_t tomlKeyEnc(char* str, const char* key)
{
	size_t count;
	size_t c;
	// кодировать имя
	count = tomlNameEnc(str, key);
	if (count == SIZE_MAX)
		return SIZE_MAX;
	str += count;
	c = tomlDelimEnc(str, ' ');
	if (c == SIZE_MAX)
		return SIZE_MAX;
	str += c;
    count += c;
	// кодировать =
	c = tomlDelimEnc(str, '=');
	if (c == SIZE_MAX)
		return SIZE_MAX;
	str += c;
    count += c;
	c = tomlDelimEnc(str, ' ');
	if (c == SIZE_MAX)
		return SIZE_MAX;
	return count + c;
}

/*
*******************************************************************************
Строка октетов
*******************************************************************************
*/

size_t tomlOctsEnc(char* str, const octet* val, size_t count)
{
	ASSERT(memIsValid(val, count));
	if (str)
	{
		ASSERT(memIsValid(str, 2 + 2 * count + 1));
		str[0] = '0', str[1] = 'x';
		hexFrom(str + 2, val, count);
	}
	return 2 + 2 * count;
}

size_t tomlOctsDec(octet* val, size_t* count, const char* str)
{
	char s[3];
	size_t len;
	size_t c;
	size_t co;
	// пропустить предваряющие пробелы
	str += (c = tomlSpaceDec(str));
	// префикс 0x?
	if (!strStartsWith(str, "0x"))
		return SIZE_MAX;
	c += 2, str += 2;
	// декодировать шестнадцатеричные символы
	s[2] = 0;
	for (len = strLen(str), co = 0; len >= 2; len -= 2, str += 2)
	{
		s[0] = str[0], s[1] = str[1];
		if (!hexIsValid(s))
			break;
		if (val)
			hexTo(val++, s);
		++co;
	}
	s[0] = s[1] = 0;
	// возвратить число октетов
	if (count)
	{
		ASSERT(memIsValid(count, O_PER_S));
		*count = co;
	}
	// учесть завершающие пробелы
	return c + 2 * co + tomlSpaceDec(str);
}

/*
*******************************************************************************
Неотрицательное целое

Анализ переполнения:
  SIZE_MAX = 10 * q + r, q = SIZE_MAX / 10, r = SIZE_MAX % 10 (в синтаксисе C)
  10 * v + d > SIZE_MAX <=> v > q || v == q && d > r
*******************************************************************************
*/

size_t tomlSizeEnc(char* str, size_t val)
{
	size_t count = 0;
	do
	{
		if (str)
		{
			ASSERT(memIsValid(str + count, 1));
			str[count] = '0' + (char)(val % 10);
		}
		++count, val /= 10;
	}
	while (val);
	if (str)
	{
		str[count] = 0;
		strRev(str);
	}
	return count;
}

size_t tomlSizeDec(size_t* val, const char* str)
{
	register size_t v;
	size_t count;
	size_t c;
	// пропустить предваряющие пробелы
	str += (count = tomlSpaceDec(str));
	// незначащий нуль?
	ASSERT(strIsValid(str));
	if (str[0] == '0' && '0' <= str[1] && str[1] <= '9' )
		return SIZE_MAX;
	// декодировать
	for (v = c = 0; '0' <= *str && *str <= '9';)
	{
		if (v > SIZE_MAX / 10 || 
			v == SIZE_MAX / 10 && SIZE_MAX % 10 < (size_t)(*str - '0'))
			return SIZE_MAX;
		v *= 10, v += (size_t)(*str - '0');
		++c, ++str;
	}
	if (!c)
		return SIZE_MAX;
	count += c;
	// возвратить декодированное значение
	if (val)
	{
		ASSERT(memIsValid(val, O_PER_S));
		*val = v;
	}
	v = 0;
	// учесть завершающие пробелы
	return count + tomlSpaceDec(str);
}

/*
*******************************************************************************
Список неотрицательных целых
*******************************************************************************
*/

size_t tomlSizesEnc(char* str, const size_t* val, size_t count)
{
	size_t c;
	// pre
	ASSERT(memIsValid(val, count * O_PER_S));
	// [
	if (str)
	{
		ASSERT(memIsValid(str, 2));
		str[0] = '[', str[1] = 0;
		++str;
	}
	c = 1;
	// кодировать целые
	while (count--)
	{
		size_t cs = tomlSizeEnc(str, *val);
		if (cs == SIZE_MAX)
			return SIZE_MAX;
		c += cs, str = str ? str + cs : 0;
		// ,
		if (count)
		{
			if (str)
			{
				ASSERT(memIsValid(str, 2));
				str[0] = ',', str[1] = ' ', str[2] = 0;
				str += 2;
			}
			c += 2;
		}
		val++;
	}
	// ]
	if (str)
	{
		ASSERT(memIsValid(str, 2));
		str[0] = ']', str[1] = 0;
		++str;
	}
	return ++c;
}

size_t tomlSizesDec(size_t* val, size_t* count, const char* str)
{
	size_t c;
	size_t c1;
	size_t cs;
	// декодировать [
	c = tomlDelimDec(str, '[');
	if (c == SIZE_MAX)
		return SIZE_MAX;
	str += c;
	// декодировать первое целое
	cs = 0;
	c1 = tomlSizeDec(val, str);
	// декодировать следующие целые
	if (c1 != SIZE_MAX)
	{
		c += c1, str += c1, ++cs, val = val ? val + 1 : 0;
		while ((c1 = tomlDelimDec(str, ',')) != SIZE_MAX)
		{
			c += c1, str += c1;
			if ((c1 = tomlSizeDec(val, str)) == SIZE_MAX)
				break;
			c += c1, str += c1, ++cs, val = val ? val + 1 : 0;
		}
	}
	// декодировать ]
	c1 = tomlDelimDec(str, ']');
	if (c1 == SIZE_MAX)
		return SIZE_MAX;
	c += c1;
	// возвратить длину списка
	if (count)
	{
		ASSERT(memIsValid(count, O_PER_S));
		*count = cs;
	}
	return c;
}

