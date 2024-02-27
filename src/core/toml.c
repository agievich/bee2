/*
*******************************************************************************
\file toml.c
\brief TOML files processing
\project bee2 [cryptographic library]
\created 2023.07.12
\version 2024.02.26
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/core/hex.h"
#include "bee2/core/mem.h"
#include "bee2/core/toml.h"
#include "bee2/core/str.h"
#include "bee2/core/util.h"

#include <ctype.h>

#define TOML_BUF_SIZE 1000

/*
*******************************************************************************
Специальные символы

Правила TOML:
* Whitespace means tab (0x09) or space (0x20).
* Newline means LF (0x0A) or CRLF (0x0D 0x0A).
* A hash symbol marks the rest of the line as a comment, except when inside
  a string.
* Control characters other than tab (U+0000 to U+0008, U+000A to U+001F,
  U+007F) are not permitted in comments.

Детали реализации:
* Функция tomlSpaceDec() возвращает число пробелов вплоть до первого непробела
  или конца строки (что встретится первым). Возвращает 0, если пробелов нет.
  Никогда не возвращает SIZE_MAX.
* Функция tomlLFDec() возвращает число символов вплоть до первого непробела
  после LF или CRLF или до конца строки (что встретится первым). 
* Функция tomlCommentDec() возвращает число символов вплоть до LF или CRLF
  или конца строки (что встретится первым). Возвращает 0, если комментарий
  отсутствует. Возвращает SIZE_MAX, если комментарий включает недопустимые
  символы.
* Функция tomlVertDec() возвращает число символов вплоть до первого непробела
  после блока из комментариев и пустых строк (завершаются LF или CRLF).
  Никогда не возвращает SIZE_MAX.
*******************************************************************************
*/

static bool_t strIsSpace(char ch)
{
	return ch == ' ' || ch == '\t';
}

static bool_t strIsAlnum(char ch) 
{
	return (bool_t)isalnum(ch);
}

static size_t tomlSpaceDec(const char* toml)
{
	size_t count;
	ASSERT(strIsValid(toml));
	for (count = 0; strIsSpace(toml[count]); ++count);
	return count;
}

static size_t tomlDelimDec(const char* toml, char delim)
{
	size_t count;
	// пропустить пробелы
	count = tomlSpaceDec(toml);
	toml += count;
	// разделитель?
	if (*toml != delim)
		return SIZE_MAX;
	++count, ++toml;
	// пропустить пробелы
	return count + tomlSpaceDec(toml);
}

static size_t tomlDelimEnc(char* toml, char delim)
{
	if (toml)
	{
		ASSERT(memIsValid(toml, 2));
		toml[0] = delim, toml[1] = 0;
	}
	return 1;
}

static size_t tomlLFDec(const char* toml)
{
	size_t count;
	// пропустить пробелы
	count = tomlSpaceDec(toml);
	toml += count;
	// конец всей строки?
	if (toml[0] == 0)
		return count;
	// LF?
	if (toml[0] == '\n')
		++count, ++toml;
	else if (toml[0] == '\r' && toml[1] == '\n')
		count += 2, toml += 2;
	else
		return SIZE_MAX;
	// пропустить пробелы
	return count + tomlSpaceDec(toml);
}

#define tomlLFEnc(toml) tomlDelimEnc(toml, '\n')

static size_t tomlCommentDec(const char* toml)
{
	size_t count = 0;
	ASSERT(strIsValid(toml));
	while (1)
	{
		size_t c;
		// есть комментарий?
		c = tomlDelimDec(toml, '#');
		if (c == SIZE_MAX)
			break;
		// обработать комментарий
		count += c, toml += c;
		while (toml[0] && toml[0] != '\n')
			++count, ++toml;
		// комментарий не продолжается на следующей строке?
		c = tomlLFDec(toml);
		if (c == SIZE_MAX || tomlDelimDec(toml + c, '#') == SIZE_MAX)
			break;
		// к следующей строке
		count += c, toml += c;
	}
	return count;
}

static size_t tomlVertDec(const char* toml)
{
	size_t count = 0;
	while (*toml)
	{
		size_t c;
		// комментарий или LF?
		if ((c = tomlCommentDec(toml)) != SIZE_MAX ||
			(c = tomlLFDec(toml)) != SIZE_MAX)
			count += c, toml += c;
		else
			break;
	}
	return count;
}

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

static size_t tomlNameBareDec(char* name, const char* toml)
{
	size_t count;
	// pre
	ASSERT(strIsValid(toml));
	// выделить имя
	for (count = 0; strIsAlnum(toml[count]) ||
		toml[count] == '_' || toml[count] == '-';
		++count);
	if (!count)
		return SIZE_MAX;
	// сохранить имя
	if (name)
	{
		ASSERT(memIsValid(name, count + 1));
		memCopy(name, toml, count);
		name[count] = 0;
	}
	return count;
}

static size_t tomlNameQuotedDec(char* name, const char* toml)
{
	size_t count;
	// pre
	ASSERT(strIsValid(toml));
	// начинается с кавычки?
	if (toml[0] != '\'' && toml[0] != '"')
		return SIZE_MAX;
	// искать закрывающую кавычку
	for (count = 1; toml[count] != toml[0]; ++count)
		if (toml[count] == 0)
			return SIZE_MAX;
	++count;
	// сохранить имя
	if (name)
	{
		ASSERT(memIsValid(name, count + 1));
		memCopy(name, toml, count);
		name[count] = 0;
	}
	return count;
}

static size_t tomlNameDec(char* name, const char* toml)
{
	size_t count;
	size_t c;
	// пропустить пробелы
	count = tomlSpaceDec(toml);
	toml += count;
	// декодировать первую часть имени
	if ((c = tomlNameBareDec(name, toml)) == SIZE_MAX &&
		(c = tomlNameQuotedDec(name, toml)) == SIZE_MAX)
		return SIZE_MAX;
	count += c, toml += c, name = name ? name + strLen(name) : 0;
	// декодировать последующие части
	while ((c = tomlDelimDec(toml, '.')) != SIZE_MAX)
	{
		count += c, toml += c;
		if (name)
		{
			ASSERT(memIsValid(name, 2));
			name[0] = '.', name[1] = 0, ++name;
		}
		if ((c = tomlNameBareDec(name, toml)) == SIZE_MAX &&
			(c = tomlNameQuotedDec(name, toml)) == SIZE_MAX)
			return SIZE_MAX;
		count += c, toml += c, name = name ? name + strLen(name) : 0;
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

static size_t tomlNameDec2(const char* toml, const char* name)
{
	size_t count;
	size_t c;
	// pre
	ASSERT(strIsValid(toml));
	ASSERT(tomlNameIsValid(name));
	// пропустить пробелы
	count = tomlSpaceDec(toml);
	toml += count;
	// декодировать первую часть имени
	VERIFY((c = tomlNameBareDec(0, name)) != SIZE_MAX ||
		(c = tomlNameQuotedDec(0, name)) != SIZE_MAX);
	if (strLen(toml) < c || !memEq(toml, name, c))
		return SIZE_MAX;
	count += c, toml += c, name += c;
	// декодировать последующие части
	while ((c = tomlDelimDec(name, '.')) != SIZE_MAX)
	{
		name += c;
		if ((c = tomlDelimDec(toml, '.')) == SIZE_MAX)
			return SIZE_MAX;
		count += c, toml += c;
		VERIFY((c = tomlNameBareDec(0, name)) != SIZE_MAX ||
			(c = tomlNameQuotedDec(0, name)) != SIZE_MAX);
		if (strLen(toml) < c || !memEq(toml, name, c))
			return SIZE_MAX;
		count += c, toml += c, name += c;
	}
	return count;
}

static size_t tomlNameEnc(char* toml, const char* name)
{
	size_t count;
	size_t c;
	// pre
	ASSERT(tomlNameIsValid(name));
	// кодировать первую часть имени
	VERIFY((c = tomlNameBareDec(toml, name)) != SIZE_MAX ||
		(c = tomlNameQuotedDec(toml, name)) != SIZE_MAX);
	count = c, name += c, toml = toml ? toml + strLen(toml) : 0;
	// кодировать последующие части
	while ((c = tomlDelimDec(name, '.')) != SIZE_MAX)
	{
		++count, name += c;
		if (toml)
		{
			ASSERT(memIsValid(toml, 2));
			toml[0] = '.', toml[1] = 0, ++toml;
		}
		VERIFY((c = tomlNameBareDec(toml, name)) != SIZE_MAX ||
			(c = tomlNameQuotedDec(toml, name)) != SIZE_MAX);
		count += c, name += c, toml = toml ? toml + strLen(toml) : 0;
	}
	return count;
}

/*
*******************************************************************************
Секция
*******************************************************************************
*/

static size_t tomlSectionDec(char* section, const char* toml)
{
	size_t count;
	size_t c;
	// декодировать [
	count = tomlDelimDec(toml, '[');
	if (count == SIZE_MAX)
		return SIZE_MAX;
	toml += count;
	// декодировать имя
	c = tomlNameDec(section, toml);
	if (c == SIZE_MAX)
		return SIZE_MAX;
	count += c, toml += c;
	// декодировать ]
	c = tomlDelimDec(toml, ']');
	if (c == SIZE_MAX)
		return SIZE_MAX;
	return count + c;
}

static size_t tomlSectionDec2(const char* toml, const char* section)
{
	size_t count;
	size_t c;
	// декодировать [
	count = tomlDelimDec(toml, '[');
	if (count == SIZE_MAX)
		return SIZE_MAX;
	toml += count;
	// декодировать имя
	c = tomlNameDec2(toml, section);
	if (c == SIZE_MAX)
		return SIZE_MAX;
	count += c, toml += c;
	// декодировать ]
	c = tomlDelimDec(toml, ']');
	if (c == SIZE_MAX)
		return SIZE_MAX;
	return count + c;
}

static size_t tomlSectionEnc(char* toml, const char* section)
{
	size_t count;
	size_t c;
	// кодировать [
	count = tomlDelimEnc(toml, '[');
	if (count == SIZE_MAX)
		return SIZE_MAX;
	toml += count;
	// кодировать имя
	c = tomlNameEnc(toml, section);
	if (c == SIZE_MAX)
		return SIZE_MAX;
	count += c, toml += c;
	// кодировать ]
	c = tomlDelimEnc(toml, ']');
	if (c == SIZE_MAX)
		return SIZE_MAX;
	return count + c;
}

/*
*******************************************************************************
Ключ

\remark Следующая функция не потребовалась:
\code
	static size_t tomlKeyDec(char* key, const char* toml)
	{
		size_t count;
		size_t c;
		// декодировать имя
		count = tomlNameDec(key, toml);
		if (count == SIZE_MAX)
			return SIZE_MAX;
		toml += count;
		// декодировать =
		c = tomlDelimDec(toml, '=');
		if (c == SIZE_MAX)
			return SIZE_MAX;
		return count + c;
	}
\endcode
*******************************************************************************
*/

static size_t tomlKeyDec2(const char* toml, const char* key)
{
	size_t count;
	size_t c;
	// декодировать имя
	count = tomlNameDec2(toml, key);
	if (count == SIZE_MAX)
		return SIZE_MAX;
	toml += count;
	// декодировать =
	c = tomlDelimDec(toml, '=');
	if (c == SIZE_MAX)
		return SIZE_MAX;
	return count + c;
}

static size_t tomlKeyEnc(char* toml, const char* key)
{
	size_t count;
	size_t c;
	// кодировать имя
	count = tomlNameEnc(toml, key);
	if (count == SIZE_MAX)
		return SIZE_MAX;
	toml += count;
	c = tomlDelimEnc(toml, ' ');
	if (c == SIZE_MAX)
		return SIZE_MAX;
	toml += c;
    count += c;
	// кодировать =
	c = tomlDelimEnc(toml, '=');
	if (c == SIZE_MAX)
		return SIZE_MAX;
	toml += c;
    count += c;
	c = tomlDelimEnc(toml, ' ');
	if (c == SIZE_MAX)
		return SIZE_MAX;
	return count + c;
}

/*
*******************************************************************************
Строка октетов
*******************************************************************************
*/

size_t tomlOctsEnc(char* toml, const octet* val, size_t count)
{
	ASSERT(memIsValid(val, count));
	if (toml)
	{
		ASSERT(memIsValid(toml, 2 + 2 * count + 1));
		toml[0] = '0', toml[1] = 'x';
		hexFrom(toml + 2, val, count);
	}
	return 2 + 2 * count;
}

static size_t tomlOctDec(octet* val, const char* toml)
{
	char hex[3];
	if (strLen(toml) < 2)
		return SIZE_MAX;
	hex[0] = toml[0], hex[1] = toml[1], hex[2] = 0;
	if (!hexIsValid(hex))
		return SIZE_MAX;
	if (val)
		hexTo(val, hex);
	hex[0] = hex[1] = 0;
	return 2;
}

size_t tomlOctsDec(octet* val, size_t* count, const char* toml)
{
	size_t c;
	size_t co;
	// пропустить предваряющие пробелы
	toml += (c = tomlSpaceDec(toml));
	// префикс 0x?
	if (!strStartsWith(toml, "0x"))
		return SIZE_MAX;
	c += 2, toml += 2, co = 0;
	// декодировать шестнадцатеричные символы
	while (1)
	{
		size_t c1;
		// LF?
		while (toml[0] == '\\')
		{
			// пропустить '\\'
			++c, ++toml;
			// пропустить комментарии
			if ((c1 = tomlCommentDec(toml)) != SIZE_MAX)
				c += c1, toml += c1;
			// к новой строке
			if ((c1 = tomlLFDec(toml)) == SIZE_MAX)
				return SIZE_MAX;
			c += c1, toml += c1;
		}
		// преобразовать пару шестнадцатеричных символов в октет
		if ((c1 = tomlOctDec(val, toml)) == SIZE_MAX)
			break;
		c += c1, toml += c1, ++co;
		val = val ? val + 1 : val;
	}
	// возвратить число октетов
	if (count)
	{
		ASSERT(memIsValid(count, O_PER_S));
		*count = co;
	}
	// учесть завершающие пробелы
	return c + tomlSpaceDec(toml);
}

/*
*******************************************************************************
Неотрицательное целое

Анализ переполнения:
  SIZE_MAX = 10 * q + r, q = SIZE_MAX / 10, r = SIZE_MAX % 10 (в синтаксисе C)
  10 * v + d > SIZE_MAX <=> v > q || v == q && d > r
*******************************************************************************
*/

size_t tomlSizeEnc(char* toml, size_t val)
{
	size_t count = 0;
	do
	{
		if (toml)
		{
			ASSERT(memIsValid(toml + count, 1));
			toml[count] = '0' + (char)(val % 10);
		}
		++count, val /= 10;
	}
	while (val);
	if (toml)
	{
		toml[count] = 0;
		strRev(toml);
	}
	return count;
}

size_t tomlSizeDec(size_t* val, const char* toml)
{
	register size_t v;
	size_t count;
	size_t c;
	// пропустить предваряющие пробелы
	toml += (count = tomlSpaceDec(toml));
	// незначащий нуль?
	ASSERT(strIsValid(toml));
	if (toml[0] == '0' && '0' <= toml[1] && toml[1] <= '9' )
		return SIZE_MAX;
	// декодировать
	for (v = c = 0; '0' <= *toml && *toml <= '9';)
	{
		if (v > SIZE_MAX / 10 || 
			v == SIZE_MAX / 10 && SIZE_MAX % 10 < (size_t)(*toml - '0'))
			return SIZE_MAX;
		v *= 10, v += (size_t)(*toml - '0');
		++c, ++toml;
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
	return count + tomlSpaceDec(toml);
}

/*
*******************************************************************************
Список неотрицательных целых
*******************************************************************************
*/

size_t tomlSizesEnc(char* toml, const size_t* val, size_t count)
{
	size_t c;
	// pre
	ASSERT(memIsValid(val, count * O_PER_S));
	// [
	if (toml)
	{
		ASSERT(memIsValid(toml, 2));
		toml[0] = '[', toml[1] = 0;
		++toml;
	}
	c = 1;
	// кодировать целые
	while (count--)
	{
		size_t cs = tomlSizeEnc(toml, *val);
		if (cs == SIZE_MAX)
			return SIZE_MAX;
		c += cs, toml = toml ? toml + cs : 0;
		// ,
		if (count)
		{
			if (toml)
			{
				ASSERT(memIsValid(toml, 2));
				toml[0] = ',', toml[1] = ' ', toml[2] = 0;
				toml += 2;
			}
			c += 2;
		}
		val++;
	}
	// ]
	if (toml)
	{
		ASSERT(memIsValid(toml, 2));
		toml[0] = ']', toml[1] = 0;
		++toml;
	}
	return ++c;
}

size_t tomlSizesDec(size_t* val, size_t* count, const char* toml)
{
	size_t c;
	size_t c1;
	size_t cs;
	// декодировать [
	c = tomlDelimDec(toml, '[');
	if (c == SIZE_MAX)
		return SIZE_MAX;
	toml += c;
	// декодировать первое целое
	cs = 0;
	c1 = tomlSizeDec(val, toml);
	// декодировать следующие целые
	if (c1 != SIZE_MAX)
	{
		c += c1, toml += c1, ++cs, val = val ? val + 1 : 0;
		while ((c1 = tomlDelimDec(toml, ',')) != SIZE_MAX)
		{
			c += c1, toml += c1;
			if ((c1 = tomlSizeDec(val, toml)) == SIZE_MAX)
				break;
			c += c1, toml += c1, ++cs, val = val ? val + 1 : 0;
		}
	}
	// декодировать ]
	c1 = tomlDelimDec(toml, ']');
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

