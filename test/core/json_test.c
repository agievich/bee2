/*
*******************************************************************************
\file json_test.c
\brief Tests for JSON
\project bee2/test
\created 2025.05.08
\version 2025.05.10
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <bee2/core/json.h>
#include <bee2/core/mem.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>

/*
*******************************************************************************
Строки
*******************************************************************************
*/

static err_t jsonTestStr()
{
	const char* jsons[] =
	{
		"\"\"",
		"\n\"   \" ",
		"  \"\\\"\\\\\\/\\b\\n\\r\\t\"  ",
		"   \"{\\u002000, \\u00ffff }\"   ",
		"\"]",
		"\"\\u001g\"",
	};
	const char* str;
	size_t len;
	size_t count;
	size_t pos;
	// корректные объекты
	for (pos = 0; pos < 4; ++pos)
	{
		count = jsonStrDec(&str, &len, jsons[pos], strLen(jsons[pos]));
		if (count != strLen(jsons[pos]) || 
			len + 2 + 2 * pos != count ||
			!memEq(str, jsons[pos] + 1 + pos, len))
			return FALSE;
	}
	// некорректные
	for (; pos < COUNT_OF(jsons); ++pos)
	{
		count = jsonStrDec(&str, &len, jsons[pos], strLen(jsons[pos]));
		if (count != SIZE_MAX)
			return FALSE;
	}
	return TRUE;
}

/*
*******************************************************************************
Числа
*******************************************************************************
*/

static err_t jsonTestSize()
{
	const char* jsons[] =
	{
		" 0",
		"\n\n\n23\t\r",
		"23a",
#if (O_PER_S == 4)
		"4294967295",
#elif (O_PER_S == 8)
		"18446744073709551615",
#else
		"255",
#endif
		"00",
		"01",
		"{}",
		"a23",
		"",
		" ",
	};
	size_t size;
	size_t count;
	size_t pos;
	// корректные объекты
	count = jsonSizeDec(&size, jsons[0], strLen(jsons[0]));
	if (count != strLen(jsons[0]) || size != 0)
		return FALSE;
	count = jsonSizeDec(&size, jsons[1], strLen(jsons[1]));
	if (count != strLen(jsons[1]) || size != 23)
		return FALSE;
	count = jsonSizeDec(&size, jsons[2], strLen(jsons[2]));
	if (count != strLen(jsons[2]) - 1 || size != 23)
		return FALSE;
	count = jsonSizeDec(&size, jsons[3], strLen(jsons[3]));
	if (count != strLen(jsons[3]))
		return FALSE;
#if (O_PER_S == 4) || (O_PER_S == 8)
	{
		char str[32];
		strCopy(str, jsons[3]);
		str[strLen(str) - 1]++;
		if (jsonSizeDec(&size, str, strLen(str)) != SIZE_MAX)
			return FALSE;
	}
#endif
	// некорректные
	for (pos = 4; pos < COUNT_OF(jsons); ++pos)
	{
		count = jsonSizeDec(&size, jsons[pos], strLen(jsons[pos]));
		if (count != SIZE_MAX)
			return FALSE;
	}
	return TRUE;
}

/*
*******************************************************************************
Объекты
*******************************************************************************
*/

static err_t jsonTestObj()
{
	const char* names[] = { "a", "b", "c" };
	const char* jsons[] =
	{
		"   {}   ",
		"{\"a\"\n:\ttrue , \"b\"\r:  false, \"c\":\nnull}",
		"{\"a\":\"\\r\\u1234\", \"b\": 0,\"c\": 100000000000}",
		"{\"a\": [1, 2], \"b\": {\"d\":1}, \"c\": {\"e\":[{},{\"f\":[]}]}}",
		"{\"a\": [[[[[[[[null]]]]]]]], \"b\":[1], \"c\":[0,{}]}",
		"{\"a\": 1, \"a\": 1}",
		"{\"a\": 1, \"b\": [1}}",
		"{\"a\": 1, \"b\": 1,}",
		"{\"a\": \"\\\"}",
		"{\"a\": \"\t\" 1}",
		"{\"a\": }",
	};
	json_elem_t elems[3];
	size_t count;
	size_t pos;
	// корректные объекты
	count = jsonObjDec(elems, jsons[0], strLen(jsons[0]), 0, 0);
	if (count != strLen(jsons[0]))
		return FALSE;
	for (pos = 1; pos <= 4; ++pos)
	{
		count = jsonObjDec(elems, jsons[pos], strLen(jsons[pos]), names, 3);
		if (count != strLen(jsons[pos]))
			return FALSE;
	}
	// некорректные
	for (; pos <= 7; ++pos)
	{
		count = jsonObjDec(elems, jsons[pos], strLen(jsons[pos]), names, 2);
		if (count != SIZE_MAX)
			return FALSE;
	}
	for (; pos < COUNT_OF(jsons); ++pos)
	{
		count = jsonObjDec(elems, jsons[pos], strLen(jsons[pos]), names, 1);
		if (count != SIZE_MAX)
			return FALSE;
	}
	return TRUE;
}

/*
*******************************************************************************
Массивы
*******************************************************************************
*/

static err_t jsonTestArr()
{
	const char* jsons[] =
	{
		"   []   ",
		"[true, false, null, 1, \"\", {}]",
		"[[true, false], null, 1, \"\", {}]",
		"[[true, false], [null, 1], \"\", {}]",
		"[[true, false], [null, 1], [\"\", {}]]",
		"[[[true, false], [null, 1]], [\"\", {}]]",
		"[true, false, null, 1,]",
		"[true, , null, 1]",
		"[[true, , null, 1]",
		"[true, n]",
	};
	json_elem_t elems[6];
	size_t size;
	size_t count;
	size_t pos;
	// корректные объекты
	count = jsonArrDec(0, &size, jsons[0], strLen(jsons[0]));
	if (count != strLen(jsons[0]) || size != 0)
		return FALSE;
	for (pos = 1; pos <= 5; ++pos)
	{
		count = jsonArrDec(elems, &size, jsons[pos], strLen(jsons[pos]));
		if (count != strLen(jsons[pos]) || size != 7 - pos)
			return FALSE;
	}
	// некорректные
	for (; pos < COUNT_OF(jsons); ++pos)
	{
		count = jsonArrDec(0, &size, jsons[pos], strLen(jsons[pos]));
		if (count != SIZE_MAX)
			return FALSE;
	}
	return TRUE;
}

static err_t jsonTestEnc()
{
	const char* fmts[] =
	{
		"[\"%s\", %u, [{}, {}] ]",
		"{\"%s\" : %u}",
		"\"%s_%u\"",
	};
	char json[128];
	size_t count;
	size_t pos;
	// кодировать
	for (pos = 0; pos < COUNT_OF(fmts); ++pos)
	{
		count = jsonFmtEnc(0, sizeof(json), fmts[pos], "a", (unsigned)12);
		if (count == SIZE_MAX || count >= sizeof(json))
			return FALSE;
		count = jsonFmtEnc(json, 0, fmts[pos], "a", (unsigned)12);
		if (count == SIZE_MAX || count >= sizeof(json))
			return FALSE;
		count = jsonFmtEnc(0, 0, fmts[pos], "a", (unsigned)12);
		if (count == SIZE_MAX || count >= sizeof(json))
			return FALSE;
		count = jsonFmtEnc(json, sizeof(json), fmts[pos], "a", (unsigned)12);
		if (count == SIZE_MAX || count >= sizeof(json) || 
			!jsonIsValid(json, count))
			return FALSE;
	}
	return TRUE;
}

/*
*******************************************************************************
Главная функция
*******************************************************************************
*/

bool_t jsonTest()
{
	return jsonTestStr() && jsonTestSize() && jsonTestObj() && jsonTestArr() &&
		jsonTestEnc();
}
