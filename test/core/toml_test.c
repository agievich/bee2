/*
*******************************************************************************
\file toml_test.c
\brief Tests for TOML
\project bee2/test
\created 2023.08.22
\version 2024.02.29
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/core/toml.h"
#include "bee2/core/err.h"
#include "bee2/core/hex.h"
#include "bee2/core/mem.h"
#include "bee2/core/str.h"
#include "bee2/core/util.h"

/*
*******************************************************************************
Кодирование
*******************************************************************************
*/

bool_t tomlTestEnc()
{
	char toml[1024];
	size_t count;
	octet octs[16];
	size_t sizes[8];
	// имя
	if (tomlNameIsValid("bare@name") ||
		!tomlNameIsValid("bare_name") ||
		!tomlNameIsValid("bare-name") ||
		!tomlNameIsValid("\'quoted_name\'") ||
		!tomlNameIsValid("\"quoted@name\"") ||
		tomlNameIsValid("\'quoted_name\"") ||
		!tomlNameIsValid("\"\"") ||
		!tomlNameIsValid("\'\'") ||
		!tomlNameIsValid("dotted.name") ||
		!tomlNameIsValid("dotted . name") ||
		tomlNameIsValid("dotted..name") ||
		!tomlNameIsValid("dotted.\"\".name") ||
		!tomlNameIsValid("dotted.\' name \'") ||
		!tomlNameIsValid("3.14159265") ||
		!tomlNameIsValid("192.168.208.1") ||
		tomlNameIsValid("192.168.208.1 "))
		return FALSE;
	// строка октетов
	if (tomlOctsDec(0, 0, "0x") != 2 ||
		tomlOctsDec(0, &count, "0x1") != 2 || count != 0 ||
		tomlOctsDec(0, &count, "0x123") != 4 || count != 1 ||
		tomlOctsDec(0, 0, "0x12") != 4 ||
		tomlOctsDec(octs, 0, " 0x1234") != 7 ||
		tomlOctsDec(octs, 0, "0x1234 ,") != 7 ||
		tomlOctsDec(0, &count, " 0x1234 ") != 8 || count != 2 ||
		tomlOctsDec(0, &count, " 0x12\\") != 6 || count != 1 ||
		tomlOctsDec(0, &count, " 0x1\\2") != 3 || count != 0 ||
		tomlOctsDec(0, &count, " 0x12\\ #\n34 #\n") != 12 || count != 2 ||
		tomlOctsDec(0, &count, " 0x12\\\n\\\n34\n") != 7 || count != 1 ||
		tomlOctsDec(0, &count, " 0x12\\\n  34") != 11 || count != 2 ||
		tomlOctsDec(0, &count, "0x12\\ #hex \n  34") != 16 || count != 2 ||
		tomlOctsEnc(0, octs, count) != 6 ||
		tomlOctsEnc(toml, octs, count) != 6 ||
		!strEq(toml, "0x1234"))
		return FALSE;
	// неотрицательное целое
	if (tomlSizeDec(0, "]") != SIZE_MAX ||
		tomlSizeDec(0, "00") != SIZE_MAX ||
		tomlSizeDec(0, "01") != SIZE_MAX ||
		tomlSizeDec(sizes, "0") != 1 || sizes[0] != 0 ||
		tomlSizeDec(sizes, "123") != 3 || sizes[0] != 123 ||
		tomlSizeDec(sizes, " 123") != 4 || sizes[0] != 123 ||
		tomlSizeDec(sizes, "123 ") != 4 || sizes[0] != 123 ||
		tomlSizeDec(sizes, " 123 ") != 5 || sizes[0] != 123 ||
		tomlSizeEnc(toml, 0) != 1 || !strEq(toml, "0") ||
		tomlSizeEnc(toml, SIZE_MAX) == SIZE_MAX ||
		tomlSizeDec(sizes, toml) == SIZE_MAX ||
		sizes[0] != SIZE_MAX ||
		(toml[strLen(toml) - 1]++, tomlSizeDec(sizes, toml)) != SIZE_MAX)
		return FALSE;
	// список неотрицательных целых
	if (tomlSizesDec(0, 0, "[]") == SIZE_MAX ||
		tomlSizesDec(0, &count, "[]") == SIZE_MAX || count != 0 ||
		tomlSizesDec(0, 0, "[01,2]") != SIZE_MAX ||
		tomlSizesDec(0, 0, "[1 [ 2]") != SIZE_MAX ||
		tomlSizesDec(0, 0, "[1,,2]") != SIZE_MAX ||
		tomlSizesDec(0, 0, "[1,2,]") == SIZE_MAX ||
		tomlSizesDec(0, 0, "[1,2,,]") != SIZE_MAX ||
		tomlSizesDec(sizes, &count, " [1 , 2] ") != 9 ||
			count != 2 || sizes[0] != 1 || sizes[1] != 2 ||
		tomlSizesEnc(toml, sizes, count) == SIZE_MAX ||
		tomlSizesDec(sizes, &count, " [1 , 2] ") != 9 ||
			count != 2 || sizes[0] != 1 || sizes[1] != 2)
		return FALSE;
	// все хорошо
	return TRUE;
}

/*
*******************************************************************************
Интеграция тестов
*******************************************************************************
*/

bool_t tomlTest()
{
	return tomlTestEnc();
}
