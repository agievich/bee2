/*
*******************************************************************************
\file bash-test.c
\brief Tests for STB 34.101.bash
\project bee2/test
\author (С) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2015.09.22
\version 2015.10.29
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include <bee2/core/mem.h>
#include <bee2/core/hex.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include <bee2/crypto/bash.h>
#include <bee2/crypto/belt.h>

#include <stdio.h>

/*
*******************************************************************************
Форматирование hex-строки

Строка str расширяется форматными символами.
\pre Памяти по адресу str хватает.
*******************************************************************************
*/

void strHexFormat(char* str)
{
	size_t i = 0;
	for (; *str; ++i, ++str)
	{
		if (i && i % 16 == 0)
		{
			memMove(str + 1, str, strLen(str) + 1);
			*str = (i % 64) ? '~' : '\n';
			++str;
		}
	}
}

/*
*******************************************************************************
Самотестирование

Создаются тесты для приложения А к СТБ 34.101.bash.
*******************************************************************************
*/

bool_t bashTest()
{
	octet buf[192];
	octet hash[64];
	char str[1024];
	octet state[1024];
	// создать стек
	ASSERT(sizeof(state) >= bash256_keep());
	ASSERT(sizeof(state) >= bash384_keep());
	ASSERT(sizeof(state) >= bash512_keep());
	// тест A.1
	memCopy(buf, beltGetH(), 192);
	hexFrom(str, buf, 192);
	strHexFormat(str);
	printf("A.1 (pre):\n%s\n", str);
	bashF(buf);
	hexFrom(str, buf, 192);
	strHexFormat(str);
	printf("A.1:\n%s\n", str);
	// тест A.2
	bash256Hash(hash, beltGetH(), 0);
	hexFrom(str, hash, 32);
	strHexFormat(str);
	printf("A.2:\n%s\n", str);
	// тест A.3
	bash256Hash(hash, beltGetH(), 127);
	hexFrom(str, hash, 32);
	strHexFormat(str);
	printf("A.3:\n%s\n", str);
	// тест A.4
	bash256Hash(hash, beltGetH(), 128);
	hexFrom(str, hash, 32);
	strHexFormat(str);
	printf("A.4:\n%s\n", str);
	// тест A.5
	bash256Hash(hash, beltGetH(), 135);
	hexFrom(str, hash, 32);
	strHexFormat(str);
	printf("A.5:\n%s\n", str);
	// тест A.6
	bash384Hash(hash, beltGetH(), 95);
	hexFrom(str, hash, 48);
	strHexFormat(str);
	printf("A.6:\n%s\n", str);
	// тест A.7
	bash384Hash(hash, beltGetH(), 96);
	hexFrom(str, hash, 48);
	strHexFormat(str);
	printf("A.7:\n%s\n", str);
	// тест A.8
	bash384Hash(hash, beltGetH(), 108);
	hexFrom(str, hash, 48);
	strHexFormat(str);
	printf("A.8:\n%s\n", str);
	// тест A.9
	bash512Hash(hash, beltGetH(), 63);
	hexFrom(str, hash, 64);
	strHexFormat(str);
	printf("A.9:\n%s\n", str);
	// тест A.10
	bash512Hash(hash, beltGetH(), 64);
	hexFrom(str, hash, 64);
	strHexFormat(str);
	printf("A.10:\n%s\n", str);
	// тест A.11
	bash512Hash(hash, beltGetH(), 127);
	hexFrom(str, hash, 64);
	strHexFormat(str);
	printf("A.11:\n%s\n", str);
	// тест A.12
	bash512Hash(hash, beltGetH(), 192);
	hexFrom(str, hash, 64);
	strHexFormat(str);
	printf("A.12:\n%s\n", str);
	// все нормально
	return TRUE;
}


