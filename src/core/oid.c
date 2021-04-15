/*
*******************************************************************************
\file oid.c
\brief Object identifiers
\project bee2 [cryptographic library]
\author Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2013.02.04
\version 2021.04.12
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
	return derEncOID(der, oid);
}

size_t oidFromDER(char* oid, const octet der[], size_t count)
{
	size_t len, c;
	c = derDecOID(oid, &len, der, count);
	if (len == SIZE_MAX || c != count)
		return SIZE_MAX;
	return len;
}
