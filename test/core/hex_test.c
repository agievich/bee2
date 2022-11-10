/*
*******************************************************************************
\file hex_test.c
\brief Tests for hexadecimal strings
\project bee2/test
\created 2016.06.17
\version 2016.06.17
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include <bee2/core/hex.h>
#include <bee2/core/mem.h>
#include <bee2/core/str.h>
#include <bee2/crypto/belt.h>

/*
*******************************************************************************
Тестирование
*******************************************************************************
*/

bool_t hexTest()
{
	octet buf[256];
	char hex[512 + 1];
	char hex1[512 + 1];
	size_t count;
	// валидация
	if (!hexIsValid("1234") ||
		hexIsValid("12345") ||
		!hexIsValid("ABCDEFabcdef") ||
		hexIsValid("abcdefgh"))
		return FALSE;
	// кодировать / декодировать
	for (count = 0; count <= 256; ++count)
	{
		hexFrom(hex, beltH(), count);
		if (!hexEq(beltH(), hex))
			return FALSE;
		hexTo(buf, hex);
		if (!memEq(buf, beltH(), count))
			return FALSE;
		hexFromRev(hex, beltH(), count);
		if (!hexEqRev(beltH(), hex))
			return FALSE;
		hexToRev(buf, hex);
		if (!memEq(buf, beltH(), count))
			return FALSE;
		memCopy(hex1, hex, sizeof(hex));
		hexLower(hex1);
		hexUpper(hex1);
		if (!strEq(hex, hex1))
			return FALSE;
	}
	// все нормально
	return TRUE;
}
