/*
*******************************************************************************
\file b64_test.c
\brief Tests for base64 encoding
\project bee2/test
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2016.06.16
\version 2016.06.16
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include <bee2/core/b64.h>
#include <bee2/core/mem.h>
#include <bee2/crypto/belt.h>

/*
*******************************************************************************
Тестирование
*******************************************************************************
*/

bool_t b64Test()
{
	octet buf[256];
	char b64[255 / 3 * 4 + 1];
	size_t count;
	// валидация
	if (!b64IsValid("1234") ||
		b64IsValid("AbC=") ||
		!b64IsValid("AbE=") ||
		b64IsValid("AbCBD4==") ||
		!b64IsValid("AbCBDg==") ||
		b64IsValid("AbC78a8@") ||
		b64IsValid("AbC78a8") ||
		b64IsValid("AbC7===") ||
		b64IsValid("Ab=7=="))
		return FALSE;
	// кодировать / декодировать
	for (count = 0; count < 256; ++count)
	{
		size_t t;
		b64From(b64, beltH(), count);
		b64To(0, &t, b64);
		if (t != count)
			return FALSE;
		t += 1;
		b64To(buf, &t, b64);
		if (t != count)
			return FALSE;
		if (!memEq(buf, beltH(), count))
			return FALSE;
	}
	// все нормально
	return TRUE;
}
