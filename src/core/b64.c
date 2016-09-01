/*
*******************************************************************************
\file b64.c
\brief The Base64 encoding
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2016.06.16
\version 2016.09.01
\license This program is released under the GNU General Public License
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/b64.h"
#include "bee2/core/mem.h"
#include "bee2/core/str.h"
#include "bee2/core/util.h"

/*
*******************************************************************************
Таблицы

\todo Кодировка base64url: + меняется на -, / меняется на _.
*******************************************************************************
*/

static const char b64_alphabet[] = 
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz"
	"0123456789+/";

static const octet b64_dec_table[256] = {
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x3E,0xFF,0xFF,0xFF,0x3F,
	0x34,0x35,0x36,0x37,0x38,0x39,0x3A,0x3B,0x3C,0x3D,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,
	0x0F,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,
	0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F,0x30,0x31,0x32,0x33,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
};

/*
*******************************************************************************
Проверка
*******************************************************************************
*/

bool_t b64IsValid(const char* b64)
{
	size_t len;
	if (!strIsValid(b64))
		return FALSE;
	// проверить длину
	len = strLen(b64);
	if (len % 4)
		return FALSE;
	// обработать паддинг 
	if (len && b64[len - 1] == '=' && b64[--len - 1] == '=')
		--len;
	// последний блок данных из 2 октетов?
	if (len % 4 == 3)
	{
		if (b64_dec_table[(octet)b64[len - 1]] & 3)
			return FALSE;
		--len;
	}
	// последний блок данных из 1 октета?
	else if (len % 4 == 2)
	{
		if (b64_dec_table[(octet)b64[len - 1]] & 15)
			return FALSE;
		--len;
	}
	// проверить остальные символы 
	for (; len--; ++b64)
		if (b64_dec_table[(octet)*b64] == 0xFF)
			return FALSE;
	return TRUE;
}

/*
*******************************************************************************
Кодирование
*******************************************************************************
*/

void b64From(char* dest, const void* src, size_t count)
{
	register u32 block;
	ASSERT(memIsDisjoint2(src, count, dest, 4 * ((count + 2) / 3) + 1));
	for (; count >= 3; count -= 3)
	{
		block  = ((const octet*)src)[0], block <<= 8;
		block |= ((const octet*)src)[1], block <<= 8;
		block |= ((const octet*)src)[2];
		dest[3] = b64_alphabet[block & 63], block >>= 6;
		dest[2] = b64_alphabet[block & 63], block >>= 6;
		dest[1] = b64_alphabet[block & 63], block >>= 6;
		dest[0] = b64_alphabet[block];
		src = (const octet*)src + 3;
		dest += 4;
	}
	if (count == 2)
	{
		block  = ((const octet*)src)[0], block <<= 8;
		block |= ((const octet*)src)[1], block <<= 2;
		dest[3] = '=';
		dest[2] = b64_alphabet[block & 63], block >>= 6;
		dest[1] = b64_alphabet[block & 63], block >>= 6;
		dest[0] = b64_alphabet[block];
		dest += 4;
	}
	else if (count == 1)
	{
		block  = ((const octet*)src)[0], block <<= 4;
		dest[3] = dest[2] = '=';
		dest[1] = b64_alphabet[block & 63], block >>= 6;
		dest[0] = b64_alphabet[block];
		dest += 4;
	}
	*dest = '\0';
	block = 0;
}

void b64To(void* dest, size_t* count, const char* src)
{
	register u32 block;
	size_t len;
	ASSERT(b64IsValid(src));
	ASSERT(memIsValid(count, sizeof(size_t)));
	ASSERT(memIsNullOrValid(dest, *count));
	// размер dest
	len = strLen(src);
	if (len && src[len - 1] == '=' && src[--len - 1] == '=')
		--len;
	ASSERT(dest ? *count >= 3 * (len / 4) + (len & 1) + (len >> 1 & 1) : TRUE);
	*count = 3 * (len / 4) + (len & 1) + (len >> 1 & 1);
	if (dest == 0)
		return;
	// декодировать
	ASSERT(memIsDisjoint2(src, strLen(src) + 1, dest, *count));
	for (; len >= 4; len -= 4)
	{
		block  = b64_dec_table[(octet)src[0]], block <<= 6;
		block |= b64_dec_table[(octet)src[1]], block <<= 6;
		block |= b64_dec_table[(octet)src[2]], block <<= 6;
		block |= b64_dec_table[(octet)src[3]];
		((octet*)dest)[2] = block & 255, block >>= 8;
		((octet*)dest)[1] = block & 255, block >>= 8;
		((octet*)dest)[0] = block;
		src += 4;
		dest = (octet*)dest + 3;
	}
	if (len == 3)
	{
		block  = b64_dec_table[(octet)src[0]], block <<= 6;
		block |= b64_dec_table[(octet)src[1]], block <<= 6;
		block |= b64_dec_table[(octet)src[2]], block >>= 2;
		((octet*)dest)[1] = block & 255, block >>= 8;
		((octet*)dest)[0] = block;
	}
	else if (len == 2)
	{
		block  = b64_dec_table[(octet)src[0]], block <<= 6;
		block |= b64_dec_table[(octet)src[1]], block >>= 4;
		((octet*)dest)[0] = block;
	}
	block = 0;
}
