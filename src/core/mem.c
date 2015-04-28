/*
*******************************************************************************
\file mem.c
\brief Memory management
\project bee2 [cryptographic library]
\author (С) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2012.12.18
\version 2015.02.25
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/mem.h"
#include "bee2/core/util.h"
#include "bee2/core/str.h"
#include "bee2/math/word.h"

/*
*******************************************************************************
Шестнадцатеричные символы
*******************************************************************************
*/

static octet _oFromHex(const char* hex)
{
	register octet o;
	ASSERT(memIsValid(hex, 2));
	// определить старшую тетраду
	if ('0' <= *hex && *hex <= '9')
		o = *hex - '0';
	else if ('A' <= *hex && *hex <= 'F')
		o = *hex - 'A' + 10;
	else if ('a' <= *hex && *hex <= 'f')
		o = *hex - 'a' + 10;
	else
		ASSERT(0);
	// к младшей тетраде
	o <<= 4, ++hex;
	// определить младшую тетраду
	if ('0' <= *hex && *hex <= '9')
		o |= *hex - '0';
	else if ('A' <= *hex && *hex <= 'F')
		o |= *hex - 'A' + 10;
	else if ('a' <= *hex && *hex <= 'f')
		o |= *hex - 'a' + 10;
	else
		ASSERT(0);
	// результат
	return o;
}

static const char _hex_symbols[] = "0123456789ABCDEF";

static void _oToHex(char* hex, register octet o)
{
	ASSERT(memIsValid(hex, 2));
	hex[0] = _hex_symbols[o >> 4];
	hex[1] = _hex_symbols[o & 15];
	o = 0;
}

/*
*******************************************************************************
Дополнительные функции

\remark Функция memWipe() повторяет функцию OPENSSL_cleanse()
из библиотеки OpenSSL:
\code
	unsigned char cleanse_ctr = 0;
	void OPENSSL_cleanse(void *ptr, size_t len)
	{
		unsigned char *p = ptr;
		size_t loop = len, ctr = cleanse_ctr;
		while(loop--)
		{
			*(p++) = (unsigned char)ctr;
			ctr += (17 + ((size_t)p & 0xF));
		}
		p=memchr(ptr, (unsigned char)ctr, len);
		if(p)
			ctr += (63 + (size_t)p);
		cleanse_ctr = (unsigned char)ctr;
	}
\endcode

\remark На платформе Windows есть функции SecureZeroMemory()
и RtlSecureZeroMemory(), которые, как и memWipe(), выполняют
гарантированную очистку памяти.

\todo Реализовать полноценную проверку корректности памяти.
*******************************************************************************
*/

bool_t memIsValid(const void* buf, size_t count)
{
	return count == 0 || buf != 0;
}

bool_t SAFE(memEq)(const void* buf1, const void* buf2, size_t count)
{
	register word diff = 0;
	ASSERT(memIsValid(buf1, count));
	ASSERT(memIsValid(buf2, count));
	for (; count >= O_PER_W; count -= O_PER_W)
	{
		diff |= *(const word*)buf1 ^ *(const word*)buf2;
		buf1 = (const word*)buf1 + 1;
		buf2 = (const word*)buf2 + 1;
	}
	while (count--)
	{
		diff |= *(const octet*)buf1 ^ *(const octet*)buf2;
		buf1 = (const octet*)buf1 + 1;
		buf2 = (const octet*)buf2 + 1;
	}
	return wordEq(diff, 0);
}

bool_t FAST(memEq)(const void* buf1, const void* buf2, size_t count)
{
	ASSERT(memIsValid(buf1, count));
	ASSERT(memIsValid(buf2, count));
	return memcmp(buf1, buf2, count) == 0;
}

int SAFE(memCmp)(const void* buf1, const void* buf2, size_t count)
{
	register word less = 0;
	register word greater = 0;
	register word w1;
	register word w2;
	ASSERT(memIsValid(buf1, count));
	ASSERT(memIsValid(buf2, count));
	if (count % O_PER_W)
	{
		w1 = w2 = 0;
		while (count-- % O_PER_W)
		{
			w1 = w1 << 8 | ((const octet*)buf1)[count];
			w2 = w2 << 8 | ((const octet*)buf2)[count];
		}
		less |= ~greater & wordLess01(w1, w2);
		greater |= ~less & wordGreater01(w1, w2);
	}
	count /= O_PER_W;
	while (count--)
	{
		w1 = ((const word*)buf1)[count];
		w2 = ((const word*)buf2)[count];
#if (OCTET_ORDER == BIG_ENDIAN)
		w1 = wordRev(w1);
		w2 = wordRev(w2);
#endif
		less |= ~greater & wordLess(w1, w2);
		greater |= ~less & wordGreater(w1, w2);
	}
	w1 = w2 = 0;
	return (wordEq(less, 0) - 1) | wordNeq(greater, 0);
}

int FAST(memCmp)(const void* buf1, const void* buf2, size_t count)
{
	const octet* b1 = (const octet*)buf1 + count;
	const octet* b2 = (const octet*)buf2 + count;
	ASSERT(memIsValid(buf1, count));
	ASSERT(memIsValid(buf2, count));
	while (count--)
		if (*--b1 > *--b2)
			return 1;
		else if (*b1 < *b2)
			return -1;
	return 0;
}

void memWipe(void* buf, size_t count)
{
	static octet wipe_ctr = 0;
	volatile octet* p = (octet*)buf;
	size_t ctr = wipe_ctr;
	size_t i = count;
	ASSERT(memIsValid(buf, count));
	// вычисления, которые должны показаться полезными оптимизатору
	while (i--)
		*(p++) = (octet)ctr, ctr += 17 + ((size_t)p & 15);
	p = memchr(buf, (octet)ctr, count);
	if (p)
		ctr += (63 + (size_t)p);
	wipe_ctr = (octet)ctr;
}

bool_t SAFE(memIsZero)(const void* buf, size_t count)
{
	register word diff = 0;
	ASSERT(memIsValid(buf, count));
	for (; count >= O_PER_W; count -= O_PER_W)
	{
		diff |= *(const word*)buf;
		buf = (const word*)buf + 1;
	}
	while (count--)
	{
		diff |= *(const octet*)buf;
		buf = (const octet*)buf + 1;
	}
	return (bool_t)wordEq(diff, 0);
}

bool_t FAST(memIsZero)(const void* buf, size_t count)
{
	ASSERT(memIsValid(buf, count));
	for (; count >= O_PER_W; count -= O_PER_W, buf = (const word*)buf + 1)
		if (*(const word*)buf)
			return FALSE;
	for (; count--; buf = (const octet*)buf + 1)
		if (*(const octet*)buf)
			return FALSE;
	return TRUE;
}

size_t memNonZeroSize(const void* buf, size_t count)
{
	ASSERT(memIsValid(buf, count));
	while (count--)
		if (*((const octet*)buf + count))
			return count + 1;
	return 0;
}

bool_t SAFE(memIsRep)(const void* buf, size_t count, octet o)
{
	register word diff = 0;
	ASSERT(memIsValid(buf, count));
	for (; count--; buf = (const octet*)buf + 1)
		diff |= *(const octet*)buf ^ o;
	return wordEq(diff, 0);
}

bool_t FAST(memIsRep)(const void* buf, size_t count, octet o)
{
	ASSERT(memIsValid(buf, count));
	for (; count--; buf = (const octet*)buf + 1)
		if (*(const octet*)buf != o)
			return FALSE;
	return TRUE;
}

bool_t memIsDisjoint(const void* buf1, const void* buf2, size_t count)
{
	ASSERT(memIsValid(buf1, count));
	ASSERT(memIsValid(buf2, count));
	return count == 0 || (const octet*)buf1 + count <= (const octet*)buf2 ||
		(const octet*)buf1 >= (const octet*)buf2 + count;
}

bool_t memIsSameOrDisjoint(const void* buf1, const void* buf2, size_t count)
{
	ASSERT(memIsValid(buf1, count));
	ASSERT(memIsValid(buf2, count));
	return buf1 == buf2 || count == 0 ||
		(const octet*)buf1 + count <= (const octet*)buf2 ||
		(const octet*)buf1 >= (const octet*)buf2 + count;
}

bool_t memIsDisjoint2(const void* buf1, size_t count1,
	const void* buf2, size_t count2)
{
	ASSERT(memIsValid(buf1, count1));
	ASSERT(memIsValid(buf2, count2));
	return count1 == 0 || count2 == 0 ||
		(const octet*)buf1 + count1 <= (const octet*)buf2 ||
		(const octet*)buf1 >= (const octet*)buf2 + count2;
}

bool_t memIsDisjoint3(const void* buf1, size_t count1,
	const void* buf2, size_t count2,
	const void* buf3, size_t count3)
{
	return memIsDisjoint2(buf1, count1, buf2, count2) &&
		memIsDisjoint2(buf1, count1, buf3, count3) &&
		memIsDisjoint2(buf2, count2, buf3, count3);
}

bool_t memIsDisjoint4(const void* buf1, size_t count1,
	const void* buf2, size_t count2,
	const void* buf3, size_t count3,
	const void* buf4, size_t count4)
{
	return memIsDisjoint2(buf1, count1, buf2, count2) &&
		memIsDisjoint2(buf1, count1, buf3, count3) &&
		memIsDisjoint2(buf1, count1, buf4, count4) &&
		memIsDisjoint3(buf2, count2, buf3, count3, buf4, count4);
}

void memJoin(void* dest, const void* src1, size_t count1, const void* src2,
	size_t count2)
{
	register octet o;
	size_t i;
	ASSERT(memIsValid(src1, count1));
	ASSERT(memIsValid(src2, count2));
	ASSERT(memIsValid(dest, count1 + count2));
repeat:
	if (memIsDisjoint2(dest, count1, src2, count2))
	{
		memMove(dest, src1, count1);
		memMove((octet*)dest + count1, src2, count2);
	}
	else if (memIsDisjoint2((octet*)dest + count1, count2, src1, count1))
	{
		memMove((octet*)dest + count1, src2, count2);
		memMove(dest, src1, count1);
	}
	else if (memIsDisjoint2(dest, count2, src1, count1))
	{
		// dest <- src2 || src1
		memMove(dest, src2, count2);
		memMove((octet*)dest + count2, src1, count1);
		// dest <- dest <<< count2
		for (i = 0; i < count2; ++i)
		{
			o = ((octet*)dest)[0];
			memMove(dest, (octet*)dest + 1, count1 + count2 - 1);
			((octet*)dest)[count1 + count2 - 1] = o;
		}
	}
	else if (memIsDisjoint2((octet*)dest + count2, count1, src2, count2))
	{
		// dest <- src2 || src1
		memMove((octet*)dest + count2, src1, count1);
		memMove(dest, src2, count2);
		// dest <- dest <<< count2
		for (i = 0; i < count2; ++i)
		{
			o = ((octet*)dest)[0];
			memMove(dest, (octet*)dest + 1, count1 + count2 - 1);
			((octet*)dest)[count1 + count2 - 1] = o;
		}
	}
	else
	{
		// src1 (src2) пересекается и с префиксом, и с суффиксом dest
		// длины count2 (count1) => и первый, и последний октет dest
		// не входят не входят ни в src1, ни в src2
		((octet*)dest)[0] = ((const octet*)src1)[0];
		((octet*)dest)[count1 + count2 - 1] = ((const octet*)src2)[count2 - 1];
		VERIFY(count1--);
		VERIFY(count2--);
		src1 = (const octet*)src1 + 1;
		dest = (octet*)dest + 1;
		goto repeat;
	}
}

void memXor(void* dest, const void* src1, const void* src2, size_t count)
{
	ASSERT(memIsSameOrDisjoint(src1, dest, count));
	ASSERT(memIsSameOrDisjoint(src2, dest, count));
	for (; count >= O_PER_W; count -= O_PER_W)
	{
		*(word*)dest = *(const word*)src1 ^ *(const word*)src2;
		src1 = (const word*)src1 + 1;
		src2 = (const word*)src2 + 1;
		dest = (word*)dest + 1;
	}
	while (count--)
	{
		*(octet*)dest = *(const octet*)src1 ^ *(const octet*)src2;
		src1 = (const octet*)src1 + 1;
		src2 = (const octet*)src2 + 1;
		dest = (octet*)dest + 1;
	}
}

void memXor2(void* dest, const void* src, size_t count)
{
	ASSERT(memIsSameOrDisjoint(src, dest, count));
	for (; count >= O_PER_W; count -= O_PER_W)
	{
		*(word*)dest ^= *(const word*)src;
		src = (const word*)src + 1;
		dest = (word*)dest + 1;
	}
	while (count--)
	{
		*(octet*)dest ^= *(const octet*)src;
		src = (const octet*)src + 1;
		dest = (octet*)dest + 1;
	}
}

void memSwap(void* buf1, void* buf2, size_t count)
{
	ASSERT(memIsDisjoint(buf1, buf2, count));
	for (; count >= O_PER_W; count -= O_PER_W)
	{
		SWAP(*(word*)buf1, *(word*)buf2);
		buf1 = (word*)buf1 + 1;
		buf2 = (word*)buf2 + 1;
	}
	while (count--)
	{
		SWAP(*(octet*)buf1, *(octet*)buf2);
		buf1 = (octet*)buf1 + 1;
		buf2 = (octet*)buf2 + 1;
	}
}

bool_t SAFE(memEqHex)(const void* buf, const char* hex)
{
	register word diff = 0;
	size_t count = strLen(hex);
	ASSERT(count % 2 == 0);
	ASSERT(memIsValid(buf, count / 2));
	for (; count; count -= 2, hex += 2, buf = (const octet*)buf + 1)
		diff |= *(const octet*)buf ^ _oFromHex(hex);
	return wordEq(diff, 0);
}

bool_t FAST(memEqHex)(const void* buf, const char* hex)
{
	size_t count = strLen(hex);
	ASSERT(count % 2 == 0);
	ASSERT(memIsValid(buf, count / 2));
	for (; count; count -= 2, hex += 2, buf = (const octet*)buf + 1)
		if (*(const octet*)buf != _oFromHex(hex))
			return FALSE;
	return TRUE;
}

bool_t SAFE(memEqHexRev)(const void* buf, const char* hex)
{
	register word diff = 0;
	size_t count = strLen(hex);
	ASSERT(count % 2 == 0);
	ASSERT(memIsValid(buf, count / 2));
	hex = hex + count;
	for (; count; count -= 2, buf = (const octet*)buf + 1)
		diff |= *(const octet*)buf ^ _oFromHex(hex -= 2);
	return wordEq(diff, 0);
}

bool_t FAST(memEqHexRev)(const void* buf, const char* hex)
{
	size_t count = strLen(hex);
	ASSERT(count % 2 == 0);
	ASSERT(memIsValid(buf, count / 2));
	hex = hex + count;
	for (; count; count -= 2, buf = (const octet*)buf + 1)
		if (*(const octet*)buf != _oFromHex(hex -= 2))
			return FALSE;
	return TRUE;
}

/*
*******************************************************************************
Реверс октетов
*******************************************************************************
*/

void memRev(void* buf, size_t count)
{
	register size_t i = count / 2;
	ASSERT(memIsValid(buf, count));
	while (i--)
	{
		((octet*)buf)[i] ^= ((octet*)buf)[count - 1 - i];
		((octet*)buf)[count - 1 - i] ^= ((octet*)buf)[i];
		((octet*)buf)[i] ^= ((octet*)buf)[count - 1 - i];
	}
}

/*
*******************************************************************************
Преобразования
*******************************************************************************
*/

void memToU16(uint16 dest[], const void* src, size_t count)
{
	ASSERT(memIsValid(src, count));
	ASSERT(memIsValid(dest, ((count + 1) / 2) * 2));
	memMove(dest, src, count);
	if (count % 2)
		((octet*)dest)[count] = 0;
#if (OCTET_ORDER == BIG_ENDIAN)
	for (count = (count + 1) / 2; count--;)
		dest[count] = wordRevU16(dest[count]);
#endif // OCTET_ORDER
}

void memFromU16(void* dest, size_t count, const uint16 src[])
{
	ASSERT(memIsValid(src, (count + 1) / 2 * 2));
	ASSERT(memIsValid(dest, count));
	memMove(dest, src, count);
#if (OCTET_ORDER == BIG_ENDIAN)
	if (count % 2)
		((octet*)dest)[--count] = ((octet*)src)[count];
	for (count /= 2; count--;)
		((uint16*)dest)[count] = wordRevU16(((uint16*)dest)[count]);
#endif // OCTET_ORDER
}

void memToU32(uint32 dest[], const void* src, size_t count)
{
	ASSERT(memIsValid(src, count));
	ASSERT(memIsValid(dest, ((count + 3) / 4) * 4));
	memMove(dest, src, count);
	if (count % 4)
		memSetZero((octet*)dest + count, 4 - count % 4);
#if (OCTET_ORDER == BIG_ENDIAN)
	for (count = (count + 3) / 4; count--;)
		dest[count] = wordRevU32(dest[count]);
#endif // OCTET_ORDER
}

void memFromU32(void* dest, size_t count, const uint32 src[])
{
	ASSERT(memIsValid(src, (count + 3) / 4 * 4));
	ASSERT(memIsValid(dest, count));
	memMove(dest, src, count);
#if (OCTET_ORDER == BIG_ENDIAN)
	if (count % 4)
	{
		register uint32 u = src[count / 4];
		do
		{
			((octet*)dest)[--count] = (octet)u;
			u >>= 8;
		}
		while (count % 4);
	}
	for (count /= 4; count--;)
		((uint32*)dest)[count] = wordRevU32(((uint32*)dest)[count]);
#endif // OCTET_ORDER
}

void memToWord(word dest[], const void* src, size_t count)
{
	ASSERT(memIsValid(src, count));
	ASSERT(memIsValid(dest, W_OF_O(count) * O_PER_W));
	memMove(dest, src, count);
	if (count % O_PER_W)
		memSetZero((octet*)dest + count, O_PER_W - count % O_PER_W);
#if (OCTET_ORDER == BIG_ENDIAN)
	for (count = W_OF_O(count); count--;)
		dest[count] = wordRev(dest[count]);
#endif // OCTET_ORDER
}

void memFromWord(void* dest, size_t count, const word src[])
{
	ASSERT(memIsValid(src, W_OF_O(count)));
	ASSERT(memIsValid(dest, count));
	memMove(dest, src, count);
#if (OCTET_ORDER == BIG_ENDIAN)
	if (count % O_PER_W)
	{
		register word w = src[count / O_PER_W];
		do
		{
			((octet*)dest)[--count] = (octet)w;
			w >>= 8;
		}
		while (count % O_PER_W);
	}
	for (count /= O_PER_W; count--;)
		((word*)dest)[count] = wordRev(((word*)dest)[count]);
#endif // OCTET_ORDER
}

void memToHex(char* dest, const void* src, size_t count)
{
	ASSERT(memIsDisjoint2(src, count, dest, 2 * count + 1));
	for (; count--; dest += 2, src = (const octet*)src + 1)
		_oToHex(dest, *(const octet*)src);
	*dest = '\0';
}

void memToHexRev(char* dest, const void* src, size_t count)
{
	ASSERT(memIsDisjoint2(src, count, dest, 2 * count + 1));
	dest = dest + 2 * count;
	*dest = '\0';
	for (; count--; src = (const octet*)src + 1)
		_oToHex(dest -= 2, *(const octet*)src);
}

void memFromHex(void* dest, const char* src)
{
	size_t count = strLen(src);
	ASSERT(count % 2 == 0);
	ASSERT(memIsDisjoint2(src, count + 1, dest, count / 2));
	for (; count; count -= 2, src += 2, dest = (octet*)dest + 1)
		*(octet*)dest = _oFromHex(src);
}

void memFromHexRev(void* dest, const char* src)
{
	size_t count = strLen(src);
	ASSERT(count % 2 == 0);
	ASSERT(memIsDisjoint2(src, count + 1, dest, count / 2));
	src = src + count;
	for (; count; count -= 2, dest = (octet*)dest + 1)
		*(octet*)dest = _oFromHex(src -= 2);
}
