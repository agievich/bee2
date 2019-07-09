/*
*******************************************************************************
\file mem.c
\brief Memory management
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2012.12.18
\version 2019.07.09
\license This program is released under the GNU General Public License
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/mem.h"
#include "bee2/core/str.h"
#include "bee2/core/util.h"
#include "bee2/core/word.h"

#ifndef OS_APPLE
	#include <malloc.h>
#else
	#include <stdlib.h>
#endif
#ifdef OS_WIN
	#include <windows.h>
#endif

/*
*******************************************************************************
Проверка

\todo Реализовать полноценную проверку корректности памяти.
*******************************************************************************
*/

bool_t memIsValid(const void* buf, size_t count)
{
	return count == 0 || buf != 0;
}

bool_t memIsAligned(const void* buf, size_t size)
{
	return (size_t)buf % size == 0;
}


/*
*******************************************************************************
Стандартные функции

\remark Перед вызовом memcpy(), memmove(), memset() проверяется, 
что count != 0: при count == 0 поведение стандартных функций непредсказуемо
(см. https://www.imperialviolet.org/2016/06/26/nonnull.html).

\remark Прямое обращение к функции ядра HeapAlloc() решает проблему 
с освобождением памяти в плагине bee2evp, связывающем bee2 с OpenSSL (1.1.0).
*******************************************************************************
*/

void memCopy(void* dest, const void* src, size_t count)
{
	ASSERT(memIsDisjoint(src, dest, count));
	if (count)
		memcpy(dest, src, count);
}

void memMove(void* dest, const void* src, size_t count)
{
	ASSERT(memIsValid(src, count));
	ASSERT(memIsValid(dest, count));
	if (count)
		memmove(dest, src, count);
}

void memSet(void* buf, octet c, size_t count)
{
	ASSERT(memIsValid(buf, count));
	if (count)
		memset(buf, c, count);
}

void memNeg(void* buf, size_t count)
{
	ASSERT(memIsValid(buf, count));
	for (; count >= O_PER_W; count -= O_PER_W)
	{
		*(word*)buf = ~*(word*)buf;
		buf = (word*)buf + 1;
	}
	while (count--)
	{
		*(octet*)buf = ~*(octet*)buf;
		buf = (octet*)buf + 1;
	}
}

void* memAlloc(size_t count)
{
#ifdef OS_WIN
	return HeapAlloc(GetProcessHeap(), 0, count);
#else
	return malloc(count);
#endif
}

void* memRealloc(void* buf, size_t count)
{
	if (count == 0)
	{
		memFree(buf);
		return 0;
	}
#ifdef OS_WIN
	if (!buf)
		return HeapAlloc(GetProcessHeap(), 0, count);
	return HeapReAlloc(GetProcessHeap(), 0, buf, count);
#else
	return realloc(buf, count);
#endif
}

void memFree(void* buf)
{
#ifdef OS_WIN
	HeapFree(GetProcessHeap(), 0, buf);
#else
	free(buf);
#endif
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
*******************************************************************************
*/

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
		while (count % O_PER_W)
		{
			w1 = w1 << 8 | ((const octet*)buf1)[--count];
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
