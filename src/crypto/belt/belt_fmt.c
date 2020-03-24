/*
*******************************************************************************
\file belt_fmt.c
\brief STB 34.101.31 (belt): FMT (format preserving encryption)
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2017.09.28
\version 2020.03.24
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/blob.h"
#include "bee2/core/err.h"
#include "bee2/core/mem.h"
#include "bee2/core/u16.h"
#include "bee2/core/u32.h"
#include "bee2/core/util.h"
#include "bee2/crypto/belt.h"
#include "bee2/math/ww.h"
#include "bee2/math/zz.h"
#include "belt_lcl.h"

/*
*******************************************************************************
Минимальное число 64-битовых блоков для размещения слова из ZZ_mod^count.

Необходимо вычислить ceil(log2(mod) * count / 64).

Реализован следующий алгоритм:

1. c <- 1588 / 2291 (диофантово приближение ln 2 через цепные дроби).
2. 2^k <- ближайшая к mod степень двойки.
3. x <- (m - 2^k)/ 2^k.
4. y <- x(60 + 60x + 11x^2)/(60 + 60x + 36x^2 + 3x^3) 
   (аппроксимация Паде для ln(1 + x)).
5. b <- ceil((k + y / c) * count / 64).
6. Возвратить b.

Аргумент ceil() на предпоследнем шаге можно записать следующим образом:
\code
	count * (4764 k (8^k + 9 4^k mod + 9 2^k mod^2 + mod^3) - 
			   2291(11 8^k + 27 4^k mod - 27 2^k mod^2 - 11 mod^3)) / 
	304896 * (8^k + 9 4^k mod + 9 2^k mod^2 + mod^3)
\endcode

Алгоритм правильно работает для mod <= 65536 и count <= 300 за исключением
следующих сочетаний (mod, count):
\code
	(49667, 160).
\endcode

Проверка:
\code
	#include <math.h>
	...
	u32 mod;
	size_t count;
	for (mod = 2; mod <= 65536; ++mod)
		for (count = 1; count <= 300; ++count)
		{
			long double b = log(mod) / log(2.0);
			b *= count, b /= 64.0;
			if ((size_t)ceil(b) != beltFMTCalcB(mod, count))
				ASSERT(0);
		}
\endcode

\remark Используется соглашение sizeof(word) >= sizeof(u16): mod либо 
умещается в word, либо равняется 65536.
*******************************************************************************
*/

static size_t beltFMTCalcB(u32 mod, size_t count)
{
	const size_t m = W_OF_B(128);
	word num[W_OF_B(128)];
	word den[W_OF_B(128)];
	size_t k;
	word stack[W_OF_B(128) * 5];
	word* t0 = stack; 
	word* t1 = t0 + m; 
	word* t2 = t1 + m; 
	word* t3 = t2 + m; 
	word* t4 = t3 + m; 
	// pre
	ASSERT(2 <= mod && mod <= 65536);
	ASSERT(1 <= count && count <= 300);
	// обработать особые сочетания (mod, count)
	if (mod == 49667 && count == 320)
		return 39;
	// обработать mod, который не умещается в 16 битов
	if (mod == 65536)
		return (16 * count + 63) / 64;
	// k <- ceil(log2(mod))
	k = B_PER_W - wordCLZ((word)mod);
	ASSERT(k > 0);
	if ((U32_1 << k) - mod > mod - (U32_1 << (k - 1)))
		--k;
	// t0 <- 8^k
	wwSetZero(t0, m);
	wwSetBit(t0, 3 * k, 1);
	// t1 <- 4^k mod 
	wwSetZero(t1, m);
	wwSetBit(t1, 2 * k, 1);
	zzMulW(t1, t1, m, mod);
	// t2 <- 2^k mod^2
	wwSetZero(t2, m);
	wwSetBit(t2, k, 1);
	zzMulW(t2, t2, m, mod);
	zzMulW(t2, t2, m, mod);
	// t3 <- mod^3
	wwSetW(t3, m, mod);
	zzMulW(t3, t3, m, mod);
	zzMulW(t3, t3, m, mod);
	// den <- t0 + 9 * t1 + 9 * t2 + t3
	wwCopy(den, t0, m);
	zzAdd2(den, t3, m);
	wwCopy(t4, t1, m);
	zzAdd2(t4, t2, m);
	zzMulW(t4, t4, m, 9);
	zzAdd2(den, t4, m);
	// num <- den * 4767 k 
	wwCopy(num, den, m);
	zzMulW(num, num, m, 4764);
	zzMulW(num, num, m, (word)k);
	// num <- count * (num - 25201 t0 - 61857 t1 + 61857 t2 + 25201 t3)
	zzMulW(t3, t3, m, 25201);
	zzAdd2(num, t3, m);
	zzMulW(t2, t2, m, 61857u);
	zzAdd2(num, t2, m);
	zzMulW(t1, t1, m, 61857u);
	zzSub2(num, t1, m);
	zzMulW(t0, t0, m, 25201);
	zzSub2(num, t0, m);
	zzMulW(num, num, m, (word)count);
	// den <- 304896 * den
	zzMulW(den, den, m, 768);
	zzMulW(den, den, m, 397);
	// num <- num + den - 1
	zzAdd2(num, den, m);
	zzSubW2(num, m, 1);
	// num <- num / den
	for (k = m; den[k - 1] == 0; --k);
	ASSERT(zzDiv_deep(m, k) <= sizeof(stack));
	zzDiv(den, num, num, m, den, k, stack);
	// возврат
	return (size_t)den[0];
}

/*
*******************************************************************************
belt-32block
*******************************************************************************
*/

void belt32BlockEncr(octet block[24], const u32 key[8])
{
	u32* t = (u32*)block;
	u32From(t, block, 24);
	// round #1
	beltBlockEncr3(t + 2, t + 3, t + 4, t + 5, key);
	t[2] ^= 1, t[0] ^= t[2], t[1] ^= t[3];
	// round #2
	beltBlockEncr3(t + 4, t + 5, t + 0, t + 1, key);
	t[4] ^= 2, t[2] ^= t[4], t[3] ^= t[5];
	// round #3
	beltBlockEncr3(t + 0, t + 1, t + 2, t + 3, key);
	t[0] ^= 3, t[4] ^= t[0], t[5] ^= t[1];
	// возврат
	u32To(block, 24, t);
}

/*
*******************************************************************************
Конвертации
*******************************************************************************
*/

static void beltStr2Bin(octet bin[], size_t b, u32 mod, 
	const u16 str[], size_t count)
{
	word* a;
	size_t m;
	// подготовить память
	memSetZero(bin, 8 * b);
	// особый случай: mod может не уложиться в word
	if (mod == 65536)
	{
		u16To(bin, 2 * count, str);
		return;
	}
	// конвертировать
	ASSERT(2 <= mod && mod < 65536);
	ASSERT(count >= 1);
	--count;
	EXPECT(str[count] < mod);
	a = (word*)bin;
	m = W_OF_O(8 * b);
	a[0] = (word)str[count];
	while (count--)
	{
		zzMulW(a, a, m, mod);
		EXPECT(str[count] < mod);
		zzAddW2(a, m, (word)str[count]);
	}
	wwTo(bin, 8 * b, a);
}

static void beltBin2StrAdd(u32 mod, u16 str[], size_t count, 
	octet bin[], size_t b)
{
	register u32 t;
	word* a;
	size_t m;
	// особый случай: mod может не уложиться в word
	if (mod == 65536)
	{
		u16* uu = (u16*)bin;
		u16From(uu, bin, 8 * b);
		while (count--)
			str[count] += uu[count];
		return;
	}
	// настроить память
	m = W_OF_O(8 * b);
	a = (word*)bin;
	wwFrom(a, bin, 8 * b);
	// конвертировать и сложить
	ASSERT(2 <= mod && mod < 65536);
	while (count--)
	{
		t = (u32)zzModW(a, m, mod);
		t += str[0], t %= mod;
		str[0] = (u16)t, ++str;
		zzDivW(a, a, m, mod);
	}
	t = 0;
}

static void beltBin2StrSub(word mod, u16 str[], size_t count, 
	octet bin[], size_t b)
{
	register u32 t;
	word* a;
	size_t m;
	// особый случай: mod может не уложиться в word
	if (mod == 65536)
	{
		u16* uu = (u16*)bin;
		u16From(uu, bin, 8 * b);
		while (count--)
			str[count] -= uu[count];
		return;
	}
	// настроить память
	m = W_OF_O(8 * b);
	a = (word*)bin;
	wwFrom(a, bin, 8 * b);
	// конвертировать и вычесть
	ASSERT(2 <= mod && mod <= 65536);
	while (count--)
	{
		t = (u32)zzModW(a, m, mod);
		t = str[0] + mod - t, t %= mod;
		str[0] = (u16)t, ++str;
		zzDivW(a, a, m, mod);
	}
	t = 0;
}

/*
*******************************************************************************
Шифрование с сохранением формата (FMT)

\remark После одного beltKWPStart() выполняются многократные обращения 
к beltKWPStepE(). Для корректной работы перед каждым обращением в состоянии
механизма KWP сбрасывается счетчик тактов:
\code
	st->kwp->round = 0;
\endcode
*******************************************************************************
*/

typedef struct
{
	belt_wbl_st wbl[1];		/*< состояние механизма WBL */
	u32 mod;				/*< модуль */
	size_t n1;				/*< длина левой половинки */
	size_t n2;				/*< длина правой половинки */
	size_t b1;				/*< число блоков для обработки левой половинки */
	size_t b2;				/*< число блоков для обработки правой половинки */
	octet iv[4 + 16 + 4];	/*< формат || синхропосылка || формат */
	octet buf[];			/*< вспомогательный буфер */
} belt_fmt_st;

size_t beltFMT_keep(u32 mod, size_t count)
{
	ASSERT(2 <= mod && mod <= 65536);
	ASSERT(2 <= count && count <= 600);
	return sizeof(belt_fmt_st) + 8 * (beltFMTCalcB(mod, (count + 1) / 2) + 1);
}

void beltFMTStart(void* state, u32 mod, size_t count, const octet key[], 
	size_t len)
{
	belt_fmt_st* st = (belt_fmt_st*)state;
	ASSERT(2 <= mod && mod <= 65536);
	ASSERT(2 <= count && count <= 600);
	ASSERT(memIsValid(state, beltFMT_keep(mod, count)));
	// инициализировать состояние
	beltWBLStart(st->wbl, key, len);
	st->mod = mod;
	st->n1 = (count + 1) / 2;
	st->n2 = count / 2;
	st->b1 = beltFMTCalcB(mod, st->n1);
	st->b2 = beltFMTCalcB(mod, st->n2);
#if (OCTET_ORDER == LITTLE_ENDIAN)
	((u16*)st->iv)[0] = (u16)mod;
	((u16*)st->iv)[1] = (u16)count;
#else
	((u16*)st->iv)[0] = u16Rev((u16)mod);
	((u16*)st->iv)[1] = u16Rev((u16)count);
#endif
	memCopy(st->iv + 20, st->iv, 4);
}

void beltFMTStepE(u16 buf[], const octet iv[16], void* state)
{
	belt_fmt_st* st = (belt_fmt_st*)state;
	size_t i;
	ASSERT(memIsValid(state, sizeof(belt_fmt_st)));
	ASSERT(memIsValid(state, beltFMT_keep(st->mod, st->n1 + st->n2)));
	ASSERT(memIsNullOrValid(iv, 16));
	ASSERT(memIsValid(buf, 2 * st->n1 + 2 * st->n2));
	// подготовить синхропосылку
	if (iv)
		memCopy(st->iv + 4, iv, 16);
	else
		memSetZero(st->iv + 4, 16);
	// такты
	for (i = 0; i < 3; ++i)
	{
		// первая половинка
		beltStr2Bin(st->buf, st->b2, st->mod, buf + st->n1, st->n2);
		memCopy(st->buf + st->b2 * 8, beltH() + 8 * i, 4);
		memCopy(st->buf + st->b2 * 8 + 4, st->iv + 8 * i, 4);
		if (st->b2 == 1)
			beltBlockEncr(st->buf, st->wbl->key);
		else if (st->b2 == 2)
			belt32BlockEncr(st->buf, st->wbl->key);
		else
			beltWBLStepE(st->buf, 8 * st->b2 + 8, st->wbl);
		beltBin2StrAdd(st->mod, buf, st->n1, st->buf, st->b2 + 1);
		// вторая половинка
		beltStr2Bin(st->buf, st->b1, st->mod, buf, st->n1);
		memCopy(st->buf + st->b1 * 8, beltH() + 8 * i + 4, 4);
		memCopy(st->buf + st->b1 * 8 + 4, st->iv + 8 * i + 4, 4);
		if (st->b1 == 1)
			beltBlockEncr(st->buf, st->wbl->key);
		else if (st->b1 == 2)
			belt32BlockEncr(st->buf, st->wbl->key);
		else
			beltWBLStepE(st->buf, 8 * st->b1 + 8, st->wbl);
		beltBin2StrAdd(st->mod, buf + st->n1, st->n2, st->buf, st->b1 + 1);
	}
}

void beltFMTStepD(u16 buf[], const octet iv[16], void* state)
{
	belt_fmt_st* st = (belt_fmt_st*)state;
	size_t i;
	ASSERT(memIsValid(state, sizeof(belt_fmt_st)));
	ASSERT(memIsValid(state, beltFMT_keep(st->mod, st->n1 + st->n2)));
	ASSERT(memIsNullOrValid(iv, 16));
	ASSERT(memIsValid(buf, 2 * st->n1 + 2 * st->n2));
	// подготовить синхропосылку
	if (iv)
		memCopy(st->iv + 4, iv, 16);
	else
		memSetZero(st->iv + 4, 16);
	// такты
	for (i = 3; i--;)
	{
		// вторая половинка
		beltStr2Bin(st->buf, st->b1, st->mod, buf, st->n1);
		memCopy(st->buf + st->b1 * 8, beltH() + 8 * i + 4, 4);
		memCopy(st->buf + st->b1 * 8 + 4, st->iv + 8 * i + 4, 4);
		if (st->b1 == 1)
			beltBlockEncr(st->buf, st->wbl->key);
		else if (st->b1 == 2)
			belt32BlockEncr(st->buf, st->wbl->key);
		else
			beltWBLStepE(st->buf, 8 * st->b1 + 8, st->wbl);
		beltBin2StrSub(st->mod, buf + st->n1, st->n2, st->buf, st->b1 + 1);
		// первая половинка
		beltStr2Bin(st->buf, st->b2, st->mod, buf + st->n1, st->n2);
		memCopy(st->buf + st->b2 * 8, beltH() + 8 * i, 4);
		memCopy(st->buf + st->b2 * 8 + 4, st->iv + 8 * i, 4);
		if (st->b2 == 1)
			beltBlockEncr(st->buf, st->wbl->key);
		else if (st->b2 == 2)
			belt32BlockEncr(st->buf, st->wbl->key);
		else
			beltWBLStepE(st->buf, 8 * st->b2 + 8, st->wbl);
		beltBin2StrSub(st->mod, buf, st->n1, st->buf, st->b2 + 1);
	}	
}

err_t beltFMTEncr(u16 dest[], u32 mod, const u16 src[], size_t count,
	const octet key[], size_t len, const octet iv[16])
{
	void* state;
	// проверить входные данные
	if (count < 2 ||
		len != 16 && len != 24 && len != 32 ||
		!memIsValid(src, 2 * count) ||
		!memIsNullOrValid(iv, 16) ||
		!memIsValid(key, len) ||
		!memIsValid(dest, 2 * count) ||
		iv && !memIsDisjoint2(dest, 2 * count, iv, 16))
		return ERR_BAD_INPUT;
	if (count > 600)
		return ERR_NOT_IMPLEMENTED;
	// создать состояние
	state = blobCreate(beltFMT_keep(mod, count));
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// зашифровать
	beltFMTStart(state, mod, count, key, len);
	memMove(dest, src, 2 * count);
	beltFMTStepE(dest, iv, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}

err_t beltFMTDecr(u16 dest[], u32 mod, const u16 src[], size_t count,
	const octet key[], size_t len, const octet iv[16])
{
	void* state;
	// проверить входные данные
	if (count < 2 ||
		len != 16 && len != 24 && len != 32 ||
		!memIsValid(src, 2 * count) ||
		!memIsNullOrValid(iv, 16) ||
		!memIsValid(key, len) ||
		!memIsValid(dest, 2 * count) ||
		iv && !memIsDisjoint2(dest, 2 * count, iv, 16))
		return ERR_BAD_INPUT;
	if (count > 600)
		return ERR_NOT_IMPLEMENTED;
	// создать состояние
	state = blobCreate(beltFMT_keep(mod, count));
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// зашифровать
	beltFMTStart(state, mod, count, key, len);
	memMove(dest, src, 2 * count);
	beltFMTStepD(dest, iv, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}
