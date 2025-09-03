/*
*******************************************************************************
\file bels.c
\brief STB 34.101.60 (bels): secret sharing algorithms
\project bee2 [cryptographic library]
\created 2013.05.14
\version 2025.09.01
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/core/blob.h"
#include "bee2/core/err.h"
#include "bee2/core/mem.h"
#include "bee2/core/u32.h"
#include "bee2/core/util.h"
#include "bee2/crypto/bels.h"
#include "bee2/crypto/belt.h"
#include "bee2/math/pp.h"
#include "bee2/math/ww.h"
#include "bee2/math/zz.h"

/*
*******************************************************************************
Открытые ключи
*******************************************************************************
*/

static const u32 m_16[17] = 
{
	0x00000087, 
	0x00000285, 0x00000C41, 0x00001821, 0x00008015, 
	0x00008301, 0x00020281, 0x00022081, 0x0002A001, 
	0x00080141, 0x00080205, 0x00082801, 0x0008A001,
	0x00108041, 0x00200025, 0x00200405, 0x00200C01,
};

static const u32 m_24[17] = 
{
	0x00000087, 
	0x00001209, 0x00001241, 0x00008601, 0x00008821, 
	0x0000C005, 0x00020049, 0x00020085, 0x00021009, 
	0x00060801, 0x00090201, 0x000A0081, 0x00200411,
	0x00228001, 0x00400209, 0x00420801, 0x00810401,
};

static const u32 m_32[17] = 
{
	0x00000425, 
	0x0001000B, 0x0001000D, 0x0001A001, 0x00020061, 
	0x00040085, 0x00200181, 0x00204005, 0x00280011, 
	0x00810201, 0x00820401, 0x0100000B, 0x01002801,
	0x01200009, 0x02000029, 0x02002009, 0x0800000B,
};

err_t belsStdM(octet m[], size_t len, size_t num)
{
	// проверить входные данные
	if ((len != 16 && len != 24 && len != 32) || 
		!memIsValid(m, len) || num > 16)
		return ERR_BAD_INPUT;
	// загрузить
	if (len == 16)
		u32To(m, 4, m_16 + num);
	else if (len == 24)
		u32To(m, 4, m_24 + num);
	else
		u32To(m, 4, m_32 + num);
	memSetZero(m + 4, len - 4);
	return ERR_OK;
}

err_t belsValM(const octet m0[], size_t len)
{
	size_t n;
	void* state;
	word* f0;
	void* stack;
	err_t code;
	// проверить входные данные
	if ((len != 16 && len != 24 && len != 32) || !memIsValid(m0, len))
		return ERR_BAD_INPUT;
	// создать состояние
	n = W_OF_O(len);
	state = blobCreate2(
		O_OF_W(n + 1),
		ppIsIrred_deep(n + 1),
		SIZE_MAX, 
		&f0, &stack);
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// загрузить многочлен
	wwFrom(f0, m0, len);
	f0[n] = 1;
	// неприводим?
	code = ppIsIrred(f0, n + 1, stack) ? ERR_OK : ERR_BAD_PUBKEY;
	// завершение
	blobClose(state);
	return code;
}

/*
*******************************************************************************
Генерация открытых ключей

\todo Изменить логику работы с gen_i: связать возврат ERR_BAD_ANG с 
B_PER_IMPOSSIBLE.
*******************************************************************************
*/

err_t belsGenM0(octet m0[], size_t len, gen_i ang, void* ang_state)
{
	size_t n, reps;
	void* state;
	word* f0;
	void* stack;
	// проверить генератор
	if (ang == 0)
		return ERR_BAD_ANG;
	// проверить входные данные
	if ((len != 16 && len != 24 && len != 32) || 
		!memIsValid(m0, len))
		return ERR_BAD_INPUT;
	// создать состояние
	n = W_OF_O(len);
	state = blobCreate2(
		O_OF_W(n + 1),
		ppIsIrred_deep(n + 1),
		SIZE_MAX,
		&f0, &stack);
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// сгенерировать многочлен
	f0[n] = 1;
	for (reps = len * 8 * B_PER_IMPOSSIBLE * 3 / 4; reps--;)
	{
		ang(f0, len, ang_state);
		wwFrom(f0, f0, len);
		if (ppIsIrred(f0, n + 1, stack))
		{
			wwTo(m0, len, f0);
			break;
		}
	}
	// завершение
	blobClose(state);
	return reps != SIZE_MAX ? ERR_OK : ERR_BAD_ANG;
}

err_t belsGenMi(octet mi[], size_t len, const octet m0[], gen_i ang, 
	void* ang_state)
{
	size_t n, reps;
	err_t code;
	void* state;
	word* f0;
	word* u;
	word* f;
	void* stack;
	// проверить генератор
	if (ang == 0)
		return ERR_BAD_ANG;
	// проверить входные данные
	if ((len != 16 && len != 24 && len != 32) || 
		!memIsValid(m0, len) || !memIsValid(mi, len))
		return ERR_BAD_INPUT;
	EXPECT(belsValM(m0, len) == ERR_OK);
	// создать состояние
	n = W_OF_O(len);
	state = blobCreate2(
		O_OF_W(n + 1),
		O_OF_W(n + 1),
		O_OF_W(n + 1) | SIZE_HI,
		ppMinPolyMod_deep(n + 1),
		SIZE_MAX,
		&f0, &f, &u, &stack);
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// загрузить многочлен
	wwFrom(f0, m0, len);
	f0[n] = 1;
	// попытки генерации
	for (reps = 3; reps--; )
	{
		ang(u, len, ang_state);
		wwFrom(u, u, len), u[n] = 0;
		// f <- минимальный многочлен элемента u
		ppMinPolyMod(f, u, f0, n + 1, stack);
		// f подходит?
		if (f[n] == 1 && wwCmp(f, f0, n) != 0)
		{
			wwTo(mi, len, f);
			break;
		}
	}
	// завершение
	if (reps != SIZE_MAX)
		code = ERR_OK;
	else if (wwEq(f, f0, n + 1))
		code = ERR_BAD_ANG;
	else 
		code = ERR_BAD_PUBKEY;
	blobClose(state);
	return code;
}

err_t belsGenMid(octet mid[], size_t len, const octet m0[], const octet id[], 
	size_t id_len)
{
	size_t n, reps;
	void* state;
	word* f0;
	word* f;
	word* u;
	void* stack;
	// проверить входные данные
	if ((len != 16 && len != 24 && len != 32) || 
		!memIsValid(m0, len) || !memIsValid(mid, len) || 
		!memIsValid(id, id_len))
		return ERR_BAD_INPUT;
	EXPECT(belsValM(m0, len) == ERR_OK);
	// создать состояние
	n = W_OF_O(len);
	state = blobCreate2(
		O_OF_W(n + 1),
		O_OF_W(n + 1),
		O_OF_W(W_OF_O(32) + 1),
		utilMax(2, 
			beltHash_keep(),
			ppMinPolyMod_deep(n + 1)),
		SIZE_MAX,
		&f0, &f, &u, &stack);
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// загрузить многочлен
	wwFrom(f0, m0, len);
	f0[n] = 1;
	// хэшировать
	beltHashStart(stack);
	beltHashStepH(id, id_len, stack);
	beltHashStepG((octet*)u, stack);
	wwFrom(u, u, 32);
	u[n] = 0;
	// попытки генерации
	for (reps = MAX2(3, B_PER_IMPOSSIBLE * 2 / len / 8); reps--;)
	{
		// f <- минимальный многочлен элемента u
		ppMinPolyMod(f, u, f0, n + 1, stack);
		// f подходит?
		if (f[n] == 1 && !wwEq(f, f0, n))
		{
			wwTo(mid, len, f);
			break;
		}
		// u <- u + 1
		zzAddW2(u, n, 1);
	}
	// завершение
	blobClose(state);
	return reps != SIZE_MAX ? ERR_OK : ERR_BAD_PUBKEY;
}

/*
*******************************************************************************
Генерация одноразового ключа
*******************************************************************************
*/

static size_t belsGenk_keep()
{
	return MAX2(beltCTR_keep(), beltCompr_deep()) + 32 + 64;
}

static void belsGenkStart(void* state, const octet s[], size_t count,
	size_t threshold, size_t len)
{
	octet* key;
	octet* iv;
	u32* K;
	// pre
	ASSERT(memIsValid(state, belsGenk_keep()));
	ASSERT(len == 16 || len == 24 || len == 32);
	ASSERT(memIsValid(s, len));
	// раскладка state
	key = (octet*)state + MAX2(beltCTR_keep(), beltCompr_deep());
	iv = key + 32;
	K = (u32*)iv;
	// K <- belt-keyexpand(s)
	beltKeyExpand2(K, s, len);
	// key <- belt-compress(~K || K)
	memCopy(K + 8, K, 32);
	memNeg(K, 32);
	beltCompr((u32*)key, K, state);
	u32To(key, 32, (u32*)key);
	// iv <- <n>_32 || <t>_32 || 0
	K[4] = (u32)count, K[5] = (u32)threshold;
	u32To(iv, 4, K + 4);
	u32To(iv + 4, 4, K + 5);
	memSetZero(iv + 8, 8);
	// start belt-ctr(key, iv)
	beltCTRStart(state, key, 32, iv);
}

static void belsGenkStepR(void* buf, size_t count, void* state)
{
	memSetZero(buf, count);
	beltCTRStepE(buf, count, state);
}

/*
*******************************************************************************
Разделение секрета
*******************************************************************************
*/

err_t belsShare(octet si[], size_t count, size_t threshold, size_t len, 
	const octet s[], const octet m0[], const octet mi[], 
	gen_i rng, void* rng_state)
{
	size_t n, i;
	void* state;
	word* f;
	word* k;
	word* c;
	void* stack;
	// проверить генератор
	if (rng == 0)
		return ERR_BAD_RNG;
	// проверить входные данные
	if ((len != 16 && len != 24 && len != 32) || 
		threshold == 0 || count < threshold ||
		!memIsValid(s, len) || !memIsValid(m0, len) || 
		!memIsValid(mi, len * count) || !memIsValid(si, count * len))
		return ERR_BAD_INPUT;
	EXPECT(belsValM(m0, len) == ERR_OK);
	// создать состояние
	n = W_OF_O(len);
	state = blobCreate2(
		O_OF_W(n + 1),
		O_OF_W(threshold * n - n),
		O_OF_W(threshold * n),
		utilMax(2, 
			ppMul_deep(threshold * n - n, n),
			ppMod_deep(threshold * n, n + 1)),
		SIZE_MAX,
		&f, &k, &c, &stack);
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// сгенерировать k
	rng(k, threshold * len - len, rng_state);
	wwFrom(k, k, threshold * len - len);
	// c(x) <- (x^l + m0(x))k(x) + s(x)
	wwFrom(f, m0, len);
	ppMul(c, k, threshold * n - n, f, n, stack);
	wwXor2(c + n, k, threshold * n - n);
	wwFrom(f, s, len);
	wwXor2(c, f, n);
	// цикл по пользователям
	for (i = 0; i < count; ++i)
	{
		// f(x) <- x^l + mi(x)
		EXPECT(belsValM(mi + i * len, len) == ERR_OK);
		wwFrom(f, mi + i * len, len);
		f[n] = 1;
		// si(x) <- c(x) mod f(x)
		ppMod(f, c, threshold * n, f, n + 1, stack);
		wwTo(si + i * len, len, f);
	}
	// завершение
	blobClose(state);
	return ERR_OK;
}

err_t belsShare2(octet si[], size_t count, size_t threshold, size_t len,
	const octet s[], gen_i rng, void* rng_state)
{
	size_t n, i;
	void* state;
	word* f;
	word* k;
	word* c;
	void* stack;
	// проверить генератор
	if (rng == 0)
		return ERR_BAD_RNG;
	// проверить входные данные
	if ((len != 16 && len != 24 && len != 32) ||
		threshold == 0 || count < threshold || count > 16 ||
		!memIsValid(s, len) || !memIsValid(si, count * (len + 1)))
		return ERR_BAD_INPUT;
	// создать состояние
	n = W_OF_O(len);
	state = blobCreate2(
		O_OF_W(n + 1),
		O_OF_W(threshold * n - n),
		O_OF_W(threshold * n),
		utilMax(2,
			ppMul_deep(threshold * n - n, n),
			ppMod_deep(threshold * n, n + 1)),
		SIZE_MAX,
		&f, &k, &c, &stack);
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// сгенерировать k
	rng(k, threshold * len - len, rng_state);
	wwFrom(k, k, threshold * len - len);
	// c(x) <- (x^l + m0(x))k(x) + s(x)
	belsStdM(stack, len, 0);
	wwFrom(f, stack, len);
	ppMul(c, k, threshold * n - n, f, n, stack);
	wwXor2(c + n, k, threshold * n - n);
	wwFrom(f, s, len);
	wwXor2(c, f, n);
	// цикл по пользователям
	for (i = 0; i < count; ++i)
	{
		// f(x) <- x^l + mi(x)
		belsStdM(stack, len, i + 1);
		wwFrom(f, stack, len);
		f[n] = 1;
		// si(x) <- c(x) mod f(x)
		ppMod(f, c, threshold * n, f, n + 1, stack);
		wwTo(si + i * (len + 1) + 1, len, f);
		si[i * (len + 1)] = (octet)(i + 1);
	}
	// завершение
	blobClose(state);
	return ERR_OK;
}

err_t belsShare3(octet si[], size_t count, size_t threshold, size_t len,
	const octet s[])
{
	void* state;
	err_t code;
	// проверить входные данные
	if ((len != 16 && len != 24 && len != 32) || !memIsValid(s, len)) 
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(belsGenk_keep());
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// запустить генератор
	belsGenkStart(state, s, count, threshold, len);
	// разделить секрет
	code = belsShare2(si, count, threshold, len, s, belsGenkStepR, state);
	// завершение
	blobClose(state);
	return code;
}

/*
*******************************************************************************
Восстановление секрета

\todo Организовать вычисления так, чтобы не было медленных (без Карацубы)
умножений "маленького" многочлена на "большой".
*******************************************************************************
*/

err_t belsRecover(octet s[], size_t count, size_t len, const octet si[], 
	const octet m0[], const octet mi[])
{
	size_t n, i, deep;
	void* state;
	word* f;
	word* g;
	word* d;
	word* u;
	word* v;
	word* c;
	word* t;
	void* stack;
	// проверить входные данные
	if ((len != 16 && len != 24 && len != 32) || count == 0 || 
		!memIsValid(si, count * len) || !memIsValid(m0, len) || 
		!memIsValid(mi, len * count) || !memIsValid(s, len))
		return ERR_BAD_INPUT;
	EXPECT(belsValM(m0, len) == ERR_OK);
	// расчет глубины стека
	n = W_OF_O(len);
	deep = utilMax(2, 
		ppMul_deep(n, n), 
		ppMod_deep(count * n, n + 1));
	for (i = 1; i < count; ++i)
		deep = utilMax(6, 
			deep, 
			ppExGCD_deep(n + 1, i * n + 1),
			ppMul_deep(i * n, i * n),
			ppMul_deep(2 * i * n, n),
			ppMul_deep(2 * n, i * n),
			ppMod_deep((2 * i + 1) * n, (i + 1) * n + 1));
	// создать состояние
	state = blobCreate2(
		O_OF_W(n + 1),
		O_OF_W(count * n + 1),
		O_OF_W((count - 1) * n + 1),
		O_OF_W((count - 1) * n + 1),
		O_OF_W(n + 1),
		O_OF_W((2 * count - 1) * n),
		O_OF_W(MAX2(2 * count - 2, count + 1) * n),
		deep,
		SIZE_MAX,
		&f, &g, &d, &u, &v, &c, &t, &stack);
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// [n]c(x) <- s1(x)
	wwFrom(c, si, len);
	// [n + 1]g(x) <- x^l + m1(x)
	wwFrom(g, mi, len), g[n] = 1;
	// цикл по пользователям
	for (f[n] = 1, i = 1; i < count; ++i)
	{
		// [n + 1]f(x) <- x^l + mi(x)
		wwFrom(f, mi + i * len, len);
		// найти d(x) = \gcd(f(x), g(x)) и коэфф. Безу [i * n]u(x), [n]v(x)
		ppExGCD(d, u, v, f, n + 1, g, i * n + 1, stack);
		ASSERT(u[i * n] == 0 && v[n] == 0);
		// d(x) != 1? 
		if (wwCmpW(d, i * n + 1, 1) != 0)
		{
			blobClose(state);
			return ERR_BAD_PUBKEY;
		}
		// [2 * i * n]c(x) <- u(x)f(x)c(x)
		// (с помощью [2 * i * n]t)
		ppMul(t, u, i * n, c, i * n, stack);
		ppMul(c, t, 2 * i * n, f, n, stack);
		wwXor2(c + n, t, 2 * i * n);
		// c(x) <- c(x) + v(x)g(x)si(x)
		// (с помощью [2 * n]d и [(i + 2) * n]t)
		wwFrom(t, si + i * len, len);
		ppMul(d, v, n, t, n, stack);
		ppMul(t, d, 2 * n, g, i * n, stack);
		wwXor2(t + i * n, d, 2 * n);
		wwXor2(c, t, (i + 2) * n);
		// [(i + 1) * n + 1]g(x) <- g(x)f(x)
		// (с помощью [(i + 1) * n]t)
		ppMul(t, f, n, g, i * n, stack);
		wwXor2(t + n, g, i * n);
		wwXor2(t + i * n, f, n);
		wwCopy(g, t, (i + 1) * n);
		g[(i + 1) * n] = 1;
		// [(i + 1) * n]c(x) <- c(x) mod g(x)
		ppMod(c, c, (2 * i + 1) * n, g, (i + 1) * n + 1, stack);
		ASSERT(c[(i + 1) * n] == 0);
	}
	// [n]s(x) <- c(x) mod (x^l + m0(x))
	wwFrom(f, m0, len), f[n] = 1;
	ppMod(c, c, count * n, f, n + 1, stack);
	ASSERT(c[n] == 0);
	wwTo(s, len, c);
	// завершение
	blobClose(state);
	return ERR_OK;
}

err_t belsRecover2(octet s[], size_t count, size_t len, const octet si[])
{
	size_t n, i, j, deep;
	void* state;
	word* f;
	word* g;
	word* d;
	word* u;
	word* v;
	word* c;
	word* t;
	void* stack;
	// проверить входные данные
	if ((len != 16 && len != 24 && len != 32) || count == 0 || count > 16 ||
		!memIsValid(si, count * (len + 1)) || !memIsValid(s, len))
		return ERR_BAD_INPUT;
	// проверить номера частичных секретов
	for (i = 0; i < count; ++i)
	{
		if (si[i * (len + 1)] == 0 || si[i * (len + 1)] > 16)
			return ERR_BAD_PUBKEY;
		for (j = i + 1; j < count; ++j)
			if (si[i * (len + 1)] == si[j * (len + 1)])
				return ERR_BAD_PUBKEY;
	}
	// расчет глубины стека
	n = W_OF_O(len);
	deep = utilMax(2,
		ppMul_deep(n, n),
		ppMod_deep(count * n, n + 1));
	for (i = 1; i < count; ++i)
		deep = utilMax(6,
			deep,
			ppExGCD_deep(n + 1, i * n + 1),
			ppMul_deep(i * n, i * n),
			ppMul_deep(2 * i * n, n),
			ppMul_deep(2 * n, i * n),
			ppMod_deep((2 * i + 1) * n, (i + 1) * n + 1));
	deep += O_OF_W(
		n + 1 +
		count * n + 1 +
		(count - 1) * n + 1 +
		(count - 1) * n + 1 +
		n + 1 +
		(2 * count - 1) * n +
		MAX2((2 * count - 2) * n, (count + 1) * n));
	// создать состояние
	state = blobCreate2(
		O_OF_W(n + 1),
		O_OF_W(count * n + 1),
		O_OF_W((count - 1) * n + 1),
		O_OF_W((count - 1) * n + 1),
		O_OF_W(n + 1),
		O_OF_W((2 * count - 1) * n),
		O_OF_W(MAX2(2 * count - 2, count + 1) * n),
		deep,
		SIZE_MAX,
		&f, &g, &d, &u, &v, &c, &t, &stack);
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// [n]c(x) <- s1(x)
	wwFrom(c, si + 1, len);
	// [n + 1]g(x) <- x^l + m1(x)
	belsStdM((octet*)g, len, si[0]);
	wwFrom(g, g, len), g[n] = 1;
	// цикл по пользователям
	for (f[n] = 1, i = 1; i < count; ++i)
	{
		// [n + 1]f(x) <- x^l + mi(x)
		belsStdM((octet*)f, len, si[i * (len + 1)]);
		wwFrom(f, f, len);
		// найти d(x) = \gcd(f(x), g(x)) и коэфф. Безу [i * n]u(x), [n]v(x)
		ppExGCD(d, u, v, f, n + 1, g, i * n + 1, stack);
		ASSERT(u[i * n] == 0 && v[n] == 0);
		// d(x) != 1? 
		if (wwCmpW(d, i * n + 1, 1) != 0)
		{
			blobClose(state);
			return ERR_BAD_PUBKEY;
		}
		// [2 * i * n]c(x) <- u(x)f(x)c(x)
		// (с помощью [2 * i * n]t)
		ppMul(t, u, i * n, c, i * n, stack);
		ppMul(c, t, 2 * i * n, f, n, stack);
		wwXor2(c + n, t, 2 * i * n);
		// c(x) <- c(x) + v(x)g(x)si(x)
		// (с помощью [2 * n]d и [(i + 2) * n]t)
		wwFrom(t, si + i * (len + 1) + 1, len);
		ppMul(d, v, n, t, n, stack);
		ppMul(t, d, 2 * n, g, i * n, stack);
		wwXor2(t + i * n, d, 2 * n);
		wwXor2(c, t, (i + 2) * n);
		// [(i + 1) * n + 1]g(x) <- g(x)f(x)
		// (с помощью [(i + 1) * n]t)
		ppMul(t, f, n, g, i * n, stack);
		wwXor2(t + n, g, i * n);
		wwXor2(t + i * n, f, n);
		wwCopy(g, t, (i + 1) * n);
		g[(i + 1) * n] = 1;
		// [(i + 1) * n]c(x) <- c(x) mod g(x)
		ppMod(c, c, (2 * i + 1) * n, g, (i + 1) * n + 1, stack);
		ASSERT(c[(i + 1) * n] == 0);
	}
	// [n]s(x) <- c(x) mod (x^l + m0(x))
	belsStdM((octet*)f, len, 0);
	wwFrom(f, f, len), f[n] = 1;
	ppMod(c, c, count * n, f, n + 1, stack);
	ASSERT(c[n] == 0);
	wwTo(s, len, c);
	// завершение
	blobClose(state);
	return ERR_OK;
}
