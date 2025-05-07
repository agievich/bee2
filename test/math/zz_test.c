/*
*******************************************************************************
\file zz_test.c
\brief Tests for multiple-precision unsigned integers
\project bee2/test
\created 2014.07.15
\version 2025.05.07
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <bee2/core/prng.h>
#include <bee2/core/safe.h>
#include <bee2/core/util.h>
#include <bee2/core/word.h>
#include <bee2/math/zz.h>
#include <bee2/math/ww.h>

/*
*******************************************************************************
Тестирование
*******************************************************************************
*/

static bool_t zzTestAdd()
{
	enum { n = 8 };
	size_t reps = 500;
	word a[n];
	word b[n];
	word c[n];
	word c1[n];
	octet combo_state[32];
	// подготовить память
	if (sizeof(combo_state) < prngCOMBO_keep())
		return FALSE;
	// инициализировать генератор COMBO
	prngCOMBOStart(combo_state, utilNonce32());
	// сложение / вычитание
	while (reps--)
	{
		word carry;
		prngCOMBOStepR(a, O_OF_W(n), combo_state);
		prngCOMBOStepR(b, O_OF_W(n), combo_state);
		// zzAdd / zzSub / zzIsSumEq
		carry = zzAdd(c, a, b, n);
		if (zzSub(c1, c, b, n) != carry || 
			!wwEq(c1, a, n) ||
			SAFE(zzIsSumEq)(c, a, b, n) != wordEq(carry, 0) ||
			FAST(zzIsSumEq)(c, a, b, n) != wordEq(carry, 0))
			return FALSE;
		// zzAdd2 / zzSub2
		wwCopy(c1, a, n);
		if (zzAdd2(c1, b, n) != carry || 
			!wwEq(c1, c, n) ||
			zzSub2(c1, b, n) != carry ||
			!wwEq(c1, a, n))
			return FALSE;
		// zzAddW / zzSubW / zzIsSumEqW
		carry = zzAddW(c, a, n, b[0]);
		if (zzSubW(c1, c, n, b[0]) != carry || 
			!wwEq(c1, a, n) ||
			SAFE(zzIsSumWEq)(c, a, n, b[0]) != wordEq(carry, 0) ||
			FAST(zzIsSumWEq)(c, a, n, b[0]) != wordEq(carry, 0))
			return FALSE;
		// zzAddW2 / zzSubW2
		wwCopy(c1, a, n);
		if (zzAddW2(c1, n, b[0]) != carry || 
			!wwEq(c1, c, n) ||
			zzSubW2(c1, n, b[0]) != carry || 
			!wwEq(c1, a, n))
			return FALSE;
		// zzAddW / zzSubW / zzIsSumEqW [n <- 1]
		carry = zzAddW(c, a, 1, b[0]);
		if (zzSubW(c1, c, 1, b[0]) != carry || 
			!wwEq(c1, a, 1) ||
			SAFE(zzIsSumWEq)(c, a, 1, b[0]) != wordEq(carry, 0) ||
			FAST(zzIsSumWEq)(c, a, 1, b[0]) != wordEq(carry, 0))
			return FALSE;
		// zzAdd3 / zzAdd
		carry = zzAdd(c, a, b, n);
		if (zzAdd3(c1, a, n, b, n) != carry ||
			!wwEq(c1, c, n))
			return FALSE;
		b[n - 1] = 0;
		carry = zzAdd(c, a, b, n);
		if (zzAdd3(c1, a, n, b, n - 1) != carry ||
			!wwEq(c1, c, n) ||
			zzAdd3(c1, b, n - 1, a, n) != carry ||
			!wwEq(c1, c, n))
			return FALSE;
		// zzNeg / zzAdd
		zzNeg(b, a, n);
		if (zzAdd(c, a, b, n) != 1 ||
			!wwIsZero(c, n))
			return FALSE;
	}
	// все нормально
	return TRUE;
}

static bool_t zzTestMul()
{
	enum { n = 8 };
	size_t reps = 500;
	word a[n];
	word b[n];
	word r[n];
	word c[2 * n];
	word c1[2 * n];
	word b1[n + 1];
	word r1[n];
	octet combo_state[32];
	octet stack[2048];
	// подготовить память
	if (sizeof(combo_state) < prngCOMBO_keep() ||
		sizeof(stack) < utilMax(4,
			zzMul_deep(n, n),
			zzSqr_deep(n),
			zzDiv_deep(2 * n, n),
			zzMod_deep(2 * n, n)))
		return FALSE;
	// инициализировать генератор COMBO
	prngCOMBOStart(combo_state, utilNonce32());
	// умножение / деление
	while (reps--)
	{
		size_t na, nb;
		word w;
		prngCOMBOStepR(a, O_OF_W(n), combo_state);
		prngCOMBOStepR(b, O_OF_W(n), combo_state);
		// zzSqr / zzMul
		for (na = 1; na <= n; ++na)
		{
			zzSqr(c, a, na, stack);
			zzMul(c1, a, na, a, na, stack);
			if (!wwEq(c, c1, na + na))
				return FALSE;
		}
		// zzMul / zzDiv / zzMod
		for (na = 1; na <= n; ++na)
		{
			a[na - 1] = a[na - 1] ? a[na - 1] : WORD_1;
			zzRandMod(r, a, na, prngCOMBOStepR, combo_state);
			for (nb = 1; nb <= n; ++nb)
			{
				zzMul(c, a, na, b, nb, stack);
				zzAddW2(c + na, nb, zzAdd2(c, r, na)); 
				zzMod(r1, c, na + nb, a, na, stack);
				if (!wwEq(r, r1, na))
					return FALSE;
				zzDiv(b1, r1, c, na + nb, a, na, stack);
				if (!wwEq(r, r1, na) || !wwEq(b, b1, nb) || b1[nb] != 0)
					return FALSE;
			}
		}
		// zzAddMulW / zzSubMulW
		for (na = 1; na <= n; ++na)
		{
			word carry, carry1;
			w = r[na - 1];
			wwCopy(c, a, na);
			carry = zzAddMulW(c, b, na, w);
			carry1 = zzSubMulW(c, b, na, w);
			if (carry != carry1 || !wwEq(c, a, na))
				return FALSE;
		}
		// zzMulW / zzDivW / zzModW / zzModW2
		for (na = 1; na <= n; ++na)
		{
			w = r[na - 1];
			w = w ? w : 1;
			c[na] = zzMulW(c, a, na, w);
			zzDivW(c1, c, na + 1, w);
			if (!wwEq(c1, a, na) || c1[na] != 0)
				return FALSE;
			r[0] %= w;
			c[na + 1] = zzAddW(c, c, na + 1, r[0]);
			if (zzModW(c, na + 2, w) != r[0])
				return FALSE;
			w &= WORD_BIT_HALF - WORD_1;
			w = w ? w : WORD_BIT_HALF;
			r[1] %= w;
			c[na] = zzMulW(c, a, na, w);
			c[na + 1] = zzAddW(c, c, na + 1, r[1]);
			if (zzModW2(c, na + 2, w) != r[1])
				return FALSE;
		}
	}
	// особенные случаи zzDiv()
	{
		ASSERT(n > 3);
		// переполнение частного, уточнение пробного частного
		b1[0] = b1[1] = WORD_MAX;
		b[0] = WORD_MAX, b[1] = WORD_BIT_HI;
		zzMul(a, b, 2, b1, 2, stack);
		zzDiv(c1, r, a, 4, b, 2, stack);
		if (!wwIsZero(r, 2) || !wwEq(c1, b1, 2) || c1[2] != 0)
			return FALSE;
		// корректирующее сложение
		b1[0] = b1[1] = b1[2] = WORD_MAX;
		b[0] = WORD_MAX, b[1] = 0, b[2] = WORD_BIT_HI;
		zzMul(a, b, 3, b1, 3, stack);
		zzDiv(c1, r, a, 6, b, 3, stack);
		if (!wwIsZero(r, 2) || !wwEq(c1, b1, 3) || c1[3] != 0)
			return FALSE;
	}
	// все нормально
	return TRUE;
}

static bool_t zzTestMod()
{
	enum { n = 8 };
	size_t reps = 500;
	word a[n];
	word b[n];
	word t[n];
	word t1[n];
	word mod[n];
	octet combo_state[32];
	octet stack[2048];
	// подготовить память
	if (sizeof(combo_state) < prngCOMBO_keep() ||
		sizeof(stack) < utilMax(10,
			zzPowerMod_deep(n, 1),
			zzMulMod_deep(n),
			zzSqrMod_deep(n),
			zzMod_deep(n, n),
			zzJacobi_deep(n, n),
			zzGCD_deep(n, n),
			zzIsCoprime_deep(n, n),
			zzDivMod_deep(n),
			zzInvMod_deep(n),
			zzAlmostInvMod_deep(n)))
		return FALSE;
	// инициализировать генератор COMBO
	prngCOMBOStart(combo_state, utilNonce32());
	// возведение в степень
	wwRepW(mod, n, WORD_MAX);
	if (!zzIsOdd(mod, n) || zzIsEven(mod, n))
		return FALSE;
	if (!zzRandMod(a, mod, n, prngCOMBOStepR, combo_state))
		return FALSE;
	b[0] = 3;
	zzPowerMod(t, a, n, b, 1, mod, stack);
	zzSqrMod(t1, a, mod, n, stack);
	zzMulMod(t1, t1, a, mod, n, stack);
	if (wwCmp(t, t1, n) != 0)
		return FALSE;
	// сложение / вычитание
	while (reps--)
	{
		size_t k;
		// генерация
		prngCOMBOStepR(mod, O_OF_W(n), combo_state);
		prngCOMBOStepR(a, O_OF_W(n), combo_state);
		prngCOMBOStepR(b, O_OF_W(n), combo_state);
		if (mod[n - 1] == 0)
			mod[n - 1] = WORD_MAX;
		zzMod(a, a, n, mod, n, stack);
		zzMod(b, b, n, mod, n, stack);
		// SAFE(zzAddMod) / SAFE(zzSubMod)
		SAFE(zzAddMod)(t, a, b, mod, n);
		SAFE(zzSubMod)(t1, t, b, mod, n);
		if (!SAFE(wwEq)(t1, a, n))
			return FALSE;
		SAFE(zzSubMod)(t1, t, a, mod, n);
		if (!SAFE(wwEq)(t1, b, n))
			return FALSE;
		// FAST(zzAddMod) / FAST(zzSubMod)
		FAST(zzAddMod)(t, a, b, mod, n);
		FAST(zzSubMod)(t1, t, b, mod, n);
		if (!FAST(wwEq)(t1, a, n))
			return FALSE;
		FAST(zzSubMod)(t1, t, a, mod, n);
		if (!FAST(wwEq)(t1, b, n))
			return FALSE;
		// SAFE(zzAddWMod) / SAFE(zzSubWMod)
		SAFE(zzAddWMod)(t, a, b[0], mod, n);
		SAFE(zzSubWMod)(t1, t, b[0], mod, n);
		if (!SAFE(wwEq)(t1, a, n))
			return FALSE;
		// FAST(zzAddWMod) / FAST(zzSubWMod)
		FAST(zzAddWMod)(t, a, b[0], mod, n);
		FAST(zzSubWMod)(t1, t, b[0], mod, n);
		if (!FAST(wwEq)(t1, a, n))
			return FALSE;
		// SAFE(zzNegMod)
		SAFE(zzNegMod)(t, a, mod, n);
		SAFE(zzAddMod)(t1, t, a, mod, n);
		if (!SAFE(wwIsZero)(t1, n))
			return FALSE;
		SAFE(zzNegMod)(t1, t1, mod, n);
		if (!SAFE(wwIsZero)(t1, n))
			return FALSE;
		// FAST(zzNegMod)
		FAST(zzNegMod)(t, a, mod, n);
		FAST(zzAddMod)(t1, t, a, mod, n);
		if (!FAST(wwIsZero)(t1, n))
			return FALSE;
		FAST(zzNegMod)(t1, t1, mod, n);
		if (!FAST(wwIsZero)(t1, n))
			return FALSE;
		// SAFE(zzDoubleMod) / SAFE(zzHalfMod)
		mod[0] |= 1;
		SAFE(zzHalfMod)(t, a, mod, n);
		SAFE(zzDoubleMod)(t1, t, mod, n);
		if (!SAFE(wwEq)(t1, a, n))
			return FALSE;
		// FAST(zzDoubleMod) / FAST(zzHalfMod)
		FAST(zzHalfMod)(t, a, mod, n);
		FAST(zzDoubleMod)(t1, t, mod, n);
		if (!FAST(wwEq)(t1, a, n))
			return FALSE;
		// zzMulMod / zzSqrMod
		zzMulMod(t, a, a, mod, n, stack);
		zzSqrMod(t1, a, mod, n, stack);
		if (!wwEq(t, t1, n))
			return FALSE;
		if (zzJacobi(t1, n, mod, n, stack) == -1)
			return FALSE;
		// zzMulMod / zzDivMod / zzInvMod
		zzGCD(t, a, n, mod, n, stack);
		if (wwCmpW(t, n, 1) != 0)
			continue;
		if (!zzIsCoprime(a, n, mod, n, stack))
			return FALSE;
		zzInvMod(t, a, mod, n, stack);
		zzMulMod(t, t, b, mod, n, stack);
		zzDivMod(t1, b, a, mod, n, stack);
		if (!wwEq(t, t1, n))
			return FALSE;
		zzMulMod(t1, t1, a, mod, n, stack);
		if (!wwEq(t1, b, n))
			return FALSE;
		// zzMulWMod / zzMulMod
		wwSetZero(b + 1, n - 1);
		zzMulWMod(t, a, b[0], mod, n, stack);
		zzMulMod(t1, a, b, mod, n, stack);
		if (!wwEq(t, t1, n))
			return FALSE;
		// zzAlmostInvMod
		k = zzAlmostInvMod(t, a, mod, n, stack);
		while (k--)
			zzHalfMod(t, t, mod, n);
		zzInvMod(t1, a, mod, n, stack);
		if (!wwEq(t, t1, n))
			return FALSE;

	}
	// все нормально
	return TRUE;
}

static bool_t zzTestGCD()
{
	enum { n = 8 };
	size_t reps = 100;
	word a[n];
	word b[n];
	word t[n];
	word t1[2 * n];
	word p[2 * n];
	word p1[3 * n];
	octet combo_state[32];
	octet stack[2048];
	// подготовить память
	if (sizeof(combo_state) < prngCOMBO_keep() ||
		sizeof(stack) < utilMax(4,
			zzMul_deep(n, n),
			zzGCD_deep(n, n),
			zzLCM_deep(n, n),
			zzExGCD_deep(n, n)))
		return FALSE;
	// инициализировать генератор COMBO
	prngCOMBOStart(combo_state, utilNonce32());
	// эксперименты
	while (reps--)
	{
		size_t na, nb;
		// генерация
		prngCOMBOStepR(a, O_OF_W(n), combo_state);
		prngCOMBOStepR(b, O_OF_W(n), combo_state);
		a[0] = a[0] ? a[0] : 1;
		b[0] = b[0] ? b[0] : 2;
		// цикл по длинами
		for (na = 1; na < n; ++na)
		for (nb = 1; nb < n; ++nb)
		{
			// zzGCD / zzLCM / zzMul
			zzGCD(t, a, na, b, nb, stack);
			zzLCM(t1, a, na, b, nb, stack);
			zzMul(p, a, na, b, nb, stack);
			zzMul(p1, t, MIN2(na, nb), t1, na + nb, stack);
			if (wwCmp2(p, na + nb, p1, na + nb + MIN2(na, nb)) != 0)
				return FALSE;
			// zzExGCD / zzMul
			zzExGCD(t, t1, t1 + n, a, na, b, nb, stack);
			zzMul(p, t1, nb, a, na, stack);
			zzMul(p1, t1 + n, na, b, nb, stack);
			zzSub2(p, p1, na + nb);
			if (wwCmp2(p, na + nb, t, MIN2(na, nb)) != 0)
				return FALSE;
		}
	}
	return TRUE;
}

static bool_t zzTestRed()
{
	enum { n = 8 };
	size_t reps = 500;
	word a[2 * n];
	word t[2 * n];
	word t1[2 * n];
	word barr_param[n + 2];
	word mod[n];
	octet combo_state[32];
	octet stack[2048];
	// подготовить память
	if (sizeof(combo_state) < prngCOMBO_keep() ||
		sizeof(stack) < utilMax(6,
			zzRed_deep(n),
			zzRedCrand_deep(n),
			zzRedBarrStart_deep(n),
			zzRedBarr_deep(n),
			zzRedMont_deep(n),
			zzRedCrandMont_deep(n)))
		return FALSE;
	// инициализировать генератор COMBO
	prngCOMBOStart(combo_state, utilNonce32());
	// редукция
	while (reps--)
	{
		// генерация
		prngCOMBOStepR(mod, O_OF_W(n), combo_state);
		prngCOMBOStepR(a, O_OF_W(2 * n), combo_state);
		mod[n - 1] = mod[n - 1] ? mod[n - 1] : 1;
		// zzRed / zzRedBarr
		wwCopy(t, a, 2 * n);
		zzRed(t, mod, n, stack);
		zzRedBarrStart(barr_param, mod, n, stack);
		wwCopy(t1, a, 2 * n);
		zzRedBarr(t1, mod, n, barr_param, stack);
		if (!wwEq(t1, t, n))
			return FALSE;
		// zzRed / FAST(zzRedBarr)
		wwCopy(t1, a, 2 * n);
		FAST(zzRedBarr)(t1, mod, n, barr_param, stack);
		if (!wwEq(t1, t, n))
			return FALSE;
		// zzRed / SAFE(zzRedMont)
		mod[0] |= 1;
		wwCopy(t, a, 2 * n);
		zzRed(t, mod, n, stack);
		wwCopy(t1, a, 2 * n);
		SAFE(zzRedMont)(t1, mod, n, wordNegInv(mod[0]), stack);
		wwCopy(t1 + n, t1, n);
		wwSetZero(t1, n);
		zzRed(t1, mod, n, stack);
		if (!wwEq(t1, t, n))
			return FALSE;
		// zzRed / FAST(zzRedMont)
		wwCopy(t1, a, 2 * n);
		FAST(zzRedMont)(t1, mod, n, wordNegInv(mod[0]), stack);
		wwCopy(t1 + n, t1, n);
		wwSetZero(t1, n);
		zzRed(t1, mod, n, stack);
		if (!wwEq(t1, t, n))
			return FALSE;
		// zzRed / SAFE(zzRedCrand)
		wwRepW(mod + 1, n - 1, WORD_MAX);
		wwCopy(t, a, 2 * n);
		zzRed(t, mod, n, stack);
		wwCopy(t1, a, 2 * n);
		SAFE(zzRedCrand)(t1, mod, n, stack);
		if (!wwEq(t1, t, n))
			return FALSE;
		// zzRed / FAST(zzRedCrand)
		wwCopy(t1, a, 2 * n);
		FAST(zzRedCrand)(t1, mod, n, stack);
		if (!wwEq(t1, t, n))
			return FALSE;
		// SAFE(zzRedMont) / SAFE(zzRedCrandMont)
		wwCopy(t, a, 2 * n);
		wwCopy(t1, a, 2 * n);
		SAFE(zzRedMont)(t, mod, n, wordNegInv(mod[0]), stack);
		SAFE(zzRedCrandMont)(t1, mod, n, wordNegInv(mod[0]), stack);
		if (!SAFE(wwEq)(t1, t, n))
			return FALSE;
		// FAST(zzRedMont) / FAST(zzRedCrandMont)
		wwCopy(t, a, 2 * n);
		wwCopy(t1, a, 2 * n);
		FAST(zzRedMont)(t, mod, n, wordNegInv(mod[0]), stack);
		FAST(zzRedCrandMont)(t1, mod, n, wordNegInv(mod[0]), stack);
		if (!FAST(wwEq)(t1, t, n))
			return FALSE;
	}
	return TRUE;
}

static bool_t zzTestEtc()
{
	enum { n = 8 };
	size_t reps1 = 500;
	size_t reps2 = 500;
	word a[n];
	word b[2 * n];
	word t[(2 * n + 1) / 2];
	octet combo_state[32];
	octet stack[2048];
	// подготовить память
	if (sizeof(combo_state) < prngCOMBO_keep() ||
		sizeof(stack) < utilMax(3,
			zzSqr_deep(n),
			zzSqrt_deep(n),
			zzJacobi_deep(2 * n, n)))
		return FALSE;
	// инициализировать генератор COMBO
	prngCOMBOStart(combo_state, utilNonce32());
	// символ Якоби
	while (reps1--)
	{
		prngCOMBOStepR(a, O_OF_W(n), combo_state);
		zzSqr(b, a, n, stack);
		prngCOMBOStepR(t, O_OF_W(n), combo_state);
		t[0] |= 1;
		// (a^2 / t) != -1?
		if (zzJacobi(b, 2 * n, t, n, stack) == -1)
			return FALSE;
	}
	// квадратные корни
	while (reps2--)
	{
		prngCOMBOStepR(a, O_OF_W(n), combo_state);
		// sqrt(a^2) == a?
		zzSqr(b, a, n, stack);
		zzSqrt(t, b, 2 * n, stack);
		if (!wwEq(a, t, n))
			return FALSE;
		// sqrt(a^2 + 1) == a?
		zzAddW2(b, 2 * n, 1);
		zzSqrt(t, b, 2 * n, stack);
		if (!wwEq(a, t, n))
			return FALSE;
		// sqrt(a^2 - 1) + 1 == a?
		if (wwIsZero(a, n))
			continue;
		zzSubW2(b, 2 * n, 2);
		zzSqrt(t, b, 2 * n, stack);
		if (wwEq(a, t, n))
			return FALSE;
		if (!zzIsSumWEq(a, t, n, 1))
			return FALSE;
	}
	return TRUE;

}

bool_t zzTest()
{
	return zzTestAdd() && 
		zzTestMul() && 
		zzTestMod() && 
		zzTestGCD() && 
		zzTestRed() &&
		zzTestEtc();
}
