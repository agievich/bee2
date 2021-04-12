/*
*******************************************************************************
\file zz_test.c
\brief Tests for multiple-precision unsigned integers
\project bee2/test
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2014.07.15
\version 2016.09.12
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include <bee2/core/mem.h>
#include <bee2/core/prng.h>
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
	const size_t n = 8;
	size_t reps;
	word a[8];
	word b[8];
	word c[8];
	word c1[8];
	octet combo_state[32];
	// pre
	ASSERT(COUNT_OF(a) >= n);
	ASSERT(COUNT_OF(b) >= n);
	ASSERT(COUNT_OF(c) >= n);
	ASSERT(COUNT_OF(c1) >= n);
	// инициализировать генератор COMBO
	ASSERT(prngCOMBO_keep() <= sizeof(combo_state));
	prngCOMBOStart(combo_state, utilNonce32());
	// сложение / вычитание
	for (reps = 0; reps < 500; ++reps)
	{
		word carry;
		prngCOMBOStepR(a, O_OF_W(n), combo_state);
		prngCOMBOStepR(b, O_OF_W(n), combo_state);
		// zzAdd / zzSub / zzIsSumEq
		carry = zzAdd(c, a, b, n);
		if (zzSub(c1, c, b, n) != carry || 
			!wwEq(c1, a, n) ||
			zzIsSumEq(c, a, b, n) != wordEq(carry, 0))
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
			zzIsSumWEq(c, a, n, b[0]) != wordEq(carry, 0) ||
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
			zzIsSumWEq(c, a, 1, b[0]) != wordEq(carry, 0))
			return FALSE;
		// zzNeg
		zzNeg(c, a, n);
		zzAdd(c1, a, c, n);
		if (!wwIsZero(c1, n)) {
			return FALSE;
		}
		// zzSetSign
		zzSetSign(c, a, n, TRUE);
		zzNeg(c1, a, n);
		if (!wwEq(c, c1, n)) {
			return FALSE;
		}
		zzSetSign(c, a, n, FALSE);
		if (!wwEq(a, c, n)) {
			return FALSE;
		}
		//FAST(zzSetSign)
		FAST(zzSetSign)(c, a, n, TRUE);
		zzNeg(c1, a, n);
		if (!wwEq(c, c1, n)) {
			return FALSE;
		}
		FAST(zzSetSign)(c, a, n, FALSE);
		if (!wwEq(a, c, n)) {
			return FALSE;
		}
	}
	// все нормально
	return TRUE;
}

static bool_t zzTestMul()
{
	const size_t n = 8;
	size_t reps;
	word a[8];
	word b[8];
	word r[8];
	word c[16];
	word c1[16];
	word b1[8 + 1];
	word r1[8];
	octet combo_state[32];
	octet stack[2048];
	// pre
	ASSERT(COUNT_OF(a) >= n);
	ASSERT(COUNT_OF(b) >= n);
	ASSERT(COUNT_OF(r) >= n);
	ASSERT(COUNT_OF(c) >= 2 * n);
	ASSERT(COUNT_OF(c1) >= 2 * n);
	ASSERT(COUNT_OF(b1) >= n + 1);
	ASSERT(COUNT_OF(r1) >= n);
	ASSERT(zzMul_deep(n, n) <= sizeof(stack));
	ASSERT(zzSqr_deep(n) <= sizeof(stack));
	ASSERT(zzDiv_deep(2 * n, n) <= sizeof(stack));
	ASSERT(zzMod_deep(2 * n, n) <= sizeof(stack));
	// инициализировать генератор COMBO
	ASSERT(prngCOMBO_keep() <= sizeof(combo_state));
	prngCOMBOStart(combo_state, utilNonce32());
	// умножение / деление
	for (reps = 0; reps < 500; ++reps)
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
	// все нормально
	return TRUE;
}

static bool_t zzTestMod()
{
	const size_t n = 8;
	size_t reps;
	word a[8];
	word b[8];
	word t[8];
	word t1[8];
	word mod[8];
	octet combo_state[32];
	octet stack[2048];
	// pre
	ASSERT(COUNT_OF(a) >= n);
	ASSERT(COUNT_OF(b) >= n);
	ASSERT(COUNT_OF(t) >= n);
	ASSERT(COUNT_OF(t1) >= n);
	ASSERT(COUNT_OF(mod) >= n);
	ASSERT(zzPowerMod_deep(n, 1) <= sizeof(stack));
	ASSERT(zzMulMod_deep(n) <= sizeof(stack));
	ASSERT(zzSqrMod_deep(n) <= sizeof(stack));
	ASSERT(zzMod_deep(n, n) <= sizeof(stack));
	ASSERT(zzJacobi_deep(n, n) <= sizeof(stack));
	ASSERT(zzGCD_deep(n, n) <= sizeof(stack));
	ASSERT(zzIsCoprime_deep(n, n) <= sizeof(stack));
	ASSERT(zzDivMod_deep(n) <= sizeof(stack));
	ASSERT(zzInvMod_deep(n) <= sizeof(stack));
	ASSERT(zzAlmostInvMod_deep(n) <= sizeof(stack));
	// инициализировать генератор COMBO
	ASSERT(prngCOMBO_keep() <= sizeof(combo_state));
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
	for (reps = 0; reps < 500; ++reps)
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
		// zzAddMod / zzSubMod
		zzAddMod(t, a, b, mod, n);
		zzSubMod(t1, t, b, mod, n);
		if (!wwEq(t1, a, n))
			return FALSE;
		zzSubMod(t1, t, a, mod, n);
		if (!wwEq(t1, b, n))
			return FALSE;
		// FAST(zzAddMod) / FAST(zzSubMod)
		FAST(zzAddMod)(t, a, b, mod, n);
		FAST(zzSubMod)(t1, t, b, mod, n);
		if (!FAST(wwEq)(t1, a, n))
			return FALSE;
		FAST(zzSubMod)(t1, t, a, mod, n);
		if (!FAST(wwEq)(t1, b, n))
			return FALSE;
		// zzAddWMod / zzSubWMod
		zzAddWMod(t, a, b[0], mod, n);
		zzSubWMod(t1, t, b[0], mod, n);
		if (!wwEq(t1, a, n))
			return FALSE;
		// FAST(zzAddWMod) / FAST(zzSubWMod)
		FAST(zzAddWMod)(t, a, b[0], mod, n);
		FAST(zzSubWMod)(t1, t, b[0], mod, n);
		if (!FAST(wwEq)(t1, a, n))
			return FALSE;
		// zzNegMod
		zzNegMod(t, a, mod, n);
		zzAddMod(t1, t, a, mod, n);
		if (!wwIsZero(t1, n))
			return FALSE;
		zzNegMod(t1, t1, mod, n);
		if (!wwIsZero(t1, n))
			return FALSE;
		// FAST(zzNegMod)
		FAST(zzNegMod)(t, a, mod, n);
		FAST(zzAddMod)(t1, t, a, mod, n);
		if (!FAST(wwIsZero)(t1, n))
			return FALSE;
		FAST(zzNegMod)(t1, t1, mod, n);
		if (!FAST(wwIsZero)(t1, n))
			return FALSE;
		// zzSetSign.
		zzSetSignMod(t, a, mod, n, TRUE);
		zzAddMod(t1, t, a, mod, n);
		if (!wwIsZero(t1, n))
			return FALSE;
		zzSetSignMod(t1, t1, mod, n, TRUE);
		if (!wwIsZero(t1, n))
			return FALSE;
		zzSetSignMod(t, a, mod, n, FALSE);
		zzSubMod(t1, t, a, mod, n);
		if (!wwIsZero(t1, n))
			return FALSE;
		zzSetSignMod(t1, t1, mod, n, FALSE);
		if (!wwIsZero(t1, n))
			return FALSE;
		// FAST(zzSetSign)
		FAST(zzSetSignMod)(t, a, mod, n, TRUE);
		FAST(zzAddMod)(t1, t, a, mod, n);
		if (!FAST(wwIsZero)(t1, n))
			return FALSE;
		FAST(zzSetSignMod)(t1, t1, mod, n, TRUE);
		if (!FAST(wwIsZero)(t1, n))
			return FALSE;
		FAST(zzSetSignMod)(t, a, mod, n, FALSE);
		FAST(zzSubMod)(t1, t, a, mod, n);
		if (!FAST(wwIsZero)(t1, n))
			return FALSE;
		FAST(zzSetSignMod)(t1, t1, mod, n, FALSE);
		if (!FAST(wwIsZero)(t1, n))
			return FALSE;
		// zzDoubleMod / zzHalfMod
		mod[0] |= 1;
		zzHalfMod(t, a, mod, n);
		zzDoubleMod(t1, t, mod, n);
		if (!wwEq(t1, a, n))
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
	const size_t n = 8;
	size_t reps;
	word a[8];
	word b[8];
	word t[8];
	word t1[16];
	word p[16];
	word p1[24];
	octet combo_state[32];
	octet stack[2048];
	// pre
	ASSERT(COUNT_OF(a) >= n);
	ASSERT(COUNT_OF(b) >= n);
	ASSERT(COUNT_OF(t) >= n);
	ASSERT(COUNT_OF(t1) >= 2 * n);
	ASSERT(COUNT_OF(p) >= 2 * n);
	ASSERT(COUNT_OF(p1) >= 3 * n);
	ASSERT(zzMul_deep(n, n) <= sizeof(stack));
	ASSERT(zzGCD_deep(n, n) <= sizeof(stack));
	ASSERT(zzLCM_deep(n, n) <= sizeof(stack));
	ASSERT(zzExGCD_deep(n, n) <= sizeof(stack));
	// инициализировать генератор COMBO
	ASSERT(prngCOMBO_keep() <= sizeof(combo_state));
	prngCOMBOStart(combo_state, utilNonce32());
	// эксперименты
	for (reps = 0; reps < 100; ++reps)
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
			int sign;
			// zzGCD / zzLCM / zzMul
			zzGCD(t, a, na, b, nb, stack);
			zzLCM(t1, a, na, b, nb, stack);
			zzMul(p, a, na, b, nb, stack);
			zzMul(p1, t, MIN2(na, nb), t1, na + nb, stack);
			if (wwCmp2(p, na + nb, p1, na + nb + MIN2(na, nb)) != 0)
				return FALSE;
			// zzExGCD / zzMul
			sign = zzExGCD(t, t1, t1 + n, a, na, b, nb, stack);
			zzMul(p, t1, nb, a, na, stack);
			zzMul(p1, t1 + n, na, b, nb, stack);
			if (sign == 1)
				zzSub2(p, p1, na + nb);
			else 
				zzSub(p, p1, p, na + nb);
			if (wwCmp2(p, na + nb, t, MIN2(na, nb)) != 0)
				return FALSE;
		}
	}
	// все нормально
	return TRUE;
}

static bool_t zzTestRed()
{
	const size_t n = 8;
	size_t reps;
	word a[16];
	word t[16];
	word t1[16];
	word barr_param[10];
	word mod[8];
	octet combo_state[32];
	octet stack[2048];
	// pre
	ASSERT(COUNT_OF(a) >= 2 * n);
	ASSERT(COUNT_OF(t) >= 2 * n);
	ASSERT(COUNT_OF(t1) >= 2 * n);
	ASSERT(COUNT_OF(mod) >= n);
	ASSERT(zzRed_deep(n) <= sizeof(stack));
	ASSERT(zzRedCrand_deep(n) <= sizeof(stack));
	ASSERT(zzRedBarrStart_deep(n) <= sizeof(stack));
	ASSERT(zzRedBarr_deep(n) <= sizeof(stack));
	ASSERT(zzRedMont_deep(n) <= sizeof(stack));
	ASSERT(zzRedCrandMont_deep(n) <= sizeof(stack));
	// инициализировать генератор COMBO
	ASSERT(prngCOMBO_keep() <= sizeof(combo_state));
	prngCOMBOStart(combo_state, utilNonce32());
	// редукция
	for (reps = 0; reps < 500; ++reps)
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
		// zzRed / zzRedMont
		mod[0] |= 1;
		wwCopy(t, a, 2 * n);
		zzRed(t, mod, n, stack);
		wwCopy(t1, a, 2 * n);
		zzRedMont(t1, mod, n, wordNegInv(mod[0]), stack);
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
		// zzRed / zzRedCrand
		wwRepW(mod + 1, n - 1, WORD_MAX);
		wwCopy(t, a, 2 * n);
		zzRed(t, mod, n, stack);
		wwCopy(t1, a, 2 * n);
		zzRedCrand(t1, mod, n, stack);
		if (!wwEq(t1, t, n))
			return FALSE;
		// zzRed / FAST(zzRedCrand)
		wwCopy(t1, a, 2 * n);
		FAST(zzRedCrand)(t1, mod, n, stack);
		if (!wwEq(t1, t, n))
			return FALSE;
		// zzRedMont / zzRedCrandMont
		wwCopy(t, a, 2 * n);
		wwCopy(t1, a, 2 * n);
		zzRedMont(t, mod, n, wordNegInv(mod[0]), stack);
		zzRedCrandMont(t1, mod, n, wordNegInv(mod[0]), stack);
		if (!wwEq(t1, t, n))
			return FALSE;
		// FAST(zzRedMont) / FAST(zzRedCrandMont)
		wwCopy(t, a, 2 * n);
		wwCopy(t1, a, 2 * n);
		FAST(zzRedMont)(t, mod, n, wordNegInv(mod[0]), stack);
		FAST(zzRedCrandMont)(t1, mod, n, wordNegInv(mod[0]), stack);
		if (!FAST(wwEq)(t1, t, n))
			return FALSE;
	}
	// все нормально
	return TRUE;
}

bool_t zzTest()
{
	return zzTestAdd() && 
		zzTestMul() && 
		zzTestMod() && 
		zzTestGCD() && 
		zzTestRed();
}

