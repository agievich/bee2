/*
*******************************************************************************
\file zz-test.c
\brief Tests for multiple-precision unsigned integers
\project bee2/test
\author (С) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2014.07.15
\version 2014.07.15
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

/*
*******************************************************************************
\file zz-test.c
\brief Тестирование работы с большими числами
\author (С) Сергей Агиевич, http://apmi.bsu.by
\created 2014.07.15
\version 2014.07.15
*******************************************************************************
*/

#include <bee2/core/mem.h>
#include <bee2/core/prng.h>
#include <bee2/core/util.h>
#include <bee2/math/zz.h>
#include <bee2/math/word.h>
#include <bee2/math/ww.h>

/*
*******************************************************************************
Тестирование
*******************************************************************************
*/

bool_t zzTest()
{
	const size_t n = 8;
	size_t reps;
	word a[8];
	word b[8];
	word c[8];
	word c1[8];
	word mod[8];
	octet combo_state[32];
	octet stack[2048];
	// pre
	ASSERT(COUNT_OF(a) >= n);
	ASSERT(COUNT_OF(b) >= n);
	ASSERT(COUNT_OF(c) >= n);
	ASSERT(COUNT_OF(c1) >= n);
	ASSERT(COUNT_OF(mod) >= n);
	// инициализровать генератор COMBO
	ASSERT(prngCOMBO_keep() <= sizeof(combo_state));
	prngCOMBOStart(combo_state, utilNonce32());
	// возведение в степень
	ASSERT(zzPowerMod_deep(n, 1) <= sizeof(stack));
	ASSERT(zzMulMod_deep(n) <= sizeof(stack));
	ASSERT(zzSqrMod_deep(n) <= sizeof(stack));
	wwRepW(mod, n, WORD_MAX);
	if (!zzRandMod(a, mod, n, prngCOMBOStepG, combo_state))
		return FALSE;
	b[0] = 3;
	zzPowerMod(c, a, n, b, 1, mod, stack);
	zzSqrMod(c1, a, mod, n, stack);
	zzMulMod(c1, c1, a, mod, n, stack);
	if (wwCmp(c, c1, n) != 0)
		return FALSE;
	// сложение / вычитание
	for (reps = 0; reps < 1000; ++reps)
	{
		word carry;
		prngCOMBOStepG(a, O_OF_W(n), combo_state);
		prngCOMBOStepG(b, O_OF_W(n), combo_state);
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
			zzIsSumWEq(c, a, n, b[0]) != wordEq(carry, 0))
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
	}
	// все нормально
	return TRUE;
}
