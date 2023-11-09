/*
*******************************************************************************
\file pp_test.c
\brief Tests for the arithmetic of binary polynomials
\project bee2/test
\created 2023.11.09
\version 2023.11.09
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <bee2/core/mem.h>
#include <bee2/core/util.h>
#include <bee2/math/pp.h>
#include <bee2/core/u16.h>
#include <bee2/math/ww.h>

/*
*******************************************************************************
Экспоненциальные S-блоки размерности 16

\remark https://eprint.iacr.org/2004/024.

\pre Многочлен x^16 + poly(x) неприводим. Здесь для 16-битового слова p
c битами p_0 (младший), p_1, ..., p_15 (старший) через p(x) обозначается
многочлен
	p_15 x^15 + ... + p_1 x + p_0.

\pre Многочлен alpha(x) является примитивным элементом поля
	GF(2^16) = GF(2)[x] / (x^16 + poly(x)).
*******************************************************************************
*/

static u16 exps16Mul(u16 a, u16 b, u16 poly)
{
	size_t i;
	u16 c;
	for (c = 0, i = 0; i < 16; ++i)
	{
		if (a & 1)
			c ^= b;
		a >>= 1;
		b = (b << 1) ^ ((b & 0x8000) ? poly : 0);
	}
	return c;
}

static void exps16Create(u16 s[65536], u16 poly, u16 alpha)
{
	size_t pos;
	for (s[0] = 0, s[1] = alpha, pos = 2; pos < 65536; ++pos)
		s[pos] = exps16Mul(s[pos - 1], alpha, poly);
}

/*
*******************************************************************************
Тест на построение экспоненциальных S-блоков

\remark Многочлен x^16 + x^5 + x^3 + x + 1, который ниже задается словом poly,
является лексикографически минимальным неприводимым пентаномом
(см. https://www.hpl.hp.com/techreports/98/HPL-98-135.pdf).
Неприводимых триномов степени 16 (и, вообще, любой степени кратной 8)
не существует [Swan R.G. Factorization of polynomials over finite fields.
Pacific J. Math., 12, pp. 1099-1106, 1962].
*******************************************************************************
*/

static bool_t ppTestExps16()
{
	const u16 poly = 0x002B;
	const u16 alpha = 0x0003;
	#define n W_OF_B(16)
	word mod[n];
	word a[n];
	word t[n];
	u16 s1[65536];
	u16 s2[65536];
	octet stack[1024];
	size_t pos;
	// подготовить память
	if (sizeof(stack) < utilMax(2,
			ppIsIrred_deep(n),
			ppMulMod_deep(n)))
		return FALSE;
	// построить модуль (неприводимый многочлен)
	u16To(mod, 2, &poly);
	wwFrom(mod, mod, 2);
	wwSetBit(mod, 16, TRUE);
	if (!ppIsIrred(mod, n, stack))
		return FALSE;
	// построить примитивный элемент
	u16To(a, 2, &alpha);
	wwFrom(a, a, 2);
	wwCopy(t, a, n);
	// построить S-блок (с проверкой примитивности)
	s1[0] = 0;
	for (pos = 1; pos < 65536; ++pos)
	{
		wwTo(s1 + pos, 2, t);
		u16From(s1 + pos, s1 + pos, 2);
		ppMulMod(t, t, a, mod, n, stack);
		// ord a < 65535?
		if (wwEq(t, a, n) && pos < 65535)
			return FALSE;
	}
	// построить S-блок вторым способом
	exps16Create(s2, poly, alpha);
	if (!memEq(s1, s2, sizeof(s1)))
		return FALSE;
	// все нормально
	return TRUE;
}

/*
*******************************************************************************
Интеграция тестов
*******************************************************************************
*/

bool_t ppTest()
{
	return ppTestExps16();
}
