/*
*******************************************************************************
\file pri_test.c
\brief Tests for prime numbers
\project bee2/test
\created 2014.07.07
\version 2023.03.30
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <bee2/core/mem.h>
#include <bee2/core/prng.h>
#include <bee2/core/util.h>
#include <bee2/core/word.h>
#include <bee2/math/pri.h>
#include <bee2/math/ww.h>

/*
*******************************************************************************
Тестирование
*******************************************************************************
*/

bool_t priTest()
{
	size_t i;
	word a[W_OF_B(521)];
	word p[W_OF_B(289)];
	word mods[1024];
	octet combo_state[32];
	octet stack[4096];
	// инициализировать генератор COMBO
	if (sizeof(combo_state) < prngCOMBO_keep())
		return FALSE;
	prngCOMBOStart(combo_state, utilNonce32());
	// проверить простоту элементов факторной базы
	if (sizeof(stack) < priIsPrimeW_deep() ||
		sizeof(stack) < priIsPrime_deep(1))
		return FALSE;
	for (i = 0; i < priBaseSize(); ++i)
	{
		a[0] = priBasePrime(i);
		if (!priIsPrimeW(a[0], stack) ||
			!priIsPrime(a, 1, stack))
			return FALSE;
	}
	// проверить простоту числа Ферма 2^{2^5} + 1
	wwSetZero(a, W_OF_B(32));
	wwSetBit(a, 32, 1);
	zzAddW2(a, W_OF_B(32), 1);
	if (sizeof(stack) < priIsPrime_deep(W_OF_B(32)) ||
		priIsPrime(a, W_OF_B(32), stack) != FALSE)
		return FALSE;
	// проверить простоту 13-го числа Мерсенна 2^521 - 1
	wwSetZero(a, W_OF_B(521));
	wwSetBit(a, 521, 1);
	zzSubW2(a, W_OF_B(521), 1);
	if (sizeof(stack) < priRMTest_deep(W_OF_B(521)) ||
		priRMTest(a, W_OF_B(521), 20, stack) != TRUE)
		return FALSE;
	// остатки по простым из факторной базы
	i = MIN2(COUNT_OF(mods), priBaseSize());
	priBaseMod(mods, a, W_OF_B(521), i);
	while (i--)
		if (mods[i] != zzModW(a, W_OF_B(521), priBasePrime(i)) ||
			priBasePrime(i) < WORD_BIT_HALF &&
				mods[i] != zzModW2(a, W_OF_B(521), priBasePrime(i)))
			return FALSE;
	// найти 2-битовое нечетное простое число
	a[0] = 2;
	if (sizeof(stack) < priNextPrime_deep(1, 0) ||
		!priNextPrime(a, a, 1, SIZE_MAX, 0, B_PER_IMPOSSIBLE, stack) ||
		a[0] != 3)
		return FALSE;
	// найти 10-битовое нечетное простое число
	a[0] = 512;
	if (sizeof(stack) < priNextPrime_deep(1, 0) ||
		!priNextPrime(a, a, 1, SIZE_MAX, 0, B_PER_IMPOSSIBLE, stack) ||
		a[0] != 521)
		return FALSE;
	// найти следующее 10-битовое нечетное простое число
	if (sizeof(stack) < priNextPrimeW_deep() ||
		!priNextPrimeW(a, ++a[0], stack) ||
		a[0] != 523)
		return FALSE;
	// убедиться, что 2^256 - 400 не является гладким
	memSet(a, 0xFF, O_OF_B(256));
	zzSubW2(a, W_OF_B(256), 400);
	if (sizeof(stack) < priIsSmooth_deep(W_OF_B(256)) ||
		priIsSmooth(a, W_OF_B(256), priBaseSize(), stack))
		return FALSE;
	// найти простое число 2^256 - 357
	if (priBaseSize() < 10 ||
		sizeof(stack) < priNextPrime_deep(W_OF_B(256), 10) ||
		!priNextPrime(a, a, W_OF_B(256), 50, 10, B_PER_IMPOSSIBLE, stack) ||
		a[0] != WORD_MAX - 356 ||
		!wwIsRepW(a + 1, W_OF_B(256) - 1, WORD_MAX))
		return FALSE;
	// найти простое число 2^256 - 189
	zzAddW2(a, W_OF_B(256), 1);
	if (!priNextPrime(a, a, W_OF_B(256), 200, 10, B_PER_IMPOSSIBLE, stack) ||
		a[0] != WORD_MAX - 188 ||
		!wwIsRepW(a + 1, W_OF_B(256) - 1, WORD_MAX))
		return FALSE;
	// построить 289-битовое простое вида 2r(2^256 - 189) + 1
	if (priBaseSize() < 10 ||
		sizeof(stack) < priExtendPrime_deep(289, W_OF_B(256), 0) ||
		!priExtendPrime(p, 289, a, W_OF_B(256), SIZE_MAX, 0, prngCOMBOStepR, 
			combo_state, stack) ||
		sizeof(stack) < priIsPrime_deep(W_OF_B(256)) ||
		!priIsPrime(p, W_OF_B(289), stack))
		return FALSE;
	// удостовериться, что в интервале (2^256 - 188, 2^256 - 1) нет простых
	zzAddW2(a, W_OF_B(256), 1);
	if (sizeof(stack) < priNextPrime_deep(W_OF_B(256), 200) ||
		priNextPrime(a, a, W_OF_B(256), 200, 0, B_PER_IMPOSSIBLE, stack))
		return FALSE;
	// проверить, что 2^256 - 29237 является простым Жермен
	memSet(a, 0xFF, O_OF_B(256));
	a[0] = WORD_MAX - 29236;
	if (sizeof(stack) < priIsSieved_deep(10) ||
		sizeof(stack) < priIsSGPrime_deep(W_OF_B(256)) ||
		!priIsSieved(a, W_OF_B(256), 10, stack) ||
		!priIsSGPrime(a, W_OF_B(256), stack) != 0)
		return FALSE;
	// построить простое 23 = 2 * 11 + 1 (за одну попытку)
	a[0] = 11;
	if (sizeof(stack) < priExtendPrime_deep(5, 1, 10) ||
		!priExtendPrime(p, 5, a, 1, SIZE_MAX, 0,
			prngCOMBOStepR, combo_state, stack) ||
		p[0] != 23)
		return FALSE;
	// все нормально
	return TRUE;
}
