/*
*******************************************************************************
\file zz_lcl.h
\brief Multiple-precision unsigned integers: local definitions
\project bee2 [cryptographic library]
\created 2016.07.01
\version 2025.03.19
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#ifndef __ZZ_LCL_H
#define __ZZ_LCL_H

#include "bee2/defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
*******************************************************************************
Замечания по языку C

В языке С все операции с беззнаковыми целыми, которые короче unsigned int,
выполняются после их предварительного приведения к unsigned int
[так назваемое integer promotions, см. C99, п. 6.3.1.4].

Сказанное учтено в реализации. Пусть, например, требуется проверить, что для
слов a, b типа word выполнено условие:
	a * b + 1 \equiv 0 (\mod 2^B_PER_W).
Можно подумать, что можно организовать проверку следующим образом:
\code
	ASSERT(a * b + 1 == 0);
\endcode
Данная проверка будет давать неверный результат при
sizeof(word) < sizeof(unsigned int). Правильный способ:
\code
	ASSERT((word)(a * b + 1) == 0);
\endcode

\warning При тестировании арифметики длина слова искусственно понижалась
до 16 битов. При этом при включении определеннных опций компилятор GCC
выдавал ошибки предупреждения при сравнении word с ~word:
comparison of promoted ~unsigned with unsigned [-Werror=sign-compare].
*******************************************************************************
*/

/*
*******************************************************************************
Примитивы регуляризации

Маскируют операцию сложения / вычитания: каждое слово a поразрядно умножается 
на mask и после этого добавляется / вычитается из b. При mask == 0 операция 
выполняется с нулевым a (т.е. не выполняется), при mask == 0 -- 
с первоначальным a.

\remark Реализованы в zz_etc.c.
*******************************************************************************
*/

void zzAddAndW(word b[], const word a[], size_t n, register word w);
word zzSubAndW(word b[], const word a[], size_t n, register word w);

/*
*******************************************************************************
Макросы умножения слов (1x1)

zzMul11:
	dword c;
	word a, b;
	c <- a, c <- c * b;

zzMul11Lo:
	word a, b;
	return (word)(a * b);
*******************************************************************************
*/

#define zzMul11(c, a, b)\
	(c) = (word)(a), (c) *= (word)(b)

#define zzMul11Lo(c, a, b)\
	(c) = (word)(a) * (word)(b)

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __ZZ_LCL_H */
