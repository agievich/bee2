/*
*******************************************************************************
\file zz_lcl.h
\brief Multiple-precision unsigned integers: local definitions
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2016.07.01
\version 2019.06.27
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
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
Макросы умножения слов

_MUL:
	dword c;
	word a, b;
	c <- a, c <- c * b;

_MUL_LO:
	word a, b;
	return (word)(a * b);

\todo _MUL_HI.
*******************************************************************************
*/

#if defined(_MSC_VER) && (B_PER_W == 32)
	#include <intrin.h>
	#define _MUL(c, a, b)\
		(c) = __emulu((word)(a), (word)(b))
#else
	#define _MUL(c, a, b)\
		(c) = (word)(a), (c) *= (word)(b)
#endif 

#define _MUL_LO(c, a, b)\
	(c) = (word)(a) * (word)(b);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __ZZ_LCL_H */
