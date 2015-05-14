﻿/*
*******************************************************************************
\file util.h
\brief Utilities
\project bee2 [cryptographic library]
\author (С) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2012.07.16
\version 2015.04.25
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

/*!
*******************************************************************************
\file util.h
\brief Вспомогательные функции и макросы
*******************************************************************************
*/

#ifndef __BEE2_UTIL_H
#define __BEE2_UTIL_H

#include <assert.h>
#include "bee2/defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
*******************************************************************************
Вспомогательные макросы
*******************************************************************************
*/

/*!	\brief Число элементов в массиве a */
#define COUNT_OF(a) (sizeof(a) / sizeof(*(a)))

/*!	\brief Число элементов в массиве a
	\pre Массив непустой.
*/
#define LAST_OF(a) ((a)[COUNT_OF(a) - 1])

/*!	\brief Предполагается выполнение условия
	
	Вычислить a (при отладке) и завершить работу, если a == 0 (при отладке). 
*/
#define ASSERT(a) assert(a)

/*!	\brief Проверяется выполнение условия

	Вычислить a (всегда) и завершить работу, если a == 0 (при отладке). 
*/
#define VERIFY(a) {if (!(a)) ASSERT(0);}

/*!	\brief Ожидается выполнение условия

	Ожидать выполнения a, ничего не предпринимая. 
	\remark Макрос EXPECT указывает на условия, которые ожидаются, 
	но все таки могут быть нарушены. Примеры условий: простота числа, 
	неприводимость многочлена, корректность эллиптической кривой. 
	\remark Ожидаемые условия могут быть труднопроверяемыми. Поэтому
	программы не могут полагаться на безусловное выполнение этих условий 
	и должны устойчиво работать даже при их нарушении. Например, 
	программа сложения точек эллиптической кривой над простым полем GF(p) 
	должна завершать сложение даже если p -- составное.
	\remark Следует четко разграничивать ASSERT (как правило, самоконтроль 
	программиста) и EXPECT (как правило, контроль входных данных).
	\remark Некоторые ожидаемые условия могут частично проверяться. 
	Например, EXPECT(p -- нечетное простое) может быть поддержано проверкой 
	ASSERT(p -- нечетное). Безусловные проверки, поддерживающие ожидаемые 
	условия, должны по возможности документироваться.
*/
#define EXPECT(a) 

#define MIN2(a, b) ((a) < (b) ? (a) : (b))
#define MAX2(a, b) ((a) > (b) ? (a) : (b))
#define MIN3(a, b, c) MIN2(a, MIN2(b, c))
#define MAX3(a, b, c) MAX2(a, MAX2(b, c))
#define MIN4(a, b, c, d) MIN2(MIN2(a, b), MIN2(c, d))
#define MAX4(a, b, c, d) MAX2(MAX2(a, b), MAX2(c, d))

/*!	\brief Поменять местами значения переменных a и b
	\pre Переменные имеют один тип.
	\pre Переменные являются целочисленными, допускающими операцию ^.
	\pre Переменные a и b различны.
	\remark Если a и b --- это одна и та же переменная, то она будет
	обнулена. Безопасный код:
	\code
		a != b ? SWAP(a, b) : 0;
	\endcode

*/
#define SWAP(a, b)\
	(a) ^= (b), (b) ^= (a), (a) ^= (b)

/*!	\brief Поменять местами значения указателей a и b
	\pre Переменные a и b различны.
*/
#define SWAP_PTR(a, b)\
	*((octet**)&(a)) = (octet*)(a) - ((octet*)(b) - (octet*)0),\
	*((octet**)&(b)) = (octet*)(b) + ((octet*)(a) - (octet*)0),\
	*((octet**)&(a)) = (octet*)(b) - ((octet*)(a) - (octet*)0)

/*
*******************************************************************************
Версия
*******************************************************************************
*/

/*!	\brief Версия 

	Определяется версия библиотеки bee2.
	\return Версия в виде строки major.minor.patch.
*/
const char* utilVersion();

/*
*******************************************************************************
Минимум / максимум
*******************************************************************************
*/

/*!	\brief Минимум

	Определяется минимум из n чисел типа size_t, переданных как дополнительные
	параметры.
	\pre n > 0.
	\return Минимум.
*/
size_t utilMin(
	size_t n,			/*!< [in] количество чисел */
	...					/*!< [in] числа */
);

/*!	\brief Максимум

	Определяется максимум из n чисел типа size_t, переданных как дополнительные
	параметры.
	\pre n > 0.
	\return Максимум.
*/
size_t utilMax(
	size_t n,			/*!< [in] количество чисел */
	...					/*!< [in] числа */
);

/*
*******************************************************************************
Контрольные суммы
*******************************************************************************
*/

/*!	\brief Контрольная сумма CRC32

	Определяется контрольная сумма буфера [count]buf. При расчете контрольной 
	суммы используется состояние state. Контрольная сумма рассчитывается 
	по алгоритму CRC32 из стандарта ISO 3309.
	\remark Контрольную сумму большого фрагмента данных можно определять
	последовательно путем многократных обращений к функции.
	При первом обращении состояние state должно быть нулевым.
	\return Контрольная сумма.
*/
uint32 utilCRC32(
	const void* buf,	/*!< [in] буфер */
	size_t count,		/*!< [in] число октетов */
	uint32 state		/*!< [in/out] состояние */
);

/*!	\brief Контрольная сумма FNV32

	Определяется контрольная сумма буфера [count]buf. При расчете контрольной 
	суммы используется состояние state. Контрольная сумма рассчитывается по 
	алгоритму FNV-1a с размерностью 32 
	(http://isthe.com/chongo/tech/comp/fnv/).
	\remark Контрольную сумму большого фрагмента данных можно определять
	последовательно путем многократных обращений к функции.
	При первом обращении state должно равняться 2166136261 = 0x811C9DC5.
	\return Контрольная сумма.
*/
uint32 utilFNV32(
	const void* buf,	/*!< [in] буфер */
	size_t count,		/*!< [in] число октетов */
	uint32 state		/*!< [in/out] состояние */
);

/*!	\brief 32-разрядный нонс

	По уникальным системным данным (дата, время) строится 32-разрядный нонс.
	\return Нонс.
	\remark Нонс (калька с англ. nonce) --- "слабо" повторяющееся значение,
	которое используется в криптографических протоколах. С помощью нонсов можно
	инициализовать генераторы псевдослучайных чисел (см. prngCOMBOStart()).
*/
uint32 utilNonce32();

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __BEE2_UTIL_H */
