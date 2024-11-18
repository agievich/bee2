/*
*******************************************************************************
\file u64.h
\brief 64-bit words
\project bee2 [cryptographic library]
\created 2015.10.28
\version 2024.11.18
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

/*!
*******************************************************************************
\file u64.h
\brief 64-разрядные слова
*******************************************************************************
*/

#ifndef __BEE2_U64_H
#define __BEE2_U64_H

#include "bee2/defs.h"
#include "bee2/core/safe.h"

#ifndef U64_SUPPORT
	#error "Cannot proceed without u64"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*!
*******************************************************************************
\file u64.h

Реализованы операции над 64-разрядными словами и массивами таких слов.

\pre В функции передаются корректные буферы памяти.
*******************************************************************************
*/

#define U64_0 ((u64)0)
#define U64_1 ((u64)1)
#define U64_MAX ((u64)(U64_0 - U64_1))

/*!	\def u64RotHi
	\brief Циклический сдвиг слова u64 на d позиций в сторону старших разрядов
	\pre 0 < d < 64.
*/
#define u64RotHi(w, d)\
	((u64)((w) << (d) | (w) >> (64 - (d))))

/*!	\def u64RotLo
	\brief Циклический сдвиг слова u64 на d позиций в сторону младших разрядов
	\pre 0 < d < 64.
*/
#define u64RotLo(w, d)\
	((u64)((w) >> (d) | (w) << (64 - (d))))

/*!	\def u64Rev
	\brief Реверс октетов слова u64
*/
#define u64Rev_(w)\
	((u64)((w) << 56 | ((w) & 0xFF00) << 40 | ((w) & 0xFF0000) << 24 |\
	((w) & 0xFF000000) << 8 | ((w) >> 8 & 0xFF000000) |\
	((w) >> 24 & 0xFF0000) | ((w) >> 40 & 0xFF00) | (w) >> 56))

/*!	\brief Реверс октетов слова

	Выполняется реверс октетов u64-слова w.
	\return Слово с переставленными октетами.
*/
u64 u64Rev(
	register u64 w		/*!< [in] слово */
);

/*!	\brief Реверс октетов массива слов

	Выполняется реверс октетов массива [count]buf из u64-слов.
*/
void u64Rev2(
	u64 buf[],			/*!< [in,out] массив слов */
	size_t count		/*!< [in] число элементов */
);

/*!	\brief Реверс битов

	Выполняется реверс битов u64-слова w.
	\return Слово с переставленными битами.
*/
u64 u64Bitrev(
	register u64 w		/*!< [in] слово */
);

/*!	\brief Вес

	Определяется число ненулевых битов в u64-слове w.
	\return Число ненулевых битов.
*/
size_t u64Weight(
	register u64 w		/*!< [in] слово */
);

/*!	\brief Четность

	Определяется сумма по модулю 2 битов u64-слова w.
	\return Сумма битов.
*/
bool_t u64Parity(
	register u64 w		/*!< [in] слово */
);

/*!	\brief Число младших нулевых битов

	Определяется длина серии из нулевых младших битов u64-слова w.
	\return Длина серии.
	\remark CTZ == Count of Trailing Zeros
	\safe Имеется ускоренная нерегулярная редакция.
*/
size_t u64CTZ(
	register u64 w		/*!< [in] слово */
);

size_t SAFE(u64CTZ)(register u64 w);
size_t FAST(u64CTZ)(register u64 w);

/*!	\brief Число старших нулевых битов

	Определяется длина серии из нулевых старших битов машинного слова w.
	\return Длина серии.
	\remark CLZ == Count of Leading Zeros
	\safe Имеется ускоренная нерегулярная редакция.
*/
size_t u64CLZ(
	register u64 w		/*!< [in] слово */
);

size_t SAFE(u64CLZ)(register u64 w);
size_t FAST(u64CLZ)(register u64 w);

/*!	\brief Тасование битов

	Биты младшей половинки u64-слова w перемещаются в четные позиции,
	биты старшей половинки -- в нечетные.
	\return Слово с растасованными битами.
*/
u64 u64Shuffle(
	register u64 w		/*!< [in] слово */
);

/*!	\brief Обратное тасование битов

	Четные биты u64-слова w группируются в его младшей половинке,
	нечетные -- в старшей.
	\return Слово с группированными битами.
*/
u64 u64Deshuffle(
	register u64 w		/*!< [in] слово */
);

/*!	\brief Аддитивно-мультипликативное обращение

	Выполняется адиттивное и мультипликативное обращение
	u64-слова-как-числа w по модулю 2^64.
	\pre w -- нечетное.
	\return - w^{-1} \mod 2^64.
	\remark Вычисляемое слово используется в редукции Монтгомери.
*/
u64 u64NegInv(
	register u64 w		/*!< [in] слово */
);


/*!	\brief Загрузка из буфера памяти

	Буфер [count]src преобразуется в массив [(count + 7) / 8]dest слов u64.
*/
void u64From(
	u64 dest[],			/*!< [out] приемник */
	const void* src,	/*!< [in] источник */
	size_t count		/*!< [in] число октетов */
);

/*!	\brief Выгрузка в буфер памяти

	Буфер [count]dest формируется по массиву [(count + 7) / 8]src слов u64.
*/
void u64To(
	void* dest,			/*!< [out] приемник */
	size_t count,		/*!< [in] число октетов */
	const u64 src[]		/*!< [in] источник */
);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __BEE2_U64_H */
