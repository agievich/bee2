/*
*******************************************************************************
\file u32.h
\brief 32-bit words
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2015.10.28
\version 2015.11.09
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

/*!
*******************************************************************************
\file u32.h
\brief 32-разрядные слова
*******************************************************************************
*/

#ifndef __BEE2_U32_H
#define __BEE2_U32_H

#include "bee2/defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/*!
*******************************************************************************
\file u32.h

Реализованы операции над 32-разрядными словами и массивами таких слов.

\pre В функции передаются корректные буферы памяти.
*******************************************************************************
*/

#define U32_0 ((u32)0)
#define U32_1 ((u32)1)
#define U32_MAX ((u32)(U32_0 - U32_1))

/*!	\def u32RotHi
	\brief Циклический сдвиг слова u32 на d позиций в сторону старших разрядов
	\pre 0 < d < 32.
*/
#define u32RotHi(w, d)\
	((u32)((w) << d | (w) >> (32 - d)))

/*!	\def u32RotLo
	\brief Циклический сдвиг слова u32 на d позиций в сторону младших разрядов
	\pre 0 < d < 32.
*/
#define u32RotLo(w, d)\
	((u32)((w) >> d | (w) << (32 - d)))

/*!	\def u32Rev
	\brief Реверс октетов слова u32
*/
#define u32Rev(w)\
	((u32)((w) << 24 | ((w) & 0xFF00) << 8 | ((w) >> 8 & 0xFF00) | (w) >> 24))

/*!	\brief Реверс октетов

	Выполняется реверс октетов слов u32 массива [count]buf.
*/
void u32Rev2(
	u32 buf[],			/*!< [in/out] приемник */
	size_t count		/*!< [in] число элементов */
);

/*!	\brief Загрузка из буфера памяти

	Буфер [count]src преобразуется в массив [(count + 3) / 4]dest слов u32.
*/
void u32From(
	u32 dest[],			/*!< [out] приемник */
	const void* src,	/*!< [in] источник */
	size_t count		/*!< [in] число октетов */
);

/*!	\brief Выгрузка в буфер памяти

	Буфер [count]dest формируется по массиву [(count + 3) / 4]src слов u32.
*/
void u32To(
	void* dest,			/*!< [out] приемник */
	size_t count,		/*!< [in] число октетов */
	const u32 src[]		/*!< [in] источник */
);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __BEE2_U32_H */
