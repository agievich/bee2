/*
*******************************************************************************
\file u64.h
\brief 64-bit words
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
\file u64.h
\brief 64-разрядные слова
*******************************************************************************
*/

#ifndef __BEE2_U64_H
#define __BEE2_U64_H

#include "bee2/defs.h"

#ifndef U64_SUPPORT
	#error "Can't proceed without u64"
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
	((u64)((w) << d | (w) >> (64 - d)))

/*!	\def u64RotLo
	\brief Циклический сдвиг слова u32 на d позиций в сторону младших разрядов
	\pre 0 < d < 64.
*/
#define u64RotLo(w, d)\
	((u64)((w) >> d | (w) << (64 - d)))

/*!	\def u64Rev
	\brief Реверс октетов слова u64
*/
#define u64Rev(w)\
	((u64)((w) << 56 | ((w) & 0xFF00) << 40 | ((w) & 0xFF0000) << 24 |\
	((w) & 0xFF000000) << 8 | ((w) >> 8 & 0xFF000000) |\
	((w) >> 24 & 0xFF0000) | ((w) >> 40 & 0xFF00) | (w) >> 56))

/*!	\brief Реверс октетов

	Выполняется реверс октетов слов u64 массива [count]buf.
*/
void u64Rev2(
	u64 buf[],			/*!< [in/out] приемник */
	size_t count		/*!< [in] число элементов */
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
