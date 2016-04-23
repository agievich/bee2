/*
*******************************************************************************
\file u16.h
\brief 16-bit words
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
\file u16.h
\brief 16-разрядные слова
*******************************************************************************
*/

#ifndef __BEE2_U16_H
#define __BEE2_U16_H

#include "bee2/defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/*!
*******************************************************************************
\file u16.h

Реализованы операции над 16-разрядными словами и массивами таких слов.

\pre В функции передаются корректные буферы памяти.
*******************************************************************************
*/

#define U16_0 ((u16)0)
#define U16_1 ((u16)1)
#define U16_MAX ((u16)(U16_0 - U16_1))

/*!	\def u16RotHi
	\brief Циклический сдвиг слова u16 на d позиций в сторону старших разрядов
	\pre 0 < d < 16.
*/
#define u16RotHi(w, d)\
	((u16)((w) << d | (w) >> (16 - d)))

/*!	\def u16RotLo
	\brief Циклический сдвиг слова u16 на d позиций в сторону младших разрядов
	\pre 0 < d < 16.
*/
#define u16RotLo(w, d)\
	((u16)((w) >> d | (w) << (16 - d)))

/*!	\def u16Rev
	\brief Реверс октетов слова u16
*/
#define u16Rev(w)\
	((u16)((w) << 8 | (w) >> 8))

/*!	\brief Реверс октетов

	Выполняется реверс октетов слов u16 массива [count]buf.
*/
void u16Rev2(
	u16 buf[],			/*!< [in/out] приемник */
	size_t count		/*!< [in] число элементов */
);

/*!	\brief Загрузка из буфера памяти

	Буфер [count]src преобразуется в массив [(count + 1) / 2]dest слов u16.
*/
void u16From(
	u16 dest[],			/*!< [out] приемник */
	const void* src,	/*!< [in] источник */
	size_t count		/*!< [in] число октетов */
);

/*!	\brief Выгрузка в буфер памяти

	Буфер [count]dest формируется по массиву [(count + 1) / 2]src слов u16.
*/
void u16To(
	void* dest,			/*!< [out] приемник */
	size_t count,		/*!< [in] число октетов */
	const u16 src[]		/*!< [in] источник */
);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __BEE2_U16_H */
