/*
*******************************************************************************
\file str.h
\brief Strings
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2013.02.04
\version 2016.04.28
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

/*!
*******************************************************************************
\file str.h
\brief Строки
*******************************************************************************
*/

#ifndef __BEE2_STR_H
#define __BEE2_STR_H

#include <string.h>
#include "bee2/defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/*!
*******************************************************************************
\file str.h

Реализованы или переопределены манипуляции над строками. Строка
представляет собой последовательность символов-октетов, которая
заканчивается нулевым октетом.

\pre Во все функции, кроме strIsValid(), передаются корректные строки.
*******************************************************************************
*/

/*!	Определяется длина строки (число символов до завершающего нулевого).
*/
#define strLen(str) strlen(str)

/*!	Возвращается strLen(str), если strLen(str) < count, или count в противном
	случае.
*/
#define strLen2(str, count) strnlen(str, count)

/*!	\brief Корректная строка?

	Проверяется, что строка str корректна.
	\return Признак успеха.
*/
bool_t strIsValid(
	const char* str		/*!< [in] строка */
);

/*!	\brief Копирование строки

	Строка src копируется в dest.
	\pre По адресу dest зарезервировано strLen(src) + 1 октетов.
	\pre Буферы src и dest не пересекаются.
*/
void strCopy(
	char* dest,			/*!< [out] строка-назначение */
	const char* src		/*!< [in] строка-источник */
);

/*!	\brief Сравнение строк
	
	Строки str1 и str2 сравниваются лексикографически.
	\return 1, если str1 > str2, или -1, если str1 < str2,
	или 0, если str1 == str2.
	\safe Функция нерегулярна.
*/
int strCmp(
	const char* str1,	/*!< [in] первая строка */
	const char* str2	/*!< [in] вторая строка */
);

/*!	Проверяется совпадение строк str1 и str2.
	\return Признак совпадения.
	\safe Функция нерегулярна.
*/
#define strEq(str1, str2) (strCmp(str1, str2) == 0)

/*
*******************************************************************************
Дополнительные функции
*******************************************************************************
*/

/*!	\brief Буквенно-цифовая?

	Проверяется, что строка str состоит только из символов-цифр '0'-'9'
	и символов букв 'A'-'Z', 'a'-'z'.
	\return Признак успеха.
	\safe Функция нерегулярна.
*/
bool_t strIsAlphanumeric(
	const char* str		/*!< [in] строка */
);

/*!	\brief Начинается?

	Проверяется, что строка str начинается с префикca prefix.
	\return Признак успеха.
	\safe Функция нерегулярна.
*/
bool_t strStartsWith(
	const char* str,	/*!< [in] строка */
	const char* prefix	/*!< [in] префикс */
);

/*!	\brief Заканчивается?

	Проверяется, что строка str заканчивается суффиксом suffix.
	\return Признак успеха.
	\safe Функция нерегулярна.
*/
bool_t strEndsWith(
	const char* str,	/*!< [in] строка */
	const char* suffix	/*!< [in] суффикс */
);

/*!	\brief Разворот строки

	Символы строки str переписываются в обратном порядке.
*/
void strRev(
	char* str		/*!< [in] строка */
);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __BEE2_STR_H */
