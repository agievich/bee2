/*
*******************************************************************************
\file bash.h
\brief STB 34.101.77 (bash): hashing algorithms
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2014.07.15
\version 2015.12.01
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#ifndef __BEE2_BASH_H
#define __BEE2_BASH_H

#ifdef __cplusplus
extern "C" {
#endif

#include "bee2/defs.h"

/*!
*******************************************************************************
\file bash.h

Экспериментальные алгоритмы СТБ 34.101.bash

СТБ 34.101.bash определяет семейство алгоритмов хэширования. Конкретный 
алгоритм bashNNN возвращает NNN-битовые хэш-значения, где NNN кратно 32 
и не превосходит 512. Параметр NNN регулируется уровнем стойкости l = NNN / 2.

Хэширование выполняется по схеме:
--	определить длину хэш-состояния с помощью функции bash_keep();
--	подготовить буфер памяти для состояния;
--	инициализировать состояние с помощью bashStart(). Передать в эту функцию
	требуемый уровень стойкости;
--	обработать фрагменты хэшируемых данных с помощью bashStepH();
--	определить хэш-значение с помощью bashStepG() или проверить его с помощью
	bashStepV().

Функции bashStart(), bashStepH(), bashStepG(), bashStepV() используют 
общее хэш-состояние и образуют связку. Функции связки являются 
низкоуровневыми --- в них не проверяются входные данные. 
Связка покрывается высокоуровневой функцией bashHash().

Стандартные уровни l = 128, 192, 256 поддержаны макросами bashNNNXXX.

Алгоритмы хэширования строятся на основе шаговой функции bash-f, 
реализованной в bashF(). Шаговая функция имеет самостоятельное значение 
и может использоваться не только для организации хэширования.

\expect Общее состояние связки функций не изменяется вне этих функций.

\pre Все входные указатели низкоуровневых функций действительны.

\pre Если не оговорено противное, то входные буферы функций связки 
не пересекаются.
*******************************************************************************
*/

/*!	\brief Шаговая функция

	Буфер block преобразуется с помощью шаговой функции bash-f.
	\pre Буфер block корректен.
*/
void bashF(
	octet block[192]	/*!< [in/out] прообраз/образ */
);

/*
*******************************************************************************
bash
*******************************************************************************
*/

/*!	\brief Длина состояния

	Возвращается длина состояния (в октетах) алгоритмов хэширования bash.
	\return Длина состояния.
*/
size_t bash_keep();

/*!	\brief Инициализация

	В state формируются структуры данных, необходимые для хэширования 
	с помощью алгоритмов bash уровня l.
	\pre l > 0 && l % 16 == 0 && l <= 256.
	\pre По адресу state зарезервировано bash_keep() октетов.
*/
void bashStart(
	void* state,		/*!< [out] состояние */
	size_t l			/*!< [in] уровень стойкости */
);	

/*!	\brief Хэширование фрагмента данных

	Текущее хэш-значение, размещенное в state, пересчитывается по алгоритму 
	bash с учетом нового фрагмента данных [count]buf.
	\expect bashStart() < bashStepH()*.
*/
void bashStepH(
	const void* buf,	/*!< [in] данные */
	size_t count,		/*!< [in] число октетов данных */
	void* state			/*!< [in/out] состояние */
);

/*!	\brief Определение хэш-значения

	Определяются первые октеты [hash_len]hash окончательного хэш-значения 
	всех данных, обработанных до этого функцией bashStepH().
	\pre hash_len <= l / 4, где l -- уровень стойкости, ранее переданный 
	в bashStart().
	\expect (bashStepH()* < bashStepG())*. 
	\remark Если продолжение хэширования не предполагается, то буферы 
	hash и state могут пересекаться.
*/
void bashStepG(
	octet hash[],		/*!< [out] хэш-значение */
	size_t hash_len,	/*!< [in] длина hash */
	void* state			/*!< [in/out] состояние */
);

/*!	\brief Проверка хэш-значения

	Прооверяется, что первые октеты окончательного хэш-значения 
	всех данных, обработанных до этого функцией bashStepH(),
	совпадают с [hash_len]hash.
	\pre hash_len <= l / 4, где l -- уровень стойкости, ранее переданный 
	в bashStart().
	\expect (bashStepH()* < bashStepV())*.
	\return Признак успеха.
*/
bool_t bashStepV(
	const octet hash[],	/*!< [in] контрольное хэш-значение */
	size_t hash_len,	/*!< [in] длина hash */
	void* state			/*!< [in/out] состояние */
);

/*!	\brief Хэширование

	С помощью алгоритма bash уровня стойкости l определяется хэш-значение 
	[l / 4]hash буфера [count]src.
	\expect{ERR_BAD_PARAM} l > 0 && l % 16 == 0 && l <= 256.
	\expect{ERR_BAD_INPUT} Буферы hash, src корректны.
	\return ERR_OK, если хэширование завершено успешно, и код ошибки
	в противном случае.
	\remark Буферы могут пересекаться.
*/
err_t bashHash(
	octet hash[],		/*!< [out] хэш-значение */
	size_t l,			/*!< [out] уровень стойкости */
	const void* src,	/*!< [in] данные */
	size_t count		/*!< [in] число октетов данных */
);

/*
*******************************************************************************
bash256
*******************************************************************************
*/

#define bash256_keep bash_keep
#define bash256Start(state) bashStart(state, 128)
#define bash256StepH(buf, count, state) bashStepH(buf, count, state)
#define bash256StepG(hash, state) bashStepG(hash, 32, state)
#define bash256StepG2(hash, hash_len, state) bashStepG(hash, hash_len, state)
#define bash256StepV(hash, state) bashStepV(hash, 32, state)
#define bash256StepV2(hash, hash_len, state) bashStepV2(hash, hash_len, state)
#define bash256Hash(hash, src, count) bashHash(hash, 128, src, count)

/*
*******************************************************************************
bash384
*******************************************************************************
*/

#define bash384_keep bash_keep
#define bash384Start(state) bashStart(state, 192)
#define bash384StepH(buf, count, state) bashStepH(buf, count, state)
#define bash384StepG(hash, state) bashStepG(hash, 48, state)
#define bash384StepG2(hash, hash_len, state) bashStepG(hash, hash_len, state)
#define bash384StepV(hash, state) bashStepV(hash, 48, state)
#define bash384StepV2(hash, hash_len, state) bashStepV2(hash, hash_len, state)
#define bash384Hash(hash, src, count) bashHash(hash, 192, src, count)

/*
*******************************************************************************
bash512
*******************************************************************************
*/

#define bash512_keep bash_keep
#define bash512Start(state) bashStart(state, 256)
#define bash512StepH(buf, count, state) bashStepH(buf, count, state)
#define bash512StepG(hash, state) bashStepG(hash, 64, state)
#define bash512StepG2(hash, hash_len, state) bashStepG(hash, hash_len, state)
#define bash512StepV(hash, state) bashStepV(hash, 64, state)
#define bash512StepV2(hash, hash_len, state) bashStepV2(hash, hash_len, state)
#define bash512Hash(hash, src, count) bashHash(hash, 256, src, count)

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __BEE2_BASH_H */
