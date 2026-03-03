/*
*******************************************************************************
\file bign_lcl.h
\brief STB 34.101.45 (bign): local declarations
\project bee2 [cryptographic library]
\created 2014.04.03
\version 2026.03.03
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#ifndef __BEE2_BIGN_LCL_H
#define __BEE2_BIGN_LCL_H

#include "bee2/crypto/bign.h"
#include "bee2/math/ec.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
*******************************************************************************
В основных функциях, объявленных в bign.h, параметры эллиптической кривой
передаются через структуру params типа bign_params. По параметрам params
строится кривая ec, именно она используется в дальнейших вычислениях.
Эти вычисления оформлены в виде EC-функций, которые сопровождают основные.
EC-функция повторяет интерфейс основной, только на ее вход вместо params
передается ec. Имя EC-функции получается из имени основной добавлением
суффикса "Ec".

Общая схема построения основной функции bignXXX():
1. Проверить params с помощью функции bignParamsCheck(). 
2. По params построить ec с помощью функции bignEcCreate().
3. Выполнить Ec-функцию bignXXXEc(), передавая ec ей на вход.
4. Завершить работу с ec c помощью функции bignEcClose().
5. Возвратить результаты работы bignXXXEc().

EC-функции имеют самостоятельное значение. Их можно использовать напрямую
в тех случаях, когда кривая ec уже создана к моменту вызова.

\remark EC-функции могут работать на уровнях стойкости l, отличных от трех
стандартных (l == 128 || l == 192 || l == 256). Для этого необходимо
(но не обязательно достаточно), чтобы уровень l был кратен длине машинного
слова в битах:
	l % B_PER_W == 0.
Последнее условие проверяется в функции bignParamsCheck2(), которая является
ослабленной редакцией bignParamsCheck().
*******************************************************************************
*/

/*!	\brief Предварительная проверка параметров

	Проводится предварительная проверка параметров params, обеспечивающая
	работоспобность высокоуровневых функций. Конкретнее, проверяется выполнение
	следующих ограничений на поля params:
	- указатель params корректен;
	- l == 128 || l == 192 || l == 256;
	- l % B_PER_W == 0;
	- p и q -- 2l-битовые нечетные числа;
	- p[0] % 4 == 3;
	- a != 0 и b != 0;
	- неиспользуемые октеты p, a, b, yG обнулены.
	\return ERR_OK в случае успеха и код ошибки в противном	случае.
	\remark Условие l % B_PER_W == 0 является ограничением реализации
	(не обременительным). При нарушении условия возвращается код ошибки
	ERR_NOT_IMPLEMENTED.
*/
err_t bignParamsCheck(
	const bign_params* params	/*!< [in] долговременные параметры */
);

/*!	\brief Ослабленная предварительная проверка параметров

	Проводится ослабленная предварительная проверка параметров params.
	Проверяются условия функции bignParamsCheck() с заменой условий
	- l == 128 || l == 192 || l == 256;
	- l % B_PER_W == 0;
	на условие
	- (2 * l) % B_PER_W == 0.
	\return ERR_OK в случае успеха и код ошибки в противном	случае.
*/
err_t bignParamsCheck2(
	const bign_params* params	/*!< [in] долговременные параметры */
);

/*!	\brief Создание эллиптической кривой

	По долговременным параметрам params создается эллиптическая кривая.
	Описание кривой возвращается по адресу *pec.
	\pre Указатель pec корректен.
	\pre bignParamsCheck2(params) == ERR_OK.
	\return ERR_OK, если кривая успешно создана, и код ошибки в противном случае.
	\remark Проводится минимальная проверка параметров, обеспечивающая
	работоспособность высокоуровневых функций.
*/
err_t bignEcCreate(
	ec_o** pec,					/*!< [out] эллиптическая кривая */
	const bign_params* params	/*!< [in] долговременные параметры */
);

/*!	\brief Закрытие эллиптической кривой

	Эллиптическая кривая ec закрывается.
*/
void bignEcClose(
	ec_o* ec					/*!< [in] эллиптическая кривая */
);

/*
*******************************************************************************
Кратная точка

Регулярные функции вычисления кратной точки.
*******************************************************************************
*/

/*!	\brief Кратная точка на кривой Bign

	Определяется аффинная точка [2 * ec->f->n]b эллиптической кривой ec, которая
	является [ec->f->n]d-кратной аффинной точки [2 * ec->f->n]a:
	\code
		b <- d a.
	\endcode
	\pre Описание ec работоспособно.
	\pre d < ec->order.
	\expect Кривая ec удовлетворяет соглашениям Bign.
	\expect В ec используются якобиевы координаты.
	\expect Точка a лежит на ec.
	\return TRUE, если кратная точка отличается от O, и FALSE в противном
	случае.
	\deep{stack} bignMulA_deep(ec->f->n, ec->d, ec->deep).
*/
bool_t bignMulA(
	word b[],			/*!< [out] кратная точка */
	const word a[],		/*!< [in] базовая точка */
	const ec_o* ec,		/*!< [in] описание кривой */
	const word d[],		/*!< [in] кратность */
	void* stack			/*!< [in] вспомогательная память */
);

size_t bignMulA_deep(size_t n, size_t ec_d, size_t ec_deep);

/*!	\brief Кратная точка на кривой Bign для скаляра специального вида

	Определяется аффинная точка [2 * ec->f->n]b эллиптической кривой ec,
	которая является [m]d-кратной аффинной точки [2 * ec->f->n]a:
	\code
		b <- d a.
	\endcode
	Скаляр d имеет специальный вид:
	- 0 < wwBitSize(d, m);
	- wwBitSize(d, m) < wwBitSize(ec->order, ec->f->n + 1);
	- wwBitSize(d, m) - 1 делится на 8.
	.
	\pre Описание ec работоспособно.
	\pre Соблюдаются ограничения на d.
	\expect Кривая ec удовлетворяет соглашениям Bign.
	\expect В ec используются якобиевы координаты.
	\expect Точка a лежит на ec.
	\return TRUE, если кратная точка отличается от O, и FALSE в противном
	случае.
	\deep{stack} bignMulA2_deep(ec->f->n, ec->d, ec->deep).
*/
bool_t bignMulA2(
	word b[],			/*!< [out] кратная точка */
	const word a[],		/*!< [in] базовая точка */
	const ec_o* ec,		/*!< [in] описание кривой */
	const word d[],		/*!< [in] кратность */
	size_t m,			/*!< [in] длина d в машинных словах */
	void* stack			/*!< [in] вспомогательная память */
);

size_t bignMulA2_deep(size_t n, size_t ec_d, size_t ec_deep, size_t m);

/*!	\brief Кратная базовая точка

	Определяется аффинная точка [2 * ec->f->n]b эллиптической кривой ec,
	которая является [ec->f->n]d-кратной точки ec->base:
	\code
		a <- d (ec->base).
	\endcode
	\pre Описание ec работоспособно.
	\expect Кривая ec удовлетворяет соглашениям Bign.
	\expect В ec используются якобиевы координаты.
	\return TRUE, если кратная точка отличается от O, и FALSE в противном
	случае.
	\deep{stack} bignMulBase_deep(ec->f->n, ec->d, ec->deep).
*/
bool_t bignMulBase(
	word a[],			/*!< [out] кратная точка */
	const ec_o* ec,		/*!< [in] описание кривой */
	const word d[],		/*!< [in] кратность */
	void* stack			/*!< [in] вспомогательная память */
);

size_t bignMulBase_deep(size_t n, size_t ec_d, size_t ec_deep);

/*
*******************************************************************************
ЕС-функции

\expect Кривая ec создана с помощью bignEcCreate().
\remark В функции bignParamsValEc() в отличие от всех остальных кривая ec
не заменяет параметры params, а используется вместе с ними.
*******************************************************************************
*/

err_t bignParamsValEc(const ec_o* ec, const bign_params* params);

err_t bignKeypairGenEc(octet privkey[], octet pubkey[], const ec_o* ec,
	gen_i rng, void* rng_state);

err_t bignKeypairValEc(const ec_o* ec, const octet privkey[],
	const octet pubkey[]);

err_t bignPubkeyValEc(const ec_o* ec, const octet pubkey[]);

err_t bignPubkeyCalcEc(octet pubkey[], const ec_o* ec, const octet privkey[]);

err_t bignDHEc(octet key[], const ec_o* ec, const octet privkey[],
	const octet pubkey[], size_t key_len);

err_t bignSignEc(octet sig[], const ec_o* ec, const octet oid_der[],
	size_t oid_len, const octet hash[], const octet privkey[], gen_i rng,
	void* rng_state);

err_t bignSign2Ec(octet sig[], const ec_o* ec, const octet oid_der[],
	size_t oid_len, const octet hash[], const octet privkey[], const void* t,
	size_t t_len);

err_t bignVerifyEc(const ec_o* ec, const octet oid_der[], size_t oid_len,
	const octet hash[], const octet sig[], const octet pubkey[]);

err_t bignKeyWrapEc(octet token[], const ec_o* ec, const octet key[],
	size_t len, const octet header[16], const octet pubkey[],
	gen_i rng, void* rng_state);

err_t bignKeyUnwrapEc(octet key[], const ec_o* ec, const octet token[],
	size_t len, const octet header[16], const octet privkey[]);

err_t bignIdExtractEc(octet id_privkey[], octet id_pubkey[],
	const ec_o* ec, const octet oid_der[], size_t oid_len,
	const octet id_hash[], const octet sig[], octet pubkey[]);

err_t bignIdSignEc(octet id_sig[], const ec_o* ec, const octet oid_der[],
	size_t oid_len, const octet id_hash[], const octet hash[],
	const octet id_privkey[], gen_i rng, void* rng_state);

err_t bignIdSign2Ec(octet id_sig[], const ec_o* ec, const octet oid_der[],
	size_t oid_len, const octet id_hash[], const octet hash[],
	const octet id_privkey[], const void* t, size_t t_len);

err_t bignIdVerifyEc(const ec_o* ec, const octet oid_der[], size_t oid_len,
	const octet id_hash[], const octet hash[], const octet id_sig[],
	const octet id_pubkey[], const octet pubkey[]);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __BEE2_BIGN_LCL_H */
