/*
*******************************************************************************
\file bign_lcl.h
\brief STB 34.101.45 (bign): local declarations
\project bee2 [cryptographic library]
\created 2014.04.03
\version 2025.09.24
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#ifndef __BEE2_BIGN_LCL_H
#define __BEE2_BIGN_LCL_H

#include "bee2/crypto/bign.h"

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

/*
*******************************************************************************
К удалению
*******************************************************************************
*/

/*!	\brief Потребности в стеке

	Определяется глубина стека, который требуется высокоуровневой функции
	для работы с эллиптической кривой, описываемой объясненными ниже
	размерностями n, f_deep, ec_d, ec_deep.
	\remark При расчете глубины не следует учитывать память для
	размещения описаний базового поля и эллиптической кривой.
*/

typedef size_t(*bign_deep_i)(
	size_t n,				/*!< [in] число слов для хранения элемента поля */
	size_t f_deep,			/*!< [in] глубина стека базового поля */
	size_t ec_d,			/*!< [in] число проективных координат */
	size_t ec_deep			/*!< [in] глубина стека эллиптической кривой */
	);

/*!	\brief Длина состояния

	Возвращается длина состояния (в октетах) высокоуровневой функции,
	которая работает на уровне стойкости l и имеет потребности в стеке deep.
	\pre l == 128 || l == 192 || l == 256.
	\return Длина состояния.
	\remark Состояние включает как локальные переменные, так и стек.
*/
size_t bignStart_keep(
	size_t l,				/*!< [in] уровень стойкости */
	bign_deep_i deep		/*!< [in] потребности в стековой памяти */
);

/*!	\brief Начало работы с параметрами

	По долговременным параметрам params по адресу state формируется описание
	эллиптической кривой.
	\pre bignParamsCheck(params) == ERR_OK.
	\return ERR_OK, если описание успешно создано, и код ошибки в противном
	случае.
	\remark Высокоуровневый механизм должен работать по следующей схеме:
	-	описать потребности в стеке с помощью функции интерфейса bign_deep_i;
	-	определить длину состояния, вызвав bignStart_keep();
	-	определить начало стека как память в state сразу после описания
		эллиптической кривой.
	.
*/
err_t bignStart(
	void* state,				/*!< [out] состояние */
	const bign_params* params	/*!< [in] долговременные параметры */
);


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __BEE2_BIGN_LCL_H */
