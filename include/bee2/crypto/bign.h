/*
*******************************************************************************
\file bign.h
\brief STB 34.101.45 (bign): digital signature and key transport algorithms
\project bee2 [cryptographic library]
\created 2012.04.27
\version 2023.09.19
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

/*!
*******************************************************************************
\file bign.h
\brief Алгоритмы СТБ 34.101.45 (bign)
*******************************************************************************
*/

#ifndef __BEE2_BIGN_H
#define __BEE2_BIGN_H

#ifdef __cplusplus
extern "C" {
#endif

#include "bee2/defs.h"

/*!
*******************************************************************************
\file bign.h

\section bign-common СТБ 34.101.45 (bign): Общие положения

Реализованы алгоритмы СТБ 34.101.45 (bign). При ссылках на алгоритмы, таблицы,
другие объекты подразумеваются разделы СТБ 34.101.45-2013, в которых эти
объекты определены.

\expect{ERR_BAD_INPUT} Все входные указатели корректны.

\safe todo
*******************************************************************************
*/

/*
*******************************************************************************
\file bign.h

\section bign-params Управление долговременными параметрами

Структура bign_params описывает долговременные параметры bign. Содержание 
полей структуры определено в п. 5.3. 

В структуре bign_params уровень стойкости l определяет используемое число
октетов в массивах p, a, b, q, yG. При l == 128 используются первые 32 октета,
при l == 192 -- первые 48. Остальные октеты игнорируются и могут быть заданы
произвольным образом. При l == 256 используются все 64 октета.

Уровень стойкости l фигурирует в описаниях функций и определяет длины ключей,
хэш-значений, подписей.
*******************************************************************************
*/

/*!	\brief Долговременные параметры bign */
typedef struct
{
	size_t l;		/*!< уровень стойкости (128, 192 или 256) */
	octet p[64];	/*!< модуль p */
	octet a[64];	/*!< коэффициент a */
	octet b[64];	/*!< коэффициент b */
	octet q[64];	/*!< порядок q */
	octet yG[64];	/*!< y-координата точки G */
	octet seed[8];  /*!< параметр seed */
} bign_params;

/*!	\brief Загрузка стандартных долговременных параметров

	В params загружаются стандартные долговременные параметры с именем name.
	Поддерживаются следующие имена:
		"1.2.112.0.2.0.34.101.45.3.1",
		"1.2.112.0.2.0.34.101.45.3.2",
		"1.2.112.0.2.0.34.101.45.3.3".
	Это имена стандартных параметров, заданных в таблицах Б.1, Б.2, Б.3.
	\return ERR_OK, если параметры успешно загружены, и код ошибки в
	противном случае.
*/
err_t bignStdParams(
	bign_params* params,	/*!< [out] стандартные параметры */
	const char* name		/*!< [in] имя параметров */
);

/*!	\brief Проверка долговременных параметров

	Проверяется корректность долговременных параметров params.
	\return ERR_OK, если параметры корректны, и код ошибки
	в противном случае.
	\remark Реализован алгоритм 6.1.4.
*/
err_t bignValParams(
	const bign_params* params	/*!< [in] долговременные параметры */
);

/*!
*******************************************************************************
\file bign.h

\section bign-oid Идентификатор объекта

В функциях ЭЦП используется идентификатор используемого алгоритма хэширования. 
Идентификатор представляет собой последовательность неотрицательных целых чисел 
{d1 d2 ... dn}. Эта последовательность должна 
удовлетворять базовым ограничениям ACH.1 (см. приложение A) и, дополнительно, 
числа di не должны превосходить 2^32 - 1 = 4294967295.

Идентификатор задается либо строкой "d1.d2....dn", либо DER-кодом.
Если идентификатор задается строкой, то числа di должны записываться без 
лидирующих нулей.

Функция bignOidEncode() выполняет преобразование строкового представления 
в DER-код.

Если идентификатор некорректен, то функции, в которых он используется,
возвращают код ERR_BAD_OID.
*******************************************************************************
*/

/*!	\brief Кодирование идентификатора объекта

	По строковому представлению oid идентификатора объекта строится его
	DER-код [?oid_len]oid_der.
	\return ERR_OK, если кодирование успешно выполнено или длина DER-кода 
	успешно рассчитана, и код ошибки в противном случае.
*/
err_t bignOidToDER(
	octet oid_der[],	/*!< [out] DER-код идентификатора */
	size_t* oid_len,	/*!< [in,out] длина буфера oid_der / длина DER-кода */
	const char* oid		/*!< [in] строковое представление идентификатора */
);

/*
*******************************************************************************
Управление ключами
*******************************************************************************
*/

/*!	\brief Генерация пары ключей

	При долговременных параметрах params генерируются личный [l / 4]privkey 
	и открытый [l / 2]pubkey ключи. При генерации используется генератор rng 
	и его состояние rng_state.
	\expect{ERR_BAD_PARAMS} Параметры params корректны.
	\expect{ERR_BAD_RNG} Генератор rng (с состоянием rng_state) корректен.
	\expect Используется криптографически стойкий генератор rng.
	\return ERR_OK, если ключи успешно сгенерированы, и код ошибки
	в противном случае.
	\remark Реализован алгоритм 6.2.2.
*/
err_t bignGenKeypair(
	octet privkey[],			/*!< [out] личный ключ */
	octet pubkey[],				/*!< [out] открытый ключ */
	const bign_params* params,	/*!< [in] долговременные параметры */
	gen_i rng,					/*!< [in] генератор случайных чисел */
	void* rng_state				/*!< [in,out] состояние генератора */
);

/*!	\brief Проверка пары ключей

	При долговременных параметрах params проверяется корректность
	личного ключа [l / 8]privkey и соответствие ему открытого ключа
	[l / 2]pubkey.
	\expect{ERR_BAD_PARAMS} Параметры params корректны.
	\return ERR_OK, если пара корректна, и код ошибки в противном случае.
*/
err_t bignValKeypair(
	const bign_params* params,	/*!< [in] долговременные параметры */
	const octet privkey[],		/*!< [in] личный ключ */
	const octet pubkey[]		/*!< [in] открытый ключ */
);

/*!	\brief Проверка открытого ключа

	При долговременных параметрах params проверяется корректность 
	открытого ключа [l / 2]pubkey.
	\expect{ERR_BAD_PARAMS} Параметры params корректны.
	\return ERR_OK, если ключ корректен, и код ошибки в противном случае.
	\remark Реализован алгоритм 6.2.3.
*/
err_t bignValPubkey(
	const bign_params* params,	/*!< [in] долговременные параметры */
	const octet pubkey[]		/*!< [in] проверяемый ключ */
);

/*!	\brief Построение открытого ключа по личному

	При долговременных параметрах params по личному ключу [l / 4]privkey 
	строится открытый ключ [l / 2]pubkey.
	\expect{ERR_BAD_PARAMS} Параметры params корректны.
	\expect{ERR_BAD_PRIVKEY} Личный ключ privkey корректен.
	\return ERR_OK, если открытый ключ успешно построен, и код ошибки
	в противном случае.
*/
err_t bignCalcPubkey(
	octet pubkey[],				/*!< [out] открытый ключ */
	const bign_params* params,	/*!< [in] долговременные параметры */
	const octet privkey[]		/*!< [in] личный ключ */
);

/*!	\brief Построение общего ключа протокола Диффи -- Хеллмана 

	При долговременных параметрах params по личному ключу [l / 4]privkey 
	и открытому ключу [l / 2]pubkey противоположной стороны строится 
	общий ключ [key_len]key. Общий ключ определяется как privkey-кратное 
	ключа pubkey, что соответствует	протоколу Диффи -- Хеллмана.
	\expect{ERR_BAD_PARAMS} Параметры params корректны.
	\expect{ERR_BAD_PRIVKEY} Личный ключ privkey корректен.
	\expect{ERR_BAD_PUBKEY} Открытый ключ pubkey корректен.
	\expect{ERR_BAD_SHAREDKEY} key_len <= l / 2.
	\return ERR_OK, если общий ключ успешно построен, и код ошибки
	в противном случае.
*/
err_t bignDH(
	octet key[],				/*!< [out] общий ключ */
	const bign_params* params,	/*!< [in] долговременные параметры */
	const octet privkey[],		/*!< [in] личный ключ */
	const octet pubkey[],		/*!< [in] открытый ключ (другой стороны) */
	size_t key_len				/*!< [in] длина key в октетах */
);

/*
*******************************************************************************
Электронная цифровая подпись (ЭЦП)
*******************************************************************************
*/

/*!	\brief Выработка ЭЦП

	Вырабатывается подпись [3 * l / 8]sig сообщения с хэш-значением 
	[l / 4]hash, полученном с помощью алгоритма с идентификатором 
	[oid_len]oid_der, заданным DER-кодом. Подпись вырабатывается на личном 
	ключе [l / 4]privkey. При выработке ЭЦП используются долговременные
	параметры params и генератор rng с состоянием rng_state.
	\expect{ERR_BAD_PARAMS} Параметры params корректны.
	\expect{ERR_BAD_OID} Идентификатор oid_der корректен.
	\expect{ERR_BAD_INPUT} Буферы sig и hash не пересекаются.
	\expect{ERR_BAD_PRIVKEY} Личный ключ privkey корректен.
	\expect{ERR_BAD_RNG} Генератор rng (с состоянием rng_state) корректен.
	\expect Генератор rng является криптографически стойким.
	\return ERR_OK, если подпись выработана, и код ошибки в противном
	случае.
	\remark Реализован алгоритм 7.1.3.
*/
err_t bignSign(
	octet sig[],				/*!< [out] подпись */
	const bign_params* params,	/*!< [in] долговременные параметры */
	const octet oid_der[],		/*!< [in] идентификатор хэш-алгоритма */
	size_t oid_len,				/*!< [in] длина oid_der в октетах */
	const octet hash[],			/*!< [in] хэш-значение */
	const octet privkey[],		/*!< [in] личный ключ */
	gen_i rng,					/*!< [in] генератор случайных чисел */
	void* rng_state				/*!< [in,out] состояние генератора */
);

/*!	\brief Детерминированная выработка ЭЦП

	Вырабатывается подпись [3 * l / 8]sig сообщения с хэш-значением 
	[l / 4]hash, полученном с помощью алгоритма с идентификатором 
	[oid_len]oid_der, заданным DER-кодом. Подпись вырабатывается на личном 
	ключе [l / 4]privkey. При выработке ЭЦП используются долговременные параметры 
	params. Одноразовый личный ключ генерируется по алгоритму 6.3.3 
	с использованием дополнительных данных [t_len]t. Если t == 0, то 
	дополнительные данные не используются.  
	\expect{ERR_BAD_PARAMS} Параметры params корректны.
	\expect{ERR_BAD_OID} Идентификатор oid_der корректен.
	\expect{ERR_BAD_INPUT} Буферы sig и hash не пересекаются.
	\expect{ERR_BAD_PRIVKEY} Личный ключ privkey корректен.
	\return ERR_OK, если подпись выработана, и код ошибки в противном
	случае.
	\remark Реализованы алгоритмы 7.1.3 и 6.3.3.
*/
err_t bignSign2(
	octet sig[],				/*!< [out] подпись */
	const bign_params* params,	/*!< [in] долговременные параметры */
	const octet oid_der[],		/*!< [in] идентификатор хэш-алгоритма */
	size_t oid_len,				/*!< [in] длина oid_der в октетах */
	const octet hash[],			/*!< [in] хэш-значение */
	const octet privkey[],		/*!< [in] личный ключ */
	const void* t,				/*!< [in] дополнительные данные */
	size_t t_len				/*!< [in] размер дополнительных данных */
);

/*!	\brief Проверка ЭЦП

	Проверяется ЭЦП [3 * l / 8]sig сообщения с хэш-значением [l / 4]hash. При 
	проверке используются долговременные параметры params и открытый ключ 
	[l / 2]pubkey. Считается, что хэш-значение [l / 4]hash получено с помощью 
	алгоритма с идентификатором [oid_len]oid_der, заданным DER-кодом.
	\expect{ERR_BAD_PARAMS} Параметры params корректны.
	\expect{ERR_BAD_OID} Идентификатор oid_der корректен.
	\expect{ERR_BAD_PUBKEY} Открытый ключ pubkey корректен.
	\return ERR_OK, если подпись корректна, и код ошибки в противном
	случае.
	\remark Реализован алгоритм 7.1.4.
	\remark При нарушении ограничений на ЭЦП возвращается код ERR_BAD_SIG.
*/
err_t bignVerify(
	const bign_params* params,	/*!< [in] долговременные параметры */
	const octet oid_der[],		/*!< [in] идентификатор хэш-алгоритма */
	size_t oid_len,				/*!< [in] длина oid_der в октетах */
	const octet hash[],			/*!< [in] хэш-значение */
	const octet sig[],			/*!< [in] подпись */
	const octet pubkey[]		/*!< [in] открытый ключ */
);

/*
*******************************************************************************
Транспорт ключа
*******************************************************************************
*/

/*!	\brief Создание токена ключа

	Создается токен [l / 4 + 16 + len]token ключа [len]key с заголовком 
	[16]header. При создании токена используются долговременные параметры 
	params, открытый ключ получателя pubkey и генератор rng с состоянием 
	rng_state.
	\expect{ERR_BAD_PARAMS} Параметры params корректны.
	\expect{ERR_BAD_INPUT} len >= 16.
	\expect{ERR_BAD_PUBKEY} Открытый ключ pubkey корректен.
	\expect{ERR_BAD_RNG} Генератор rng (с состоянием rng_state) корректен.
	\expect Используется криптографически стойкий генератор rng.
	\return ERR_OK, если токен успешно создан, и код ошибки в противном
	случае.
	\remark Реализован алгоритм 7.2.3.
	\remark Может передаваться нулевой указатель header. В этом случае будет
	использоваться заголовок из всех нулей.
*/
err_t bignKeyWrap(
	octet token[],				/*!< [out] токен ключа */
	const bign_params* params,	/*!< [in] долговременные параметры */
	const octet key[],			/*!< [in] транспортируемый ключ */
	size_t len,					/*!< [in] длина ключа в октетах */
	const octet header[16],		/*!< [in] заголовок ключа */
	const octet pubkey[],		/*!< [in] открытый ключ получателя */
	gen_i rng,					/*!< [in] генератор случайных чисел */
	void* rng_state				/*!< [in,out] состояние генератора */
);

/*!	\brief Разбор токена ключа

	Определяется ключ [len - (l / 4 + 16)]key, который имеет заголовок 
	[16]header и содержится в токене [len]token. При разборе токена 
	используются долговременные параметры params и личный ключ [l / 2]privkey.
	\expect{ERR_BAD_PARAMS} Параметры params корректны.
	\expect{ERR_BAD_PRIVKEY} Личный ключ privkey корректен.
	\return ERR_OK, если токен успешно разобран, и код ошибки в противном
	случае.
	\remark Реализован алгоритм 7.2.4.
	\remark Может передаваться нулевой указатель header. В этом случае будет
	использоваться заголовок из всех нулей.
	\remark При нарушении целостности токена возвращается код ERR_BAD_KEYTOKEN.
	Этот код будет возвращен, если len < 32 + l / 4.
*/
err_t bignKeyUnwrap(
	octet key[],				/*!< [out] ключ */
	const bign_params* params,	/*!< [in] долговременные параметры */
	const octet token[],		/*!< [in] токен ключа */
	size_t len,					/*!< [in] длина токена в октетах */
	const octet header[16],		/*!< [in] заголовок ключа */
	const octet privkey[]		/*!< [in] личный ключ получателя */
);

/*!
*******************************************************************************
\file bign.h

\section bign-ibs Идентификационная ЭЦП

Идентификационная подпись при передаче и хранении должна объединяться 
с открытым ключом (см. Д.3). Объединенная подпись состоит из 7 * l / 8 
октетов и включает две части: первая часть -- собственно подпись 
(3 * l / 8 октетов), вторая часть -- открытый ключ (l / 2 октетов).
*******************************************************************************
*/

/*!	\brief Извлечение пары ключей

	Из подписи [3 * l / 8]sig идентификатора с хэш-значением [l / 4]id_hash 
	извлекаются личный [l / 4]id_privkey и открытый [l / 2]id_pubkey ключи. 
	Используются долговременные параметры params и открытый ключ [l / 2]pubkey 
	доверенной стороны. Считается, что хэш-значение id_hash получено с помощью 
	алгоритма с идентификатором [oid_len]oid_der, заданным DER-кодом.
	\expect{ERR_BAD_PARAMS} Параметры params корректны.
	\expect{ERR_BAD_OID} Идентификатор oid_der корректен.
	\expect{ERR_BAD_PUBKEY} Открытый ключ pubkey корректен.
	\return ERR_OK, если ключи успешно извлечены, и код ошибки
	в противном случае.
	\remark Реализован алгоритм B.2.3.
	\remark Одновременно с извлечением ключей проверяется подпись sig.
	Если подпись некорректна, то будет возвращен код ERR_BAD_SIG.
*/
err_t bignIdExtract(
	octet id_privkey[],			/*!< [out] личный ключ */
	octet id_pubkey[],			/*!< [out] открытый ключ */
	const bign_params* params,	/*!< [in] долговременные параметры */
	const octet oid_der[],		/*!< [in] идентификатор хэш-алгоритма */
	size_t oid_len,				/*!< [in] длина oid_der в октетах */
	const octet id_hash[],		/*!< [in] хэш-значение идентификатора */
	const octet sig[],			/*!< [in] подпись идентификатора */
	octet pubkey[]				/*!< [in] открытый ключ доверенной стороны */
);

/*!	\brief Выработка идентификационной ЭЦП

	Вырабатывается идентификационная подпись [3 * l / 8]id_sig сообщения с 
	хэш-значением [l / 4]hash. Подпись вырабатывается на личном ключе 
	[l / 4]id_privkey стороны, которая имеет идентификатор с хэш-значением 
	[l / 4]id_hash. Считается, что хэш-значения id_hash и hash получены с 
	помощью алгоритма с идентификатором [oid_len]oid_der, заданным DER-кодом. 
	При выработке ЭЦП используются долговременные параметры params и генератор 
	rng с состоянием rng_state.
	\expect{ERR_BAD_PARAMS} Параметры params корректны.
	\expect{ERR_BAD_OID} Идентификатор oid_der корректен.
	\expect{ERR_BAD_PRIVKEY} Ключ id_privkey получен с помощью функции 
	bignIdExtract().
	\expect{ERR_BAD_RNG} Генератор rng (с состоянием rng_state) корректен.
	\expect Генератор rng является криптографически стойким.
	\return ERR_OK, если подпись выработана, и код ошибки в противном
	случае.
	\remark Реализован алгоритм B.2.4. 
*/
err_t bignIdSign(
	octet id_sig[],				/*!< [out] идентификационная подпись */
	const bign_params* params,	/*!< [in] долговременные параметры */
	const octet oid_der[],		/*!< [in] идентификатор хэш-алгоритма */
	size_t oid_len,				/*!< [in] длина oid_der в октетах */
	const octet id_hash[],		/*!< [in] хэш-значение идентификатора */
	const octet hash[],			/*!< [in] хэш-значение сообщения */
	const octet id_privkey[],	/*!< [in] личный ключ */
	gen_i rng,					/*!< [in] генератор случайных чисел */
	void* rng_state				/*!< [in,out] состояние генератора */
);

/*!	\brief Детерминированная выработка идентификационной ЭЦП

	Вырабатывается идентификационная подпись [3 * l / 8]id_sig сообщения 
	с хэш-значением [l / 4]hash. Подпись вырабатывается на личном ключе 
	[l / 4]id_privkey стороны, которая имеет идентификатор с хэш-значением 
	[l / 4]id_hash. Считается, что хэш-значения id_hash и hash получены с 
	помощью алгоритма с идентификатором [oid_len]oid_der, заданным DER-кодом. 
	При выработке ЭЦП используются долговременные параметры params. 
	Одноразовый личный ключ генерируется по алгоритму 6.3.3 с использованием 
	дополнительных данных [t_len]t. Если t == 0, то дополнительные данные 
	не используются.
	\expect{ERR_BAD_PARAMS} Параметры params корректны.
	\expect{ERR_BAD_OID} Идентификатор oid_der корректен.
	\expect{ERR_BAD_PRIVKEY} Ключ id_privkey получен с помощью функции 
	bignIdExtract().
	\return ERR_OK, если подпись выработана, и код ошибки в противном
	случае.
	\remark Реализованы алгоритмы B.2.4 и 6.3.3. 
*/
err_t bignIdSign2(
	octet id_sig[],				/*!< [out] идентификационная подпись */
	const bign_params* params,	/*!< [in] долговременные параметры */
	const octet oid_der[],		/*!< [in] идентификатор хэш-алгоритма */
	size_t oid_len,				/*!< [in] длина oid_der в октетах */
	const octet id_hash[],		/*!< [in] хэш-значение идентификатора */
	const octet hash[],			/*!< [in] хэш-значение сообщения */
	const octet id_privkey[],	/*!< [in] личный ключ */
	const void* t,				/*!< [in] дополнительные данные */
	size_t t_len				/*!< [in] длина t в октетах */
);

/*!	\brief Проверка идентификационной ЭЦП

	Проверяется идентификационная ЭЦП [3 * l / 8]id_sig сообщения 
	с хэш-значением [l / 4]hash, выработанная стороной, хэш-значение 
	идентификатора которой есть [l / 4]id_hash. При проверке используются 
	долговременные параметры params, открытый ключ [l / 2]id_pubkey и открытый 
	ключ доверенной стороны [l / 4]pubkey. Считается, что хэш-значения 
	id_hash, hash получены с помощью алгоритма с идентификатором 
	[oid_len]oid_der, заданным DER-кодом.
	\expect{ERR_BAD_PARAMS} Параметры params корректны.
	\expect{ERR_BAD_OID} Идентификатор oid_der корректен.
	\expect{ERR_BAD_PUBKEY}
	-	открытый ключ id_pubkey получен с помощью функции bignIdExtract();
	-	открытый ключ pubkey корректен.
	.
	\return ERR_OK, если подпись корректна, и код ошибки в противном
	случае.
	\remark Реализован алгоритм B.2.5.
	\remark При нарушении ограничений на ЭЦП возвращается код ERR_BAD_SIG.
*/
err_t bignIdVerify(
	const bign_params* params,	/*!< [in] долговременные параметры */
	const octet oid_der[],		/*!< [in] идентификатор хэш-алгоритма */
	size_t oid_len,				/*!< [in] длина oid_der в октетах */
	const octet id_hash[],		/*!< [in] хэш-значение идентификатора */
	const octet hash[],			/*!< [in] хэш-значение сообщения */
	const octet id_sig[],		/*!< [in] подпись */
	const octet id_pubkey[],	/*!< [in] открытый ключ */
	const octet pubkey[]		/*!< [in] открытый ключ доверенной стороны */
);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __BEE2_BIGN_H */
