/*
*******************************************************************************
\file pfok.h
\brief Draft of RD_RB: key establishment protocols in finite fields
\project bee2 [cryptographic library]
\created 2014.06.30
\version 2024.01.11
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

/*!
*******************************************************************************
\file pfok.h
\brief Протоколы Проекта РД РБ (pfok)
*******************************************************************************
*/

#ifndef __BEE2_PFOK_H
#define __BEE2_PFOK_H

#ifdef __cplusplus
extern "C" {
#endif

#include "bee2/defs.h"

/*!
*******************************************************************************
\file pfok.h

\section pfok-common Проект РД РБ (pfok): Общие положения

Реализованы протоколы Проекта РД РБ (pfok). При ссылках на протоколы, таблицы, 
другие объекты подразумеваются разделы Проекта, в которых эти объекты 
определены. Дополнительно используются данные, представленные в СТБ 34.101.50.

\expect{ERR_BAD_INPUT} Все входные указатели корректны.

\safe todo
*******************************************************************************
*/

/*
*******************************************************************************
\file pfok.h

\section pfok-params Долговременные параметры

Структура pfok_params описывает долговременные параметры pfok. Содержание 
полей структуры определено в разделах 3, 5.1, 5.2. 

В структуре pfok_params параметр l определяет используемое число октетов 
в массивах p, g: используется O_OF_B(l) октетов. Неиспользуемые октеты
заполняются нулями. Параметр r определяет битовую длину личного ключа, 
параметр n -- общего секретного. 

Размерности l, r, n фигурирует в описаниях функций.

Ограничения:
-	l и r выбираются из таблицы 5.1;
-	p -- простое число битовой длины l такое, что q = (p - 1) / 2 простое. 
	Число p определяет группу Монтгомери B_p. Эта группа неотрицательных 
	вычетов mod p c операцией умножения Монтгомери: 
	\code
		u \circ v = u v R^{-1} \bmod p, R = 2^{l + 2};
	\endcode
	Возведение в степень в B_p обозначается круглыми скобками: u^(v) --- 
	произведение Монтгомери v экземпляров элемента u;
-	0 < g < p;
-	g имеет порядок q в группе B_p. В протоколах используется группа GG,
	порожденная g.
.

Размерности массивов p и g соответствуют максимальному значению l = 2942 
(см. табл. 5.1).

Структура pfok_seed описывает затравочные параметры, по которым генерируются 
долговременные параметры или проверяется результат генерации.

Ограничения на затравочные параметры указаны в описании функции pfokSeedVal().


Ограничения на затравочные параметры:
-	размерность l соответствует определенному уровню стойкости;
-	zi[i] \in {1, 2,..., 65256};
-	массив (цепочка) li начинается с числа li[0] = l - 1 и заканчивается числом
	li[t] \in {17,...,32}, после которого идут нули;
-	5 * li[i + 1] / 4 + 4 < li[i] <= 2 * li[i + 1], 0 <= i < t.
.

Размерности массива li соответствуют следующей цепочке максимальной длины:
	2941, 2349, 1875, 1496, 1193, 951, 757, 602, 478, 379, 299, 235, 184, 
	143, 111, 85, 64, 47, 34, 23.
Первый элемент цепочки: 2942 - 1.
Следующий элемент определяется по текущему элементу x как (4 * x - 17) / 5.

При генерации p = 2q + 1 простые числа q строятся до тех пор, пока 2q + 1 не 
окажется простым. Процедура генерации параметров может быть очень длительной. 
Поэтому в функцию генерации параметров можно передавать указатель на функцию
интерфейса pfok_on_q_i, которая получает управление при построении каждого 
нового кандидата q.
*******************************************************************************
*/

/*!	\brief Долговременные параметры */
typedef struct
{
	size_t l;			/*!< битовая длина p */
	size_t r;			/*!< битовая длина личного ключа */
	size_t n;			/*!< битовая длина общего ключа */
	octet p[368];		/*!< модуль p */
	octet g[368];		/*!< образующий g */
} pfok_params;

/*!	\brief Затравочные данные */
typedef struct
{
	size_t l;			/*!< битовая длина p */
	u16 zi[31];			/*!< числа zi[i] */
	size_t li[20];		/*!< цепочка li */
} pfok_seed;

/*!	\brief Обработка нового числа q

	Обрабатывается построение очередного простого числа [n]q во время 
	генерации параметра p = 2q + 1. Новое простое число получено в попытке
	с номером num (нумерация начиная с 1).
	\remark При генерации долговременных параметров функция будет вызываться
	с возрастающим номером num до тех пор, пока p не окажется простым.
	\remark По окончании вычислений окончательное простое [n]q передается
	в функцию еще раз с нулевым num. В этом обращении можно выполнить
	завершающие служебные действия.
*/
typedef void (*pfok_on_q_i) (
	const word q[],			/*!< [in] простое число */
	const size_t n,			/*!< [in] длина q в машинных словах */
	size_t num				/*!< [in] номер попытки */
);

/*!	\brief Проверка затравочных параметров

	Проверяется, что затравочные параметры seed корректны:
	-	размерность l соответствует определенному уровню стойкости;
	-	zi[i] \in {1, 2,..., 65256};
	-	массив (цепочка) li начинается с числа li[0] = l - 1 и заканчивается
		числом li[t] \in {17,...,32}, после которого идут нули;
	-	5 * li[i + 1] / 4 + 4 < li[i] <= 2 * li[i + 1], 0 <= i < t.
	.
	\return ERR_OK, если параметры корректны, и код ошибки в противном случае.
*/
err_t pfokSeedVal(
	const pfok_seed* seed	/*!< [in] затравочные параметры */
);

/*!	\brief Настройка затравочных параметров

	В структуре seed незаполненным (нулевым) параметрам seed->zi и seed->li
	присваиваются значения по умолчанию. Эти значения определяются с участием
	seed->l следующим образом:
	-	zi[0] = 1,..., zi[30] = 31;
	-	li[0] = l - 1, li[1] = li[0] / 2 + 1, ...,
			li[t] = li[t - 1] / 2 + 1 \in {17,..., 32}, 0, ...., 0.
	.
	\return ERR_OK, если итоговые параметры корректны, и код ошибки
	в противном случае.
*/
err_t pfokSeedAdj(
	pfok_seed* seed		/*!< [in/out] затравочные параметры */
);

/*!	\brief Загрузка стандартных долговременных параметров

	В params загружаются стандартные долговременные параметры с именем name, 
	а в seed -- затравочные параметры, на которых получены params. Указатель
	seed может быть нулевым, и в этом случае затравочные параметры не загружаются.
	Поддерживаются следующие имена:
		"1.2.112.0.2.0.1176.2.3.3.2",
		"1.2.112.0.2.0.1176.2.3.6.2",
		"1.2.112.0.2.0.1176.2.3.10.2".
	Это имена стандартных параметров, заданных в таблице В.3 СТБ 34.101.50.
	Дополнительно поддерживается имя "test" тестовых параметров первого 
	уровня стойкости (l == 638).
	\return ERR_OK, если параметры успешно загружены, и код ошибки в
	противном случае.
*/
err_t pfokParamsStd(
	pfok_params* params,	/*!< [out] стандартные параметры */
	pfok_seed* seed,		/*!< [out] затравочные параметры */
	const char* name		/*!< [in] имя параметров */
);

/*!	\brief Генерация долговременных параметров

	По затравочным параметрам seed генерируются долговременные параметры params.
	При построении очередного числа q, по которому определяется params->p, 
	вызывается функция on_q.
	\return ERR_OK, если параметры успешно сгенерированы, и код ошибки
	в противном случае.
	\remark Указатель on_q может быть нулевым и тогда построение q не 
	обрабатывается.
	\remark Реализованы алгоритмы 5.2, 5.3. В качестве params->g выбираются 
	последовательные числа 1, 2,... до тех пор, пока не встретится подходящее.
*/
err_t pfokParamsGen(
	pfok_params* params,	/*!< [out] долговременные параметры */
	const pfok_seed* seed,	/*!< [in] затравочные параметры */
	pfok_on_q_i on_q		/*!< [in] обработчик */
);

/*!	\brief Проверка долговременных параметров

	Проверяется, что долговременные параметры params корректны. Для полей 
	params проверяются следующие условия:
	-	размерности l и r согласованы и соответствуют определенному уровню 
		стойкости;
	-	n < l;
	-	p -- l-битовое простое число;
	-	q = (p - 1) / 2 -- простое;
	-	g < p;
	-	g имеет порядок p - 1 в группе Монтгомери mod p.
	.
	\return ERR_OK, если параметры корректны, и код ошибки в противном случае.
	\warning Не проверяется, что p построен по алгоритму 5.2.
*/
err_t pfokParamsVal(
	const pfok_params* params	/*!< [in] долговременные параметры */
);

/*
*******************************************************************************
Управление ключами
*******************************************************************************
*/

/*!	\brief Генерация пары ключей

	При долговременных параметрах params генерируются личный 
	[O_OF_B(r)]privkey и открытый [O_OF_B(l)]pubkey ключи. При генерации 
	используется генератор rng и его состояние rng_state.
	\expect{ERR_BAD_PARAMS} Параметры params корректны.
	\expect{ERR_BAD_RNG} Генератор rng (с состоянием rng_state) корректен.
	\expect Используется криптографически стойкий генератор rng.
	\return ERR_OK, если ключи успешно сгенерированы, и код ошибки
	в противном случае.
	\remark pubkey = g^(privkey).
*/
err_t pfokKeypairGen(
	octet privkey[],			/*!< [out] личный ключ */
	octet pubkey[],				/*!< [out] открытый ключ */
	const pfok_params* params,	/*!< [in] долговременные параметры */
	gen_i rng,					/*!< [in] генератор случайных чисел */
	void* rng_state				/*!< [in,out] состояние генератора */
);

/*!	\brief Проверка открытого ключа

	При долговременных параметрах params проверяется корректность
	открытого ключа [O_OF_B(l)]pubkey.
	\expect{ERR_BAD_PARAMS} Параметры params корректны.
	\return ERR_OK, если ключ корректен, и код ошибки в противном случае.
*/
err_t pfokPubkeyVal(
	const pfok_params* params,	/*!< [in] долговременные параметры */
	const octet pubkey[]		/*!< [in] проверяемый ключ */
);

/*!	\brief Построение открытого ключа по личному

	При долговременных параметрах params по личному ключу 
	[O_OF_B(r)]privkey строится открытый ключ [O_OF_B(l)]pubkey.
	\expect{ERR_BAD_PARAMS} Параметры params корректны.
	\expect{ERR_BAD_PRIVKEY} Личный ключ privkey корректен.
	\return ERR_OK, если открытый ключ успешно построен, и код ошибки
	в противном случае.
	\remark pubkey = g^(privkey).
*/
err_t pfokPubkeyCalc(
	octet pubkey[],				/*!< [out] открытый ключ */
	const pfok_params* params,	/*!< [in] долговременные параметры */
	const octet privkey[]		/*!< [in] личный ключ */
);

/*!	\brief Построение общего ключа протокола Диффи -- Хеллмана 

	При долговременных параметрах params по личному ключу 
	[O_OF_B(r)]privkey и открытому ключу [O_OF_B(l)]pubkey противоположной 
	стороны строится общий ключ [O_OF_B(n)]sharekey. Общий ключ 
	определяется как n битов числа pubkey^(privkey), что соответствует 
	протоколу Диффи -- Хеллмана.
	\expect{ERR_BAD_PARAMS} Параметры params корректны.
	\expect{ERR_BAD_PUBKEY} Открытый ключ pubkey корректен.
	\expect{ERR_BAD_PRIVKEY} Личный ключ privkey корректен.
	\return ERR_OK, если общий ключ успешно построен, и код ошибки
	в противном случае.
	\remark Функция поддерживает протокол без аутентификации сторон (4.1)
	при следующих соглашениях:
	\code
		privkey = ua, pubkey = vb || privkey = ub, pubkey = va.
	\endcode
	\remark Функция поддерживает односторонний протокол (4.3) при следующих 
	соглашениях:
	\code
		privkey = ua, pubkey = yb || privkey = xb, pubkey = va.
	\endcode
*/
err_t pfokDH(
	octet sharekey[],			/*!< [out] общий ключ */
	const pfok_params* params,	/*!< [in] долговременные параметры */
	const octet privkey[],		/*!< [in] личный ключ */
	const octet pubkey[]		/*!< [in] открытый ключ (другой стороны) */
);

/*!	\brief Построение общего ключа протокола MTI

	При долговременных параметрах params по личному ключу 
	[O_OF_B(r)]privkey, одноразовому личному ключу [O_OF_B(r)]privkey1,
	открытому ключу [O_OF_B(l)]pubkey противоположной стороны 
	и одноразовому открытому ключу [O_OF_B(l)]pubkey противоположной стороны 
	строится общий ключ [O_OF_B(n)]sharekey. Общий ключ 
	определяется как n битов числа
	\code
		pubkey1^(privkey) \xor pubkey^(privkey1).
	\endcode
	что соответствует протоколу Диффи -- Хеллмана.
	\expect{ERR_BAD_PARAMS} Параметры params корректны.
	\expect{ERR_BAD_PUBKEY} Открытый ключ pubkey корректен.
	\expect{ERR_BAD_PRIVKEY} Личный ключ privkey корректен.
	\return ERR_OK, если общий ключ успешно построен, и код ошибки
	в противном случае.
	\remark Функция поддерживает протокол с аутентификацией сторон (4.2)
	при следующих соглашениях:
	\code
		privkey = xa, privkey1 = ua, pubkey = yb, pubkey1 = vb || 
		privkey = xb, privkey1 = ub, pubkey = ya, pubkey1 = va. 
	\endcode
	\remark Протокол 4.2 построен по схеме MTI (Matsumoto, Takashima, Imai),
	чем и объясняется название функции.
*/
err_t pfokMTI(
	octet sharekey[],			/*!< [out] общий ключ */
	const pfok_params* params,	/*!< [in] долговременные параметры */
	const octet privkey[],		/*!< [in] личный ключ */
	const octet privkey1[],		/*!< [in] одноразовый личный ключ */
	const octet pubkey[],		/*!< [in] открытый ключ (другой стороны) */
	const octet pubkey1[]		/*!< [in] однораз. откр. ключ (др. стороны) */
);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __BEE2_PFOK_H */
