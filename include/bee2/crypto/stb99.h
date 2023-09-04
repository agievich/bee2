/*
*******************************************************************************
\file stb99.h
\brief STB 1176.2-99: generation of parameters
\project bee2 [cryptographic library]
\created 2023.08.01
\version 2023.09.04
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

/*!
*******************************************************************************
\file stb99.h
\brief Параметры алгоритмов электронной цифровой подписи СТБ 1176.2-99 (stb99)
*******************************************************************************
*/

#ifndef __BEE2_STB99_H
#define __BEE2_STB99_H

#ifdef __cplusplus
extern "C" {
#endif

#include "bee2/defs.h"

/*!
*******************************************************************************
\file stb99.h

\section stb99-common СТБ 1176.2-99 (stb99): Общие положения

Реализованы алгоритмы генерации параметров, установленные в СТБ 1176.2-99.
Упоминаемые таблицы, пункты и другие объекты относятся к СТБ 1176.2.
Дополнительно используются данные, представленные в СТБ 34.101.50. 

\expect{ERR_BAD_INPUT} Все входные указатели корректны.
*******************************************************************************
*/

/*
*******************************************************************************
\file stb99.h

\section stb99-params Долговременные параметры

Структура stb99_params описывает долговременные параметры stb99. Содержание 
полей структуры определено в разделах 5.1, 7.2.

В stb99_params параметры l и r определяют используемое число октетов 
в массивах p, q, a: в массивах p и a используется O_OF_B(l) октетов,
в массиве q ---  O_OF_B(r) октетов. Неиспользуемые октеты игнорируются.

Размерности l, r фигурирует в описаниях функций.

Ограничения:
-	l и r выбираются из таблицы 7.1;
-	p -- простое число битовой длины l. 
	Число p определяет группу Монтгомери B_p. Эта группа неотрицательных 
	вычетов mod p c операцией умножения Монтгомери: 
	\code
		u \circ v = u v R^{-1} \bmod p, R = 2^{l + 2};
	\endcode
-	q -- простое число битовой длины r, которое делит p - 1; 
	Число q определяет подгруппу GG группы B_p;
-	0 < a < p;
-	a имеет порядок q в B_p, является образующим GG.
.

Размерности массивов p, q, a соответствуют максимальным значениям l = 2462 
и r = 257 (см. табл. 7.1) с учетом выравнивания на 8-байтовую границу.

Структура stb99_seed описывает затравочные параметры, по которым генерируются 
долговременные параметры или проверяется результат генерации. Затравочные
параметры описаны в пункте 7.2.1.

Ограничения на затравочные параметры:
-	zi[i] \in {1, 2,..., 65256};
-	массив (цепочка) di начинается с числа di[0] и заканчивается числом 
	di[t] \in {17,...,32}. Элементы массива после di[t] игнорируются;
-	массив (цепочка) ri начинается с числа ri[0] и заканчивается числом 
	ri[s] \in {17,...,32}. Элементы массива после ri[s] игнорируются;
-	l / 2 <= di[0] <= 7 * l / 8 - r;
-	ri[0] = r;
-	5 * di[i + 1] / 4 + 4 < di[i] <= 2 * di[i + 1];
-	5 * ri[i + 1] / 4 < ri[i] <= 2 * ri[i + 1].
.

Размерности массива di соответствуют следующей цепочке максимальной длины:
	1897, 1514, 1207, 962, 766, 609, 483, 383, 303, 239, 187, 146, 113,
	87, 66, 49, 35, 24.
Первый элемент цепочки: 7 * 2462 / 8 - 257.
Следующий элемент определяется по текущему элементу x как (4 * x - 17) / 5.

Размерности массива ri соответствуют следующей цепочке максимальной длины:
	257, 205, 163, 130, 103, 82, 65, 51, 40, 31.
Первый элемент цепочки: 257.
Следующий элемент определяется по текущему элементу x как (4 * x - 1) / 5.

Параметр p имеет вид 2 * g0 * q * R + 1, где g0 -- большое простое.
При генерации сначала строится g0, затем q. Простые й строятся до тех пор,
пока p не окажется простым.
*******************************************************************************
*/

/*!	\brief Долговременные параметры */
typedef struct
{
	u32 l;			/*!< битовая длина p */
	u32 r;			/*!< битовая длина q */
	octet p[308];	/*!< модуль p */
	octet q[33];	/*!< порядок q */
	octet a[308];	/*!< образующий a */
} stb99_params;

/*!	\brief Затравочные параметры */
typedef struct
{
	u16 zi[31];		/*!< числа zi */
	u32 di[18];		/*!< цепочка di */
	u32 ri[10];		/*!< цепочка ri */
	octet d[308];	/*!< число d */
} stb99_seed;

/*!	\brief Загрузка стандартных долговременных параметров

	В params загружаются стандартные долговременные параметры с именем name, 
	а в seed -- затравочные параметры, на которых получены params. Указатель
	seed может быть нулевым, и в этом случае затравочные параметры не загружаются.
	Поддерживаются следующие имена:
		"1.2.112.0.2.0.1176.2.3.3.1",
		"1.2.112.0.2.0.1176.2.3.6.1",
		"1.2.112.0.2.0.1176.2.3.10.1".
	Это имена стандартных параметров, заданных в таблице В.2 СТБ 34.101.50.
	Дополнительно поддерживается имя "test" тестовых параметров первого 
	уровня стойкости (l == 638).
	\return ERR_OK, если параметры успешно загружены, и код ошибки в
	противном случае.
*/
err_t stb99StdParams(
	stb99_params* params,	/*!< [out] стандартные параметры */
	stb99_seed* seed,		/*!< [out] затравочные параметры */
	const char* name		/*!< [in] имя параметров */
);

/*!	\brief Генерация долговременных параметров

	По затравочным параметрам seed генерируются долговременные параметры
	params.
	\return ERR_OK, если параметры успешно сгенерированы, и код ошибки
	в противном случае.
	\remark Реализованы алгоритмы 7.2, 7.3. В качестве d выбирается сначала 
	seed->d, а затем последовательные инкременты d до тех пор, пока среди них
	не встретится подходящий. Окончательное значение d возвращается в seed->d.
*/
err_t stb99GenParams(
	stb99_params* params,	/*!< [out] долговременные параметры */
	stb99_seed* seed		/*!< [in/out] затравочные параметры */
);

/*!	\brief Проверка долговременных параметров

	Проверяется, что долговременные параметры params корректны:
	-	размерности l и r согласованы и соответствуют определенному уровню 
		стойкости;
	-	p -- l-битовое простое число;
	-	q  -- r-битовое простое число;
	-	q | p - 1;
	-	0 < a < p;
	-	a имеет порядок q в группе B_p.
	.
	\return ERR_OK, если параметры корректны, и код ошибки в противном случае.
	\warning Не проверяется, что p и q построены по алгоритму 7.2.
*/
err_t stb99ValParams(
	const stb99_params* params	/*!< [in] долговременные параметры */
);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __BEE2_STB99_H */
