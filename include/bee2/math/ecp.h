/*
*******************************************************************************
\file ecp.h
\brief Elliptic curves over prime fields
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2012.06.24
\version 2014.04.17
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

/*!
*******************************************************************************
\file ecp.h
\brief Эллиптические кривые над простыми полями
*******************************************************************************
*/

#ifndef __BEE2_ECP_H
#define __BEE2_ECP_H

#include "bee2/math/ec.h"

#ifdef __cplusplus
extern "C" {
#endif

/*!
*******************************************************************************
\file ecp.h

Реализована арифметика эллиптических кривых над простым полем f = GF(p).
Кривая описывается уравнением Вейерштрасса
	E: y^2 = x^3 + Ax + B (\mod p).
E(GF(p)) -- множество аффинных точек E (решений E в GF(p)),
O -- бесконечно удаленная точка.

Поддерживаются якобиановы координаты (с помощью структуры ec_o) 
и аффинные координаты (прямые функции).

\pre Все указатели, передаваемые в функции, действительны.

\pre Буферы точек не пересекаются с буфером описания кривой.

\safe todo
*******************************************************************************
*/

/*
*******************************************************************************
Создание кривой
*******************************************************************************
*/

/*!	\brief Создание эллиптической кривой в якобиановых координатах

	Создается описание ec эллиптической кривой в якобиановых координатах
	над полем f с коэффициентами [f->no]A и [f->no]B.
	\return Признак успеха.
	\post ec->d == 3.
	\post Буферы ec->order и ec->base подготовлены для ecCreateGroup().
	\keep{ec} ecpCreateJ_keep(f->n).
	\deep{stack} ecpCreateJ_deep(f->n, f->deep).
*/
bool_t ecpCreateJ(
	ec_o* ec,			/*!< [in] описание кривой */
	const qr_o* f,		/*!< [in] базовое поле */
	const octet A[],	/*!< [in] коэффициент A */
	const octet B[],	/*!< [in] коэффициент B */
	void* stack			/*!< [in] вспомогательная память */
);

size_t ecpCreateJ_keep(size_t n);
size_t ecpCreateJ_deep(size_t n, size_t f_deep);

/*
*******************************************************************************
Свойства кривой и группы точек
*******************************************************************************
*/

/*!	\brief Корректное описание эллиптической кривой?

	Проверяется корректность описания ec эллиптической кривой. 
	Описание корректно, если:
	-	ecSeemsValid(ec) == TRUE;
	-	gfpIsValid(ec->f) == TRUE;
	-	A, B \in f;
	-	4 A^3 + 27 B^2 не делится на p (гладкость).
	.
	\return Признак корректности.
	\deep{stack} ecpIsValid_deep(ec->f->n, f->deep).
*/
bool_t ecpIsValid(
	const ec_o* ec,		/*!< [in] описание кривой */
	void* stack			/*!< [in] вспомогательная память */
);

size_t ecpIsValid_deep(size_t n, size_t f_deep);

/*!	\brief Описание группы точек эллиптической кривой выглядит корректным?

	Проверяется корректность описания группы точек эллиптической кривой ec.
	Описание корректно, если:
	-	ecIsOperableGroup(ec) == TRUE;
	-	|ec->order * ec->cofactor - (p + 1)| <= 2 * \sqrt{p} (границы Хассе);
	-	точка ec->base лежит на ec.
	.
	\pre Описание ec работоспособно.
	\return Признак корректности.
	\remark Не проверяется, что порядок ec->base равняется ec->order.
	\deep{stack} ecpSeemsValidGroup_deep(ec->f->n, ec->f->deep).
*/
bool_t ecpSeemsValidGroup(
	const ec_o* ec,		/*!< [in] описание кривой */
	void* stack			/*!< [in] вспомогательная память */
);

size_t ecpSeemsValidGroup_deep(size_t n, size_t f_deep);

/*!	\brief Надежная группа точек эллиптической кривой?

	Для группы точек кривой ec проверяются следующие условия, определяющие ее
	криптографическую надежность:
	-	ec->order -- простое;
	-	ec->order != p (условие Семаева);
	-	ec->order не делит числа p^i - 1, i <= mov_threshold (MOV).
	.
	\pre Описание ec (включая описание группы точек) работоспособно.
	\expect Описание ec (включая описание группы точек) корректно.
	\return Признак успеха проверки.
	\deep{stack} ecpIsSafeGroup_deep(ec->f->n).
*/
bool_t ecpIsSafeGroup(
	const ec_o* ec,			/*!< [in] описание кривой */
	size_t mov_threshold,	/*!< [in] MOV-порог */
	void* stack				/*!< [in] вспомогательная память */
);

size_t ecpIsSafeGroup_deep(size_t n);

/*
*******************************************************************************
Арифметика аффинных точек
*******************************************************************************
*/

/*!	\brief Аффинная точка лежит на кривой?

	Проверяется, что аффинная точка [2 * ec->f->n]a лежит на кривой ec.
	\pre Описание ec работоспособно.
	\expect Описание ec корректно.
	\return Признак успеха проверки.
	\deep{stack} ecpIsOnA_deep(ec->f->n, ec->f->deep).
*/
bool_t ecpIsOnA(
	const word a[],		/*!< [in] точка */
	const ec_o* ec,		/*!< [in] описание кривой */
	void* stack			/*!< [in] вспомогательная память */
);

size_t ecpIsOnA_deep(size_t n, size_t f_deep);

/*!	\brief Обратная аффинная точка

	Определяется аффинная точка [2 * ec->f->n]b кривой ec, обратная к аффинной 
	точке [2 * ec->f->n]a.
	\pre Описание ec работоспособно.
	\pre Координаты a лежат в базовом поле.
	\expect Описание ec корректно.
	\expect Точка a лежит на ec.
*/
void ecpNegA(
	word b[],			/*!< [out] обратная точка */
	const word a[],		/*!< [in] точка */
	const ec_o* ec		/*!< [in] описание кривой */
);

/*!	\brief Cложение аффинных точек

	Определяется сумма [2 * ec->f->n]c аффинных точек [2 * ec->f->n]a 
	и [2 * ec->f->n]b кривой ec:
	\code
		c <- a + b.
	\endcode
	\pre Описание ec работоспособно.
	\pre Координаты a и b лежат в базовом поле.
	\expect Описание ec корректно.
	\expect Точки a и b лежат на ec.
	\return TRUE, если сумма является аффинной точкой, и FALSE в противном
	случае.
	\deep{stack} ecpAddAA_deep(ec->f->n, ec->f->deep).
*/
bool_t ecpAddAA(
	word c[],			/*!< [out] сумма */
	const word a[],		/*!< [in] первое слагаемое */
	const word b[],		/*!< [in] второе слагаемое */
	const ec_o* ec,		/*!< [in] описание кривой */
	void* stack			/*!< [in] вспомогательная память */
);

size_t ecpAddAA_deep(size_t n, size_t f_deep);

/*!	\brief Вычитание аффинных точек

	Определяется разность [2 * ec->f->n]c аффинных точек [2 * ec->f->n]a 
	и [2 * ec->f->n]b эллиптической кривой ec:
	\code
		c <- a - b.
	\endcode
	\pre Описание ec работоспособно.
	\pre Координаты a и b лежат в базовом поле.
	\expect Описание ec корректно.
	\expect Точки a и b лежат на ec.
	\return TRUE, если разность является аффинной точкой, и FALSE в противном
	случае (a == b).
	\deep{stack} ecpSubAA_deep(n, ec->f->deep).
*/
bool_t ecpSubAA(
	word c[],			/*!< [out] разность */
	const word a[],		/*!< [in] уменьшаемое */
	const word b[],		/*!< [in] вычитаемое */
	const ec_o* ec,		/*!< [in] описание кривой */
	void* stack			/*!< [in] вспомогательная память */
);

size_t ecpSubAA_deep(size_t n, size_t f_deep);

/*!	\brief Преобразование элемента поля в аффинную точку

	Элемент [ec->f->n]a поля ec->f преобразуется в аффинную точку 
	[2 * ec->f->n]b эллиптической кривой ec.
	\pre Описание ec работоспособно.
	\pre a \in f && p \equiv 3 (\mod 4) && A != 0 && B != 0.
	\expect Описание ec корректно.
	\expect B -- квадратичный вычет по модулю p. Если это условие 
	нарушается, то точка b не будет лежать на ec для a \in {0, p - 1}.
	\remark Реализован алгоритм SWU в редакции СТБ 34.101.66.
	\deep{stack} ecpSWU_deep(ec->f->n, ec->f->deep).
*/
void ecpSWU(
	word b[],			/*!< [out] точка */
	const word a[],		/*!< [in] элемент поля */
	const ec_o* ec,		/*!< [in] описание кривой */
	void* stack			/*!< [in] вспомогательная память */
);

size_t ecpSWU_deep(size_t n, size_t f_deep);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __BEE2_ECP_H */
