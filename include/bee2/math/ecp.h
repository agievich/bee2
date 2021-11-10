/*
*******************************************************************************
\file ecp.h
\brief Elliptic curves over prime fields
\project bee2 [cryptographic library]
\created 2012.06.24
\version 2021.07.29
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

Поддерживаются якобиевы координаты (с помощью структуры ec_o) 
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

/*!	\brief Создание эллиптической кривой в якобиевых координатах

	Создается описание ec эллиптической кривой в якобиевых координатах
	над полем f с коэффициентами [f->no]A и [f->no]B.
	\return Признак успеха.
	\pre gfpIsOperable(f) == TRUE.
	\expect{FALSE} f->mod > 3.
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
	-	ec->f->mod > 3;
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
	-	|ec->order * ec->cofactor - (p + 1)| <= 2 * \sqrt(p) (границы Хассе);
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

/*!	\brief Удвоение проективной и вычитание/сложение с аффинной точкой

	На эллиптической кривой ec определяется точка [ec->d * ec->f->n]с,
	полученная удвоением точки [3 * ec->f->n]a и сложением с точкой ((-1) ^ (1 + neg_b)) * [2 * ec->f->n]b:
	\code
		c <- 2 a + ((-1) ^ (1 + neg_b)) b.
	\endcode
	\pre Описание ec работоспособно.
	\pre Буфер c либо не пересекается, либо совпадает с буфером a.
	\pre Буферы a и b не пересекается.
	\pre Буферы b и c не пересекается.
	\pre Координаты a и b лежат в базовом поле.
	\expect Описание ec корректно.
	\expect Точки a и b лежат на кривой.
	\expect Точки a и b не равны.
*/
void ecpDblAddA(
	word c[],				/*!< [out] результат удвоения и сложения */
	const word a[],			/*!< [in] первоначальная точка 1 */
	const word b[],			/*!< [in] первоначальная точка 2 */
	bool_t neg_b,			/*!< [in] флаг вычитания/сложения с точкой b */
	const struct ec_o* ec,	/*!< [in] описание эллиптической кривой */
	void* stack				/*!< [in] вспомогательная память */
);

size_t ecpDblAddA_deep(size_t n, size_t f_deep);

/*!	\brief Условное аддитивное обращение аффинной точки

	На эллиптической кривой ec определяется точка [2 * ec->f->n]b,
	полученная умножением точки [2 * ec->f->n]a на выражение ((-1) ^ (1 + neg))
	\code
		b <- ((-1) ^ (1 + neg_b)) a.
	\endcode
	\pre Описание ec работоспособно.
	\pre Буфер b либо не пересекается, либо совпадает с буфером a.
	\pre Координаты a и b лежат в базовом поле.
	\expect Описание ec корректно.
	\expect Точка a лежит на кривой.
*/
void ecpSetSignA(
	word b[],				/*!< [out] результат условного аддитивного обращения */
	const word a[],			/*!< [in] первоначальная точка */
	bool_t neg,				/*!< [in] флаг отрицательности */
	const struct ec_o* ec	/*!< [in] описание эллиптической кривой */
);

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

/*!	\brief Расчет малых нечетных кратных в якобиевых координатах

	Для i \in \{1,2,\ldots,2^{w-1}-1\} определяются кратности (2i+1) a
	аффинной точки [2 * ec->f->n]a кривой ec:
	\code
		da <- 2 a
		c[i] <- (2i+1) a.
	\endcode
	Кратности помещаются в буфер [(2^{w-1}-1) * 3 * ec->f->n]c.
	\pre Описание ec работоспособно.
	\pre Координата a лежит в базовом поле.
	\expect Описание ec корректно.
	\expect Точка a лежит на ec.
	\deep{stack} ecpOddSmall_deep(w, ec->f->n, ec->f->deep).
	\safe Алгоритм регулрен.
*/
void ecpSmallMultDivpJ(
	word c[],			/*!< [out] кратные якобиевы точки */
	word da[],			/*!< [out] удвоенная якобиева точка */
	const word a[],		/*!< [in] аффинная точка */
	const size_t w,		/*!< [in] ширина окна */
	const ec_o* ec,		/*!< [in] описание кривой */
	void* stack			/*!< [in] вспомогательная память */
);

size_t ecpSmallMultDivpJ_deep(bool_t da, const size_t w, size_t n, size_t f_deep);

/*!	\brief Расчет малых нечетных кратных в аффинных координатах

	Для i \in \{1,2,\ldots,2^{w-1}-1\} определяются кратности (2i+1) a
	аффинной точки [2 * ec->f->n]a кривой ec:
	\code
		c[i] <- (2i+1) a.
	\endcode
	Кратности помещаются в буфер [(2^{w-1}-1) * 2 * ec->f->n]c.
	\pre Описание ec работоспособно.
	\pre Координата a лежит в базовом поле.
	\expect Описание ec корректно.
	\expect Точка a лежит на ec.
	\deep{stack} ecpOddSmall_deep(w, ec->f->n, ec->f->deep).
	\safe Алгоритм регулрен.
*/
void ecpSmallMultA(
	word* c,				/*!< [out] линейный массив нечетных малых кратных (2i-1)[2n]a для i=1,2^{w-1} в аффинных координатах */
	const word a[],			/*!< [in] базовая точка в аффинных координатах */
	const size_t w,			/*!< [in] размер окна, число точек в массиве есть 2^{w-1} */
	const struct ec_o* ec,	/*!< [in] описание эллиптической кривой */
	void* stack				/*!< [in] вспомогательная память */
);

size_t ecpSmallMultA_deep(const size_t w, size_t n, size_t f_deep);

void ecpSmallMultJ(
	word* c,				/*!< [out] линейный массив нечетных малых кратных (2i-1)[2n]a для i=1,2^{w-1} в якобиевых координатах */
	const word a[],			/*!< [in] базовая точка в аффинных координатах */
	const size_t w,			/*!< [in] размер окна, число точек в массиве есть 2^{w-1} */
	const struct ec_o* ec,	/*!< [in] описание эллиптической кривой */
	void* stack				/*!< [in] вспомогательная память */
);

size_t ecpSmallMultJ_deep(const size_t w, size_t n, size_t f_deep);

/*
*******************************************************************************
Complete формулы
*******************************************************************************

Реализованы алгоритмы 1 и 2 из https://eprint.iacr.org/2015/1060.pdf

Результирующая точка c в однородных координатах.
Для перевода в аффинные или якобиевые координаты необходимо использовать
ecpHToA или ecpHToJ

TODO: реализовать алгоритмы для ec->A == -3
TODO: добавить ecpHToA_deep или ecpHToA_deep в ecpCreateJ_deep чтобы учитывалось в ec_deep, либо передавать f_deep в ecMulA_deep
TODO: вынести в отдельный файл?
*/

/*!	\brief Перевод якобиевых координат в однородные

  [3n]с <- [3n]a (H <- J)
*/
void ecpJToH(
	word* c,				/*!< [out] точка в однородных координатах [3n] */
	const word a[],	/*!< [in] точка в якобиевых координатах [3n] */
	const struct ec_o* ec,	/*!< [in] описание эллиптической кривой */
	void* stack				/*!< [in] вспомогательная память */
);

size_t ecpJToH_deep(size_t f_deep);

/*!	\brief Перевод однородных координат в аффинные

  [2n]b <- [3n]a (A <- H)

  \todo регуляризовать, так как используется в SAFE(ecMulA)
*/
bool_t ecpHToA(word b[], const word a[], const ec_o* ec, void* stack);

size_t ecpHToA_deep(size_t n, size_t f_deep);


/*!	\brief Перевод однородных координат в якобиевы

  [3n]b <- [3n]a (J <- H)
*/
bool_t ecpHToJ(word b[], const word a[], const ec_o* ec, void* stack);

size_t ecpHToJ_deep(size_t n, size_t f_deep);

/*!	\brief Сложение точек в якобиевых и получение результата в аффинных координатах

	Точки a и b могут быть нулевыми или равными, сумма a+b не может быть нулевой:
  [2n]с <- [3n]a + [3n]b (A <- J+J)

	Реализован алгоритм 1 из https://eprint.iacr.org/2015/1060.pdf
	\pre a+b -- не нулевая точка
	\pre буфферы с,a,b совпадают или не пересекаются
*/
void ecpAddAJJ_complete(word* c, const word a[], const word b[], const ec_o* ec, void* stack);

size_t ecpAddAJJ_complete_deep(size_t n, size_t f_deep);

/*!	\brief Сложение точек в якобиевых и аффинных и получение результата в аффинных координатах

	Точка a может быть нулевой или равной b, сумма a+b не может быть нулевой:
  [2n]с <- [3n]a + [2n]b (A <- J+A)

	Реализован алгоритм 2 из https://eprint.iacr.org/2015/1060.pdf
	\pre a+b -- не нулевая точка
	\pre буфферы с,a,b совпадают или не пересекаются
*/
void ecpAddAJA_complete(word* c, const word a[], const word b[], const ec_o* ec, void* stack);

size_t ecpAddAJA_complete_deep(size_t n, size_t f_deep);

/*
*******************************************************************************
Smult
*******************************************************************************
*/

size_t ecpMulAWidth(const size_t l);

/*!	\brief Кратная точка

	Определяется аффинная точка [2 * ec->f->n]b эллиптической кривой ec,
	которая является [m]d-кратной аффинной точки [2 * ec->f->n]a:
	\code
		b <- d a.
	\endcode
	Предвычисленные аффинные малце кратные точки [2 * ec->f->n]a указываются в 
	[2^w * 2 * ec->f->n]c в следующем порядке:
	[1-2^w]a, [3-2^w]a, .., [-1]a, [1]a, [3]a, .., [2^w-1]a,

	\pre Описание ec работоспособно.
	\pre Координаты a лежат в базовом поле.
	\pre 3 <= w && w + 1 < B_PER_W
	\pre m не превосходит размера порядка кривой (ec->f->n+1).
	\expect Описание ec корректно.
	\expect Точка a лежит на ec.
	\return TRUE, если кратная точка является аффинной, и FALSE в противном
	случае (b == O).
	\safe Вычисления регулярные.
	\deep{stack} ecpMulA_deep(ec->f->n, ec->d, ec->f->deep, m).
*/
bool_t ecpMulA1(word b[], const word a[], const ec_o* ec, const word d[],
	size_t m, const word c[], word w, void* stack);

size_t ecpMulA1_deep(size_t n, size_t f_deep, size_t ec_d, size_t ec_deep, size_t m);

bool_t ecpMulA(word b[], const word a[], const ec_o* ec, const word d[], size_t m, void* stack);

size_t ecpMulA_deep(size_t n, size_t f_deep, size_t ec_d, size_t ec_deep, size_t ec_order_len);

size_t ecpMulJWidth(const size_t l);

bool_t ecpMulAJ1(word b[], const word a[], const ec_o* ec, const word d[],
	size_t m, const word precomp_j[], word precomp_w, void* stack);

size_t ecpMulAJ1_deep(size_t n, size_t f_deep, size_t ec_d, size_t ec_deep, size_t m);

bool_t ecpMulAJ(word b[], const word a[], const ec_o* ec, const word d[],
	size_t m, void* stack);

size_t ecpMulAJ_deep(size_t n, size_t f_deep, size_t ec_d, size_t ec_deep, size_t ec_order_len);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __BEE2_ECP_H */
