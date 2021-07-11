/*
*******************************************************************************
\file gfp.h
\brief Prime fields
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2012.07.11
\version 2014.04.17
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

/*!
*******************************************************************************
\file gfp.h
\brief Простые поля
*******************************************************************************
*/

#ifndef __BEE2_GFP_H
#define __BEE2_GFP_H

#include "bee2/math/zm.h"

#ifdef __cplusplus
extern "C" {
#endif

/*!
*******************************************************************************
\file gfp.h

Реализованы операции в простом конечном поле GF(p), p -- нечетное простое 
число. Элементы поля интерпретируются как элементы кольца вычетов 
Zm = Z / (mod), mod = p. 

Наследуются соглашения для Zm, определенные в заголовочном файле zm.h. 

\pre Все указатели, передаваемые в функции, действительны.

\safe todo
*******************************************************************************
*/

/*
*******************************************************************************
Управление описанием поля
*******************************************************************************
*/

/*!	\brief Создание описания простого поля

	По модулю [no]p, заданному строкой октетов, создается описание f 
	поля GF(p). Подбирается оптимальное (с точки зрения эффективности 
	вычислений) описание поля.
	\expect p -- нечетное простое.
	\return Признак успеха.
	\post f->no == no и f->n == W_OF_O(no).
	\keep{f} gfpCreate_keep(no).
	\deep{stack} gfpCreate_deep(no).
*/
bool_t gfpCreate(
	qr_o* f,			/*!< [out] описание поля */
	const octet p[],	/*!< [in] модуль */
	size_t no,			/*!< [in] длина p в октетах */
	void* stack			/*!< [in] вспомогательная память */
);

size_t gfpCreate_keep(size_t no);
size_t gfpCreate_deep(size_t no);

/*!	\brief Работоспособное описание простого поля?

	Проверяется работоспособность описания f поля GF(p). Проверяются 
	следующие условия:
	-	zmIsOperable(f) == TRUE;
	-	f->mod -- нечетное, большее 1.
	.
	\return Признак корректности.
*/
bool_t gfpIsOperable(
	const qr_o* f		/*!< [in] описание поля */
);

/*!	\brief Корректное описание простого поля?

	Проверяется корректность описания f поля GF(p). Проверяются 
	следующие условия: 
	-	gfpIsOperable(f) == TRUE;
	-	f->mod -- простое.
	.
	\return Признак корректности.
	\deep{stack} gfpIsValid_deep(f->n).
*/
bool_t gfpIsValid(
	const qr_o* f,		/*!< [in] описание поля */
	void* stack			/*!< [in] вспомогательная память */
);

size_t gfpIsValid_deep(size_t n);

/*
*******************************************************************************
Псевдонимы
*******************************************************************************
*/

#define gfpDouble(b, a, f)\
	zzDoubleMod(b, a, (f)->mod, (f)->n)

#define gfpHalf(b, a, f)\
	zzHalfMod(b, a, (f)->mod, (f)->n)

#define gfpMul2(c, a, b, a2, b2, f, stack)\
	do {\
		qrAdd(c, a, b, f);\
		qrSqr(c, c, f, stack);\
		qrSub(c, c, a2, f);\
		qrSub(c, c, b2, f);\
		gfpHalf(c, c, f);\
	} while(0)

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __BEE2_GFP_H */
