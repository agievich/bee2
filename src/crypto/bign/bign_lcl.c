/*
*******************************************************************************
\file bign_lcl.c
\brief STB 34.101.45 (bign): local definitions
\project bee2 [cryptographic library]
\created 2012.04.27
\version 2025.09.04
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/core/err.h"
#include "bee2/core/blob.h"
#include "bee2/core/mem.h"
#include "bee2/core/util.h"
#include "bee2/math/gfp.h"
#include "bee2/math/ecp.h"
#include "bee2/math/ww.h"
#include "bee2/math/zz.h"
#include "bign_lcl.h"

/*
*******************************************************************************
Проверка работоспособности
*******************************************************************************
*/

bool_t bignParamsAreOperable(const bign_params* params)
{
	size_t no;
	// pre
	ASSERT(memIsValid(params, sizeof(bign_params)));
	// корректный уровень стойкости?
	// p mod 4 == 3? q mod 2 == 1?
	// p и q -- 2l-битовые?
	// a != 0? b != 0?
	// неиспользуемые октеты обнулены?
	return
		(params->l == 128 || params->l == 192 || params->l == 256) &&
		(no = O_OF_B(2 * params->l)) &&
		params->p[0] % 4 == 3 && params->q[0] % 2 == 1 &&
		params->p[no - 1] >= 128 && params->q[no - 1] >= 128 &&
		memIsZero(params->p + no, sizeof(params->p) - no) &&
		!memIsZero(params->a, no) &&
		!memIsZero(params->b, no) &&
		memIsZero(params->a + no, sizeof(params->a) - no) &&
		memIsZero(params->b + no, sizeof(params->b) - no) &&
		memIsZero(params->q + no, sizeof(params->q) - no) &&
		memIsZero(params->yG + no, sizeof(params->yG) - no);
}

/*
*******************************************************************************
Создание эллиптической кривой
*******************************************************************************
*/

err_t bignStart(void* state, const bign_params* params)
{
	// размерности
	size_t no, n;
	size_t f_keep;
	size_t ec_keep;
	// состояние
	ec_o* ec;		/* кривая */
	qr_o* f;		/* поле */
	void* stack;	/* вложенный стек */
	// pre
	ASSERT(memIsValid(params, sizeof(bign_params)));
	ASSERT(bignParamsAreOperable(params));
	ASSERT(memIsValid(state, bignStart_keep(params->l, 0)));
	// определить размерности
	no = O_OF_B(2 * params->l);
	n = W_OF_B(2 * params->l);
	f_keep = gfpCreate_keep(no);
	ec_keep = ecpCreateJ_keep(n);
	// разметить память
	(void)memSlice(state,
		ec_keep,
		f_keep,
		SIZE_0,
		SIZE_MAX,
		&ec, &f, &stack);
	// создать поле
	if (!gfpCreate(f, params->p, no, stack))
		return ERR_BAD_PARAMS;
	ASSERT(wwBitSize(f->mod, n) == params->l * 2);
	ASSERT(wwGetBits(f->mod, 0, 2) == 3);
	// создать кривую и группу
	if (!ecpCreateJ(ec, f, params->a, params->b, stack) ||
		!ecCreateGroup(ec, 0, params->yG, params->q, no, 1, stack))
		return ERR_BAD_PARAMS;
	ASSERT(wwBitSize(ec->order, n) == params->l * 2);
	ASSERT(zzIsOdd(ec->order, n));
	// присоединить f к ec
	objAppend(ec, f, 0);
	// все нормально
	return ERR_OK;
}

size_t bignStart_keep(size_t l, bign_deep_i deep)
{
	// размерности
	size_t no = O_OF_B(2 * l);
	size_t n = W_OF_B(2 * l);
	size_t f_keep = gfpCreate_keep(no);
	size_t f_deep = gfpCreate_deep(no);
	size_t ec_d = 3;
	size_t ec_keep = ecpCreateJ_keep(n);
	size_t ec_deep = ecpCreateJ_deep(n, f_deep);
	// расчет
	return memSlice(0,
		ec_keep,
		f_keep,
		utilMax(3,
			ec_deep,
			ecCreateGroup_deep(f_deep),
			deep ? deep(n, f_deep, ec_d, ec_deep) : 0),
		SIZE_MAX);
}


/*
*******************************************************************************
Создание / закрытие эллиптической кривой
*******************************************************************************
*/

err_t bignEcCreate(ec_o** pec, const bign_params* params)
{
	size_t no, n;
	size_t f_deep;
	// состояние
	void* state; 
	ec_o* ec;		/* кривая */
	qr_o* f;		/* поле */
	void* stack;
	// pre
	ASSERT(memIsValid(pec, sizeof(*pec)));
	// входной контроль
	if (!memIsValid(params, sizeof(bign_params)))
		return ERR_BAD_INPUT;
	if (!bignParamsAreOperable(params))
		return ERR_BAD_PARAMS;
	// определить размерности
	no = O_OF_B(2 * params->l);
	n = W_OF_B(2 * params->l);
	f_deep = gfpCreate_deep(no);
	// создать состояние
	state = blobCreate2(
		ecpCreateJ_keep(n),
		gfpCreate_keep(no),
		SIZE_MAX,
		&ec, &f);
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// создать стек
	stack = blobCreate(
		utilMax(3,
			gfpCreate_deep(no),
			ecpCreateJ_deep(n, f_deep),
			ecCreateGroup_deep(f_deep)));
	if (stack == 0)
	{
		blobClose(state);
		return ERR_OUTOFMEMORY;
	}
	// создать поле, кривую и группу
	if (!gfpCreate(f, params->p, no, stack) ||
		!ecpCreateJ(ec, f, params->a, params->b, stack) ||
		!ecCreateGroup(ec, 0, params->yG, params->q, no, 1, stack))
	{
		blobClose(state);
		blobClose(stack);
		return ERR_BAD_PARAMS;
	}
	ASSERT(wwBitSize(f->mod, n) == params->l * 2);
	ASSERT(wwGetBits(f->mod, 0, 2) == 3);
	ASSERT(wwBitSize(ec->order, n) == params->l * 2);
	ASSERT(zzIsOdd(ec->order, n));
	// присоединить f к ec
	objAppend(ec, f, 0);
	// завершение
	blobClose(stack);
	*pec = ec;
	return ERR_OK;
}

void bignEcClose(ec_o* ec)
{
	blobClose(ec);
}
