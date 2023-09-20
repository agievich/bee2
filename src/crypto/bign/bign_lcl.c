/*
*******************************************************************************
\file bign_lcl.c
\brief STB 34.101.45 (bign): local definitions
\project bee2 [cryptographic library]
\created 2012.04.27
\version 2023.09.19
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/core/err.h"
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

bool_t bignIsOperable(const bign_params* params)
{
	size_t no;
	// pre
	ASSERT(memIsValid(params, sizeof(bign_params)));
	// корректный уровень стойкости?
	// p mod 4 == 3? q mod 2 == 1?
	// p и q -- 2l-битовые?
	// неиспользуемые октеты обнулены?
	return
		(params->l == 128 || params->l == 192 || params->l == 256) &&
		(no = O_OF_B(2 * params->l)) &&
		params->p[0] % 4 == 3 && params->q[0] % 2 == 1 &&
		params->p[no - 1] >= 128 && params->q[no - 1] >= 128 &&
		memIsZero(params->p + no, sizeof(params->p) - no) &&
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
	qr_o* f;		/* поле */
	ec_o* ec;		/* кривая */
	void* stack;	/* вложенный стек */
	// pre
	ASSERT(memIsValid(params, sizeof(bign_params)));
	ASSERT(bignIsOperable(params));
	ASSERT(memIsValid(state, bignStart_keep(params->l, 0)));
	// определить размерности
	no = O_OF_B(2 * params->l);
	n = W_OF_B(2 * params->l);
	f_keep = gfpCreate_keep(no);
	ec_keep = ecpCreateJ_keep(n);
	// создать поле
	f = (qr_o*)((octet*)state + ec_keep);
	stack = (octet*)f + f_keep;
	if (!gfpCreate(f, params->p, no, stack))
		return ERR_BAD_PARAMS;
	ASSERT(wwBitSize(f->mod, n) == params->l * 2);
	ASSERT(wwGetBits(f->mod, 0, 2) == 3);
	// создать кривую и группу
	ec = (ec_o*)state;
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
	return f_keep + ec_keep +
		utilMax(3,
			ec_deep,
			ecCreateGroup_deep(f_deep),
			deep ? deep(n, f_deep, ec_d, ec_deep) : 0);
}

