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
Создание / закрытие эллиптической кривой
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
	ASSERT(params->l == 128 || params->l == 192  || params->l == 256);
	ASSERT(memIsValid(state, bignStart_keep(params->l, 0)));
	// определить размерности
	no = O_OF_B(2 * params->l);
	n = W_OF_B(2 * params->l);
	f_keep = gfpCreate_keep(no);
	ec_keep = ecpCreateJ_keep(n);
	// создать поле и выполнить минимальные проверки p
	f = (qr_o*)((octet*)state + ec_keep);
	stack = (octet*)f + f_keep;
	if (!gfpCreate(f, params->p, no, stack) ||
		wwBitSize(f->mod, n) != params->l * 2 ||
		wwGetBits(f->mod, 0, 2) != 3)
		return ERR_BAD_PARAMS;
	// создать кривую и группу, выполнить минимальную проверку order
	ec = (ec_o*)state;
	if (!ecpCreateJ(ec, f, params->a, params->b, stack) ||
		!ecCreateGroup(ec, 0, params->yG, params->q, no, 1, stack) ||
		wwBitSize(ec->order, n) != params->l * 2 ||
		zzIsEven(ec->order, n))
		return ERR_BAD_PARAMS;
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

