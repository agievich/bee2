/*
*******************************************************************************
\file bign_ec.c
\brief STB 34.101.45 (bign): curves
\project bee2 [cryptographic library]
\created 2012.04.27
\version 2025.09.15
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
Создание эллиптической кривой
*******************************************************************************
*/

err_t bignEcCreate(ec_o** pec, const bign_params* params)
{
	size_t no, n;
	size_t f_deep;
	void* state; 
	ec_o* ec;		/* [ecpCreateJ_keep(n)] */
	qr_o* f;		/* [gfpCreate_keep(no)] */
	void* stack;
	// pre
	ASSERT(memIsValid(pec, sizeof(*pec)));
	ASSERT(bignParamsCheck2(params) == ERR_OK);
	// размерности
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
			ecGroupCreate_deep(f_deep)));
	if (stack == 0)
	{
		blobClose(state);
		return ERR_OUTOFMEMORY;
	}
	// создать поле, кривую и группу
	if (!gfpCreate(f, params->p, no, stack) ||
		!ecpCreateJ(ec, f, params->a, params->b, stack) ||
		!ecGroupCreate(ec, 0, params->yG, params->q, no, 1, stack))
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

/*
*******************************************************************************
Закрытие эллиптической кривой
*******************************************************************************
*/

void bignEcClose(ec_o* ec)
{
	blobClose(ec);
}

