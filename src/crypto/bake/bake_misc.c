/*
*******************************************************************************
\file bake_misc.c
\brief STB 34.101.66 (bake): miscellaneous (curves, KDF)
\project bee2 [cryptographic library]
\created 2014.04.14
\version 2025.09.25
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/core/blob.h"
#include "bee2/core/err.h"
#include "bee2/core/mem.h"
#include "bee2/core/obj.h"
#include "bee2/core/util.h"
#include "bee2/crypto/bake.h"
#include "bee2/crypto/belt.h"
#include "bee2/math/ecp.h"
#include "bee2/math/gfp.h"
#include "bee2/math/ww.h"
#include "bee2/math/zz.h"
#include "../bign/bign_lcl.h"
#include "bake_lcl.h"

/*
*******************************************************************************
Эллиптическая кривая
*******************************************************************************
*/

err_t bakeEcStart(void* state, const bign_params* params)
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
	ASSERT(bignParamsCheck(params) == ERR_OK);
	ASSERT(memIsValid(state, bakeEcStart_keep(params->l, 0)));
	// определить размерности
	no = O_OF_B(2 * params->l);
	n = W_OF_B(2 * params->l);
	f_keep = gfpCreate_keep(no);
	ec_keep = ecpCreateJ_keep(n);
	// разметить память
	memSlice(state,
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
		!ecGroupCreate(ec, 0, params->yG, params->q, no, 1, stack))
		return ERR_BAD_PARAMS;
	ASSERT(wwBitSize(ec->order, n) == params->l * 2);
	ASSERT(zzIsOdd(ec->order, n));
	// присоединить f к ec
	objAppend(ec, f, 0);
	// все нормально
	return ERR_OK;
}

size_t bakeEcStart_keep(size_t l, bake_ec_deep_i deep)
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
	return memSliceSize(
		ec_keep,
		f_keep,
		utilMax(3,
			ec_deep,
			ecGroupCreate_deep(f_deep),
			deep ? deep(n, f_deep, ec_d, ec_deep) : 0),
		SIZE_MAX);
}

/*
*******************************************************************************
Алгоритм bakeKDF
*******************************************************************************
*/

err_t bakeKDF(octet key[32], const octet secret[], size_t secret_len, 
	const octet iv[], size_t iv_len, size_t num)
{
	void* state;
	octet* block;		/* [16] */
	void* stack;
	// проверить входные данные
	if (!memIsValid(secret, secret_len) ||
		!memIsValid(iv, iv_len) ||
		!memIsValid(key, 32))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate2( 
		(size_t)16, 
		utilMax(2,
			beltHash_keep(), 
			beltKRP_keep()), 
		SIZE_MAX, 
		&block, &stack);
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// key <- beltHash(secret || iv)
	beltHashStart(stack);
	beltHashStepH(secret, secret_len, stack);
	beltHashStepH(iv, iv_len, stack);
	beltHashStepG(key, stack);
	// key <- beltKRP(Y, 1^96, num)
	memSet(block, 0xFF, 12);
	beltKRPStart(stack, key, 32, block);
	CASSERT(B_PER_S <= 128);
	memCopy(block, &num, sizeof(size_t));
#if (OCTET_ORDER == BIG_ENDIAN)
	memRev(block, sizeof(size_t));
#endif
	memSetZero(block + sizeof(size_t), 16 - sizeof(size_t));
	beltKRPStepG(key, 32, block, stack);
	// завершить
	blobClose(state);
	return ERR_OK;
}
