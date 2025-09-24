/*
*******************************************************************************
\file bake_kdf.c
\brief STB 34.101.66 (bake): KDF
\project bee2 [cryptographic library]
\created 2014.04.14
\version 2025.09.24
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
#include "bee2/math/qr.h"
#include "bee2/math/ecp.h"
#include "bee2/math/ww.h"
#include "bee2/math/zz.h"
#include "../bign/bign_lcl.h"

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
