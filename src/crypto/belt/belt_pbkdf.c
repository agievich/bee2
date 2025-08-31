/*
*******************************************************************************
\file belt_pbkdf.c
\brief STB 34.101.31 (belt): PBKDF (password-based key derivation)
\project bee2 [cryptographic library]
\created 2012.12.18
\version 2017.08.31
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/core/blob.h"
#include "bee2/core/err.h"
#include "bee2/core/mem.h"
#include "bee2/crypto/belt.h"

/*
*******************************************************************************
Построение ключа по паролю
*******************************************************************************
*/

err_t beltPBKDF2(octet key[32], const octet pwd[], size_t pwd_len,
	size_t iter, const octet salt[], size_t salt_len)
{
	void* state;
	octet* t;
	void* stack;
	// проверить входные данные
	if (iter == 0 ||
		!memIsValid(pwd, pwd_len) ||
		!memIsValid(salt, salt_len) ||
		!memIsValid(key, 32))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate2(
		(size_t)32, &t,
		beltHMAC_keep(), &stack,
		SIZE_MAX);
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// key <- HMAC(pwd, salt || 00000001)
	beltHMACStart(stack, pwd, pwd_len);
	beltHMACStepA(salt, salt_len, stack);
	*(u32*)key = 0, key[3] = 1;
	beltHMACStepA(key, 4, stack);
	beltHMACStepG(key, stack);
	// пересчитать key
	memCopy(t, key, 32);
	while (--iter)
	{
		beltHMACStart(stack, pwd, pwd_len);
		beltHMACStepA(t, 32, stack);
		beltHMACStepG(t, stack);
		memXor2(key, t, 32);
	}
	// завершить
	blobClose(state);
	return ERR_OK;
}
