/*
*******************************************************************************
\file belt_pbkdf.c
\brief STB 34.101.31 (belt): PBKDF (password-based key derivation)
\project bee2 [cryptographic library]
\created 2012.12.18
\version 2017.09.15
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
	octet* t;			/* [32] */
	void* hmac_state;	/* [beltHMAC_keep()] состояние после обработки pwd */
	void* hmac_state1;	/* [beltHMAC_keep()] рабочая копия hmac_state */
	// проверить входные данные
	if (iter == 0 ||
		!memIsValid(pwd, pwd_len) ||
		!memIsValid(salt, salt_len) ||
		!memIsValid(key, 32))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate2(
		(size_t)32,
		beltHMAC_keep(),
		beltHMAC_keep(),
		SIZE_MAX,
		&t, &hmac_state, &hmac_state1);
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// key <- HMAC(pwd, salt || 00000001)
	beltHMACStart(hmac_state, pwd, pwd_len);
	memCopy(hmac_state1, hmac_state, beltHMAC_keep());
	beltHMACStepA(salt, salt_len, hmac_state1);
	*(u32*)key = 0, key[3] = 1;
	beltHMACStepA(key, 4, hmac_state1);
	beltHMACStepG(key, hmac_state1);
	// пересчитать key
	memCopy(t, key, 32);
	while (--iter)
	{
		memCopy(hmac_state1, hmac_state, beltHMAC_keep());
		beltHMACStepA(t, 32, hmac_state1);
		beltHMACStepG(t, hmac_state1);
		memXor2(key, t, 32);
	}
	// завершить
	blobClose(state);
	return ERR_OK;
}
