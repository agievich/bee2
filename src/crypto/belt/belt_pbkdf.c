/*
*******************************************************************************
\file belt_pbkdf.c
\brief STB 34.101.31 (belt): PBKDF (password-based key derivation)
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2012.12.18
\version 2017.09.28
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
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
	// проверить входные данные
	if (iter == 0 ||
		!memIsValid(pwd, pwd_len) ||
		!memIsValid(salt, salt_len) ||
		!memIsValid(key, 32))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(beltHMAC_keep() + 32);
	if (state == 0)
		return ERR_OUTOFMEMORY;
	t = (octet*)state + beltHMAC_keep();
	// key <- HMAC(pwd, salt || 00000001)
	beltHMACStart(state, pwd, pwd_len);
	beltHMACStepA(salt, salt_len, state);
	*(u32*)key = 0, key[3] = 1;
	beltHMACStepA(key, 4, state);
	beltHMACStepG(key, state);
	// пересчитать key
	memCopy(t, key, 32);
	while (--iter)
	{
		beltHMACStart(state, pwd, pwd_len);
		beltHMACStepA(t, 32, state);
		beltHMACStepG(t, state);
		memXor2(key, t, 32);
	}
	// завершить
	blobClose(state);
	return ERR_OK;
}
