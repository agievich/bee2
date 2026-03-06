/*
*******************************************************************************
\file bign256_test.c
\brief Tests for Bign256
\project bee2/test
\created 2026.03.06
\version 2026.03.06
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <bee2/core/mem.h>
#include <bee2/core/hex.h>
#include <bee2/core/prng.h>
#include <bee2/core/util.h>
#include <bee2/crypto/belt.h>
#include <bee2/crypto/bign256.h>

/*
*******************************************************************************
Самотестирование
*******************************************************************************
*/

bool_t bign256Test()
{
	bign_params params[1];
	octet privkey[64];
	octet pubkey[128];
	octet pubkey1[128];
	octet sig[96];
	octet token[20 + 16 + 64];
	mem_align_t state[64 / sizeof(mem_align_t)];
	// подготовить память
	if (sizeof(state) < prngCOMBO_keep())
		return FALSE;
	// инициализировать ГПСЧ
	prngCOMBOStart(state, 20);
	// загрузить параметры
	if (bignParamsStd(params, "1.2.112.0.2.0.34.101.45.3.3") != ERR_OK)
		return FALSE;
	// упрвление ключами
	if (bign256KeypairGen(privkey, pubkey, prngCOMBOStepR, state) != ERR_OK ||
		bign256KeypairVal(privkey, pubkey) != ERR_OK ||
		bign256PubkeyVal(pubkey) != ERR_OK ||
		bign256PubkeyCalc(pubkey1, privkey) != ERR_OK ||
		!memEq(pubkey, pubkey1, 128))
		return FALSE;
	memSetZero(pubkey1, 64);
	memCopy(pubkey1 + 64, params->yG, 64);
	if (bign256DH(pubkey1, privkey, pubkey1, 128) != ERR_OK ||
		!memEq(pubkey, pubkey1, 128))
		return FALSE;
	// ЭЦП
	if (bign256Sign(sig, beltH(), privkey, prngCOMBOStepR, state) != ERR_OK ||
		bign256Verify(beltH(), sig, pubkey) != ERR_OK ||
		bign256Sign2(sig, beltH(), privkey, 0, 0) != ERR_OK ||
		bign256Verify(beltH(), sig, pubkey) != ERR_OK)
		return FALSE;
	// транспорт ключа
	if (bign256KeyWrap(token, beltH(), 20, beltH() + 32, pubkey, prngCOMBOStepR,
			state) != ERR_OK ||
		bign256KeyUnwrap(token, token, 20 + 16 + 64, beltH() + 32, 
			privkey) != ERR_OK ||
		!memEq(token, beltH(), 20))
		return FALSE;
	// все нормально
	return TRUE;
}
