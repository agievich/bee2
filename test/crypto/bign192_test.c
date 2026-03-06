/*
*******************************************************************************
\file bign192_test.c
\brief Tests for Bign192
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
#include <bee2/crypto/bign192.h>

/*
*******************************************************************************
Самотестирование
*******************************************************************************
*/

bool_t bign192Test()
{
	bign_params params[1];
	octet privkey[48];
	octet pubkey[96];
	octet pubkey1[96];
	octet sig[72];
	octet token[19 + 16 + 48];
	mem_align_t state[64 / sizeof(mem_align_t)];
	// подготовить память
	if (sizeof(state) < prngCOMBO_keep())
		return FALSE;
	// инициализировать ГПСЧ
	prngCOMBOStart(state, 19);
	// загрузить параметры
	if (bignParamsStd(params, "1.2.112.0.2.0.34.101.45.3.2") != ERR_OK)
		return FALSE;
	// упрвление ключами
	if (bign192KeypairGen(privkey, pubkey, prngCOMBOStepR, state) != ERR_OK ||
		bign192KeypairVal(privkey, pubkey) != ERR_OK ||
		bign192PubkeyVal(pubkey) != ERR_OK ||
		bign192PubkeyCalc(pubkey1, privkey) != ERR_OK ||
		!memEq(pubkey, pubkey1, 96))
		return FALSE;
	memSetZero(pubkey1, 48);
	memCopy(pubkey1 + 48, params->yG, 48);
	if (bign192DH(pubkey1, privkey, pubkey1, 96) != ERR_OK ||
		!memEq(pubkey, pubkey1, 96))
		return FALSE;
	// ЭЦП
	if (bign192Sign(sig, beltH(), privkey, prngCOMBOStepR, state) != ERR_OK ||
		bign192Verify(beltH(), sig, pubkey) != ERR_OK ||
		bign192Sign2(sig, beltH(), privkey, 0, 0) != ERR_OK ||
		bign192Verify(beltH(), sig, pubkey) != ERR_OK)
		return FALSE;
	// транспорт ключа
	if (bign192KeyWrap(token, beltH(), 19, beltH() + 32, pubkey, prngCOMBOStepR,
			state) != ERR_OK ||
		bign192KeyUnwrap(token, token, 19 + 16 + 48, beltH() + 32, 
			privkey) != ERR_OK ||
		!memEq(token, beltH(), 19))
		return FALSE;
	// все нормально
	return TRUE;
}
