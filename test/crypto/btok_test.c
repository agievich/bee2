/*
*******************************************************************************
\file btok_test.c
\brief Tests for STB 34.101.79 (btok) helpers
\project bee2/test
\created 2022.07.07
\version 2022.07.11
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include <bee2/core/hex.h>
#include <bee2/core/mem.h>
#include <bee2/core/prng.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include <bee2/crypto/belt.h>
#include <bee2/crypto/bign.h>
#include <bee2/crypto/btok.h>

#include <stdio.h>

static bool_t btokCVCTest()
{
	octet echo[256];
	btok_cvc_t cvc0[1];
	btok_cvc_t cvc1[1];
	btok_cvc_t cvc2[1];
	bign_params params[1];
	octet privkey0[64];
	octet privkey1[48];
	octet cert0[512]; size_t cert0_len;
	octet cert1[512]; size_t cert1_len;

	// запустить ГПСЧ
	prngEchoStart(echo, beltH(), 256);

	// составить и проверить cvc0
	memSetZero(cvc0, sizeof(btok_cvc_t));
	strCopy(cvc0->authority, "BYCA00000000");
	strCopy(cvc0->holder, "BYCA00000000");
	hexTo(cvc0->from, "020200070007");
	hexTo(cvc0->until, "040400070007");
	memSet(cvc0->hat_eid, 0xEE, sizeof(cvc0->hat_eid));
	memSet(cvc0->hat_esign, 0x77, sizeof(cvc0->hat_esign));
	cvc0->pubkey_len = 128;
	if (btokCVCCheck(cvc0) == ERR_OK)
		return FALSE;
	if (bignStdParams(params, "1.2.112.0.2.0.34.101.45.3.3") != ERR_OK ||
		bignGenKeypair(privkey0, cvc0->pubkey, params, prngEchoStepR, 
			echo) != ERR_OK ||
		btokCVCCheck(cvc0) != ERR_OK)
		return FALSE;
	// создать cert0
	if (btokCVCWrap(0, 0, cvc0, privkey0, 64) != ERR_OK)
		return FALSE;
	cvc0->pubkey_len = 0;
	if (btokCVCWrap(0, &cert0_len, cvc0, privkey0, 64) != ERR_OK)
		return FALSE;
	ASSERT(cert0_len == 349); /* максимальная длина CV-сертификата */
	ASSERT(cert0_len <= sizeof(cert0));
	if (btokCVCWrap(cert0, &cert0_len, cvc0, privkey0, 64) != ERR_OK ||
		bignValKeypair(params, privkey0, cvc0->pubkey) != ERR_OK)
		return FALSE;
	// разобрать cert0
	if (btokCVCUnwrap(cvc1, cert0, cert0_len, 0, 0) != ERR_OK ||
		btokCVCUnwrap(cvc1, cert0, cert0_len, cvc0->pubkey,
			cvc0->pubkey_len) != ERR_OK ||
		!memEq(cvc0, cvc1, sizeof(btok_cvc_t)))
		return FALSE;

	// составить и проверить cvc1
	memSetZero(cvc1, sizeof(btok_cvc_t));
	strCopy(cvc1->authority, "BYCA00000000");
	strCopy(cvc1->holder, "BYCA1000");
	hexTo(cvc1->from, "020200070007");
	hexTo(cvc1->until, "030300070007");
	memSet(cvc1->hat_eid, 0xDD, sizeof(cvc1->hat_eid));
	memSet(cvc1->hat_esign, 0x33, sizeof(cvc1->hat_esign));
	cvc1->pubkey_len = 96;
	if (bignStdParams(params, "1.2.112.0.2.0.34.101.45.3.2") != ERR_OK ||
		bignGenKeypair(privkey1, cvc1->pubkey, params, prngEchoStepR,
			echo) != ERR_OK ||
		btokCVCCheck(cvc1) != ERR_OK)
		return FALSE;
	// создать pre-cert1 (запрос на выпуск сертификата)
	if (btokCVCWrap(0, &cert1_len, cvc1, privkey1, 48) != ERR_OK)
		return FALSE;
	ASSERT(cert1_len <= sizeof(cert1));
	if (btokCVCWrap(cert1, 0, cvc1, privkey1, 48) != ERR_OK)
		return FALSE;
	// разобрать pre-cert1:
	// - извлечь открытый ключ,
	// - проверить подпись,
	// - проверить соответствие authority <=> holder
	if (btokCVCUnwrap(cvc1, cert1, cert1_len, 0, 0) != ERR_OK ||
		btokCVCUnwrap(cvc2, cert1, cert1_len, cvc1->pubkey,
			cvc1->pubkey_len) != ERR_OK ||
		!memEq(cvc1, cvc2, sizeof(btok_cvc_t)) ||
		!strEq(cvc1->authority, cvc0->holder))
		return FALSE;
	// создать cert1
	if (btokCVCWrap(0, &cert1_len, cvc1, privkey0, 64) != ERR_OK)
		return FALSE;
	ASSERT(cert1_len <= sizeof(cert1));
	if (btokCVCWrap(cert1, &cert1_len, cvc1, privkey0, 64) != ERR_OK)
		return FALSE;
	// все хорошо
	return TRUE;
}

bool_t btokTest()
{
	return btokCVCTest();
}
