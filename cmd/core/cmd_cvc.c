/*
*******************************************************************************
\file cmd_cvc.c
\brief Command-line interface to Bee2: managing CV-certificates
\project bee2/cmd
\created 2022.08.20
\version 2023.05.29
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "../cmd.h"
#include <bee2/core/err.h>
#include <bee2/core/blob.h>
#include <bee2/core/hex.h>
#include <bee2/core/util.h>
#include <bee2/crypto/btok.h>
#include <stdio.h>

/*
*******************************************************************************
Печать сертификата
*******************************************************************************
*/

err_t cmdCVCPrint(const btok_cvc_t* cvc)
{
	err_t code;
	char* hex;
	// проверить содержимое
	code = btokCVCCheck(cvc);
	ERR_CALL_CHECK(code);
	// выделить память и разметить ее
	code = cmdBlobCreate(hex, 2 * 128 + 1);
	ERR_CALL_CHECK(code);
	// печатать содержимое
	ASSERT(cvc->pubkey_len <= 128);
	hexFrom(hex, cvc->pubkey, cvc->pubkey_len);
	printf(
		"authority = \"%s\"\n"
		"holder = \"%s\"\n"
		"pubkey = %s\n",
		cvc->authority, cvc->holder, hex);
	hexFrom(hex, cvc->hat_eid, 5);
	hexFrom(hex + 16, cvc->hat_esign, 2);
	printf(
		"hat_eid = %s\n"
		"hat_esign = %s\n",
		hex, hex + 16);
	ASSERT(cvc->sig_len <= 96);
	hexFrom(hex, cvc->sig, cvc->sig_len);
	printf(
		"from = %c%c%c%c%c%c\n"
		"until = %c%c%c%c%c%c\n"
		"sig = %s\n",
		cvc->from[0] + '0', cvc->from[1] + '0',
		cvc->from[2] + '0', cvc->from[3] + '0',
		cvc->from[4] + '0', cvc->from[5] + '0',
		cvc->until[0] + '0', cvc->until[1] + '0',
		cvc->until[2] + '0', cvc->until[3] + '0',
		cvc->until[4] + '0', cvc->until[5] + '0',
		hex);
	// завершить
	cmdBlobClose(hex);
	return ERR_OK;
}
