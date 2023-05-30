/*
*******************************************************************************
\file cmd_cvc.c
\brief Command-line interface to Bee2: managing CV-certificates
\project bee2/cmd
\created 2022.08.20
\version 2023.05.30
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "../cmd.h"
#include <bee2/core/err.h>
#include <bee2/core/blob.h>
#include <bee2/core/hex.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include <stdio.h>

/*
*******************************************************************************
Печать сертификата
*******************************************************************************
*/

static void cmdCVCPrintName(const char* name)
{
	ASSERT(strIsValid(name));
	printf("%s", name);
}

static err_t cmdCVCPrintMem(const octet* buf, size_t count)
{
	err_t code;
	char* hex;
	code = cmdBlobCreate(hex, 2 * count + 1);
	ERR_CALL_CHECK(code);
	hexFrom(hex, buf, count);
	printf("%s", hex);
	cmdBlobClose(hex);
	return ERR_OK;
}

static void cmdCVCPrintDate(const octet date[6])
{
	ASSERT(tmDateIsValid2(date));
	printf("%c%c%c%c%c%c",
		date[0] + '0', date[1] + '0', date[2] + '0',
		date[3] + '0', date[4] + '0', date[5] + '0');
}

err_t cmdCVCPrint(const btok_cvc_t* cvc, const char* scope)
{
	err_t code = ERR_OK;
	// проверить содержимое
	code = btokCVCCheck(cvc);
	ERR_CALL_CHECK(code);
	// печать всех полей
	if (scope == 0)
	{
		printf("authority = \"");
		cmdCVCPrintName(cvc->authority);
		printf("\"\nholder = \"");
		cmdCVCPrintName(cvc->holder);
		printf("\"\npubkey = ");
		code = cmdCVCPrintMem(cvc->pubkey, cvc->pubkey_len);
		ERR_CALL_CHECK(code);
		printf("\nhat_eid = ");
		code = cmdCVCPrintMem(cvc->hat_eid, sizeof(cvc->hat_eid));
		ERR_CALL_CHECK(code);
		printf("\nhat_esign = ");
		code = cmdCVCPrintMem(cvc->hat_esign, sizeof(cvc->hat_esign));
		ERR_CALL_CHECK(code);
		printf("\nfrom = ");
		cmdCVCPrintDate(cvc->from);
		printf("\nuntil = ");
		cmdCVCPrintDate(cvc->until);
		printf("\nsig = ");
		code = cmdCVCPrintMem(cvc->sig, cvc->sig_len);
		ERR_CALL_CHECK(code);
		printf("\n");
		return code;
	}
	// печать отдельных полей
	if (strEq(scope, "authority"))
		cmdCVCPrintName(cvc->authority);
	else if (strEq(scope, "holder"))
		cmdCVCPrintName(cvc->holder);
	else if (strEq(scope, "from"))
		cmdCVCPrintDate(cvc->from);
	else if (strEq(scope, "until"))
		cmdCVCPrintDate(cvc->until);
	else if (strEq(scope, "eid"))
		code = cmdCVCPrintMem(cvc->hat_eid, sizeof(cvc->hat_eid));
	else if (strEq(scope, "esign"))
		code = cmdCVCPrintMem(cvc->hat_esign, sizeof(cvc->hat_esign));
	else if (strEq(scope, "pubkey"))
		code = cmdCVCPrintMem(cvc->pubkey, cvc->pubkey_len);
	else
		code = ERR_CMD_PARAMS;
	ERR_CALL_CHECK(code);
	printf("\n");
	return code;
}
