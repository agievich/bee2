/*
*******************************************************************************
\file cmd_cvc.c
\brief Command-line interface to Bee2: managing CV-certificates
\project bee2/cmd
\created 2022.08.20
\version 2023.06.06
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

err_t cmdCVCPrint(const btok_cvc_t* cvc, const char* scope)
{
	err_t code = ERR_OK;
	// проверить содержимое
	code = btokCVCCheck(cvc);
	ERR_CALL_CHECK(code);
	// печать всех полей
	if (scope == 0)
	{
		printf("authority: %s\n", cvc->authority);
		printf("holder:    %s\n", cvc->holder);
		printf("pubkey:    ");
		code = cmdPrintMem2(cvc->pubkey, cvc->pubkey_len);
		ERR_CALL_CHECK(code);
		printf("\nhat_eid:   ");
		code = cmdPrintMem(cvc->hat_eid, sizeof(cvc->hat_eid));
		ERR_CALL_CHECK(code);
		printf("\nhat_esign: ");
		code = cmdPrintMem(cvc->hat_esign, sizeof(cvc->hat_esign));
		ERR_CALL_CHECK(code);
		printf("\nfrom:      ");
		code = cmdPrintDate(cvc->from);
		ERR_CALL_CHECK(code);
		printf("\nuntil:     ");
		code = cmdPrintDate(cvc->until);
		ERR_CALL_CHECK(code);
		printf("\nsig:       ");
		code = cmdPrintMem2(cvc->sig, cvc->sig_len);
	}
	// печать отдельных полей
	else if (strEq(scope, "authority"))
		printf("%s", cvc->authority);
	else if (strEq(scope, "holder"))
		printf("%s", cvc->holder);
	else if (strEq(scope, "from"))
		code = cmdPrintDate(cvc->from);
	else if (strEq(scope, "until"))
		code = cmdPrintDate(cvc->until);
	else if (strEq(scope, "eid"))
		code = cmdPrintMem(cvc->hat_eid, sizeof(cvc->hat_eid));
	else if (strEq(scope, "esign"))
		code = cmdPrintMem(cvc->hat_esign, sizeof(cvc->hat_esign));
	else if (strEq(scope, "pubkey"))
		code = cmdPrintMem(cvc->pubkey, cvc->pubkey_len);
	else if (strEq(scope, "sig"))
		code = cmdPrintMem(cvc->sig, cvc->sig_len);
	else
		code = ERR_CMD_PARAMS;
	// завершить
	ERR_CALL_CHECK(code);
	printf("\n");
	return code;
}
