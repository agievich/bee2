/*
*******************************************************************************
\file cmd_cvc.c
\brief Command-line interface to Bee2: managing CV-certificates
\project bee2/cmd
\created 2022.08.20
\version 2025.06.09
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <stdio.h>
#include <bee2/core/err.h>
#include <bee2/core/mem.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include "bee2/cmd.h"

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

/*
*******************************************************************************
Управление коллекцией сертификатов
*******************************************************************************
*/

err_t cmdCVCsCreate(octet* certs, size_t* certs_len, const char* descr)
{
	err_t code;
	int argc;
	char** argv;
	int pos;
	size_t len;
	// pre
	ASSERT(memIsValid(certs_len, O_PER_S));
	ASSERT(memIsNullOrValid(certs, *certs_len));
	ASSERT(strIsValid(descr));
	// создать список файлов сертификатов
	code = cmdArgCreate(&argc, &argv, descr);
	ERR_CALL_CHECK(code);
	// просмотреть список
	len = 0;
	for (pos = 0; pos < argc; ++pos)
	{
		size_t size;
		// определить размер файла
		size = cmdFileSize(argv[pos]);
		code = size != SIZE_MAX ? ERR_OK : ERR_FILE_READ;
		ERR_CALL_HANDLE(code, cmdArgClose(argv));
		// режим чтения?
		if (certs)
		{
			// выход за границы?
			code = len + size <= *certs_len ? ERR_OK : ERR_OUTOFMEMORY;
			ERR_CALL_HANDLE(code, cmdArgClose(argv));
			// читать сертификат
			code = cmdFileReadAll(certs + len, &size, argv[pos]);
			ERR_CALL_HANDLE(code, cmdArgClose(argv));
		}
		// увеличить длину коллекции
		len += size;
	}
	cmdArgClose(argv);
	// завершить
	*certs_len = len;
	return code;
}


err_t cmdCVCsCount(size_t* count, const octet* certs, size_t certs_len)
{
	ASSERT(memIsValid(certs, certs_len));
	ASSERT(memIsValid(count, O_PER_S));
	// цикл по сертификатам
	for (*count = 0; certs_len; ++*count)
	{
		size_t len = btokCVCLen(certs, certs_len);
		if (len == SIZE_MAX)
			return ERR_BAD_CERTRING;
		certs += len, certs_len -= len;
	}
	return ERR_OK;
}

err_t cmdCVCsGet(size_t* offset, size_t* cert_len, const octet* certs,
	size_t certs_len, size_t num)
{
	size_t pos;
	size_t len;
	// pre
	ASSERT(memIsValid(certs, certs_len));
	ASSERT(memIsNullOrValid(offset, O_PER_S));
	ASSERT(memIsNullOrValid(cert_len, O_PER_S));
	// цикл по сертификатам
	for (pos = 0; certs_len; )
	{
		len = btokCVCLen(certs, certs_len);
		if (len == SIZE_MAX)
			return ERR_BAD_CERTRING;
		if (num-- == 0)
		{
			if (offset)
				*offset = pos;
			if (cert_len)
				*cert_len = len;
			return ERR_OK;
		}
		pos += len, certs += len, certs_len -= len;
	}
	return ERR_OUTOFRANGE;
}

err_t cmdCVCsGetLast(size_t* offset, size_t* cert_len, const octet* certs,
	size_t certs_len)
{
	size_t pos;
	size_t len;
	// pre
	ASSERT(memIsValid(certs, certs_len));
	ASSERT(memIsNullOrValid(offset, O_PER_S));
	ASSERT(memIsNullOrValid(cert_len, O_PER_S));
	// пустая коллекция?
	if (!certs_len)
		return ERR_OUTOFRANGE;
	// цикл по сертификатам
	for (pos = 0; certs_len; )
	{
		len = btokCVCLen(certs, certs_len);
		if (len == SIZE_MAX)
			return ERR_BAD_CERTRING;
		if (len == certs_len)
			break;
		pos += len, certs += len, certs_len -= len;
	}
	// сертификат найден
	if (offset)
		*offset = pos;
	if (cert_len)
		*cert_len = len;
	return ERR_OK;
}

err_t cmdCVCsFind(size_t* offset, const octet* certs, size_t certs_len,
	const octet* cert, size_t cert_len)
{
	size_t pos;
	// pre
	ASSERT(memIsValid(certs, certs_len));
	ASSERT(memIsValid(cert, cert_len));
	ASSERT(memIsNullOrValid(offset, O_PER_S));
	// цикл по сертификатам
	for (pos = 0; certs_len; )
	{
		size_t len = btokCVCLen(certs, certs_len);
		if (len == SIZE_MAX)
			return ERR_BAD_CERTRING;
		if (len == cert_len && memEq(certs, cert, cert_len))
		{
			if (offset)
				*offset = pos;
			return ERR_OK;
		}
		pos += len, certs += len, certs_len -= len;
	}
	return ERR_NOT_FOUND;
}

err_t cmdCVCsCheck(const octet* certs, size_t certs_len)
{
	err_t code;
	void* stack;
	btok_cvc_t* cvc;
	// pre
	ASSERT(memIsValid(certs, certs_len));
	// выделить и разметить память
	code = cmdBlobCreate(stack, sizeof(btok_cvc_t));
	ERR_CALL_CHECK(code);
	cvc = (btok_cvc_t*)stack;
	// цикл по сертификатам
	while (certs_len)
	{
		// разобрать сертификат
		size_t len = btokCVCLen(certs, certs_len);
		if (len == SIZE_MAX)
			code = ERR_BAD_CERTRING;
		else
			code = btokCVCUnwrap(cvc, certs, len, 0, 0);
		ERR_CALL_HANDLE(code, cmdBlobClose(stack));
		// к следующему
		certs += len, certs_len -= len;
	}
	// завершить
	cmdBlobClose(stack);
	return code;
}

err_t cmdCVCsVal(const octet* certs, size_t certs_len, const octet date[6])
{
	err_t code;
	void* stack;
	size_t len;
	btok_cvc_t* cvca;
	btok_cvc_t* cvc;
	// pre
	ASSERT(memIsValid(certs, certs_len));
	ASSERT(memIsNullOrValid(date, 6));
	// пустая цепочка?
	if (!certs_len)
		return ERR_OK;
	// выделить и разметить память
	code = cmdBlobCreate(stack, 2 * sizeof(btok_cvc_t));
	ERR_CALL_CHECK(code);
	cvca = (btok_cvc_t*)stack;
	cvc = cvca + 1;
	// найти и разобрать первый сертификат
	len = btokCVCLen(certs, certs_len);
	if (len == SIZE_MAX)
		code = ERR_BAD_CERT;
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	code = btokCVCUnwrap(cvca, certs, len, 0, 0);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	certs_len -= len, certs += len;
	// цикл по остальным сертификатам
	while (certs_len)
	{
		// разобрать сертификат
		len = btokCVCLen(certs, certs_len);
		if (len == SIZE_MAX)
			code = ERR_BAD_CERT;
		ERR_CALL_HANDLE(code, cmdBlobClose(stack));
		// проверить сертификат
		if (len == certs_len && date && !memIsZero(date, 6))
			code = btokCVCVal2(cvc, certs, len, cvca, date);
		else
			code = btokCVCVal2(cvc, certs, len, cvca, 0);
		ERR_CALL_HANDLE(code, cmdBlobClose(stack));
		// к следующему сертификату
		certs_len -= len, certs += len;
		// издатель <- эмитент
		memCopy(cvca, cvc, sizeof(btok_cvc_t));
	}
	// завершить
	cmdBlobClose(stack);
	return code;
}

err_t cmdCVCsPrint(const octet* certs, size_t certs_len)
{
	err_t code;
	void* stack;
	btok_cvc_t* cvc;
	// pre
	ASSERT(memIsValid(certs, certs_len));
	// выделить и разметить память
	code = cmdBlobCreate(stack, sizeof(btok_cvc_t));
	ERR_CALL_CHECK(code);
	cvc = (btok_cvc_t*)stack;
	// цикл по сертификатам
	while (certs_len)
	{
		// разобрать сертификат
		size_t len = btokCVCLen(certs, certs_len);
		if (len == SIZE_MAX)
			code = ERR_BAD_CERTRING;
		else
			code = btokCVCUnwrap(cvc, certs, len, 0, 0);
		ERR_CALL_HANDLE(code, cmdBlobClose(stack));
		// печатать
		printf("  %s (%u bits, issued by %s, ",
			cvc->holder, (unsigned)cvc->pubkey_len * 2, cvc->authority);
		code = cmdPrintDate(cvc->from);
		ERR_CALL_HANDLE(code, cmdBlobClose(stack));
		printf("-");
		code = cmdPrintDate(cvc->until);
		ERR_CALL_HANDLE(code, cmdBlobClose(stack));
		printf(")\n");
		// к следующему
		certs += len, certs_len -= len;
	}
	// завершить
	cmdBlobClose(stack);
	return code;
}
