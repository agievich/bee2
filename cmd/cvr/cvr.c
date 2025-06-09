/*
*******************************************************************************
\file cvr.c
\brief Manage CV-certificate rings
\project bee2/cmd 
\created 2023.06.08
\version 2025.06.09
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <stdio.h>
#include <bee2/core/blob.h>
#include <bee2/core/err.h>
#include <bee2/core/dec.h>
#include <bee2/core/mem.h>
#include <bee2/core/str.h>
#include <bee2/core/tm.h>
#include <bee2/core/util.h>
#include "bee2/cmd.h"

/*
*******************************************************************************
Утилита cvr

Функционал:
- создание кольца;
- добавление сертификата в кольцо;
- удаление сертификата из кольца;
- извлечение сертификата из кольца;
- печать информации о кольце.

Пример (после примера в cvc.c):
  # выпуск дополнительного сертификата
  bee2cmd kg gen -pass pass:bob privkey3
  bee2cmd cvc req -authority BYCA1023 -from 221030 -until 391231 \
    -holder 590082394655 -pass pass:bob privkey3 req3
  bee2cmd cvc iss -pass pass:trent privkey1 cert1 req3 cert3
  # управление кольцом
  bee2cmd cvr init -pass pass:alice privkey2 cert2 ring2
  bee2cmd cvr add -pass pass:alice privkey2 cert2 cert3 ring2
  bee2cmd cvr val cert2 ring2
  bee2cmd sig val -anchor cert2 ring2 ring2
  bee2cmd cvr find ring2 cert3
  bee2cmd cvr extr -cert0 ring2 cert31
  bee2cmd sig extr -cert0 ring2 cert21
  bee2cmd cvr print ring2
  bee2cmd cvr print -certc ring2
  bee2cmd sig print ring2
  bee2cmd cvr del -pass pass:alice privkey2 cert2 cert3 ring2
  bee2cmd cvr find ring2 
*******************************************************************************
*/

static const char _name[] = "cvr";
static const char _descr[] = "manage certificate rings";

static int cvrUsage()
{
	printf(
		"bee2cmd/%s: %s\n"
		"Usage:\n"
		"  cvr init -pass <schema> <privkeya> <certa> <ring>\n"
		"    init <ring> on behalf of the holder of <privkeya>/<certa>\n"
		"  cvr add -pass <schema> <privkeya> <certa> <cert> <ring>\n"
		"    add <cert> to <ring>\n"
		"  cvr del -pass <schema> <privkeya> <certa> <cert> <ring>\n"
		"    remove <cert> from <ring>\n"
		"  cvr val <certa> <ring>\n"
		"    validate <ring> using <certa> as an anchor\n"
		"  cvr find <ring> <cert>\n"
		"    find <cert> in <ring>\n"
		"  cvr extr -cert<nnn> <ring> <obj_file>\n"
		"    extract object from <ring> and store it in <obj_file>\n"
		"      -cert<nnn> -- <nnn>th certificate\n"
		"        \\remark certificates are numbered from zero\n"
		"      -certa -- holder's certificate\n"
		"  cvr print [-certc] <ring>\n"
		"    print <ring> info: all fields or a specific field\n"
		"      -certc -- number of certificates\n"
		"  .\n"
		,
		_name, _descr
	);
	return -1;
}

/*
*******************************************************************************
Создание кольца

cvr init -pass <schema> <privkeya> <certa> <ring>
*******************************************************************************
*/

static err_t cvrCreate(int argc, char* argv[])
{
	err_t code;
	cmd_pwd_t pwd;
	size_t privkey_len;
	octet* privkey;
	octet date[6];
	// самотестирование
	code = cmdStDo(CMD_ST_BIGN);
	ERR_CALL_CHECK(code);
	// обработать опции
	if (argc != 5 || !strEq(argv[0], "-pass"))
		code = ERR_CMD_PARAMS;
	ERR_CALL_CHECK(code);
	// проверить наличие/отсутствие файлов
	code = cmdFileValExist(2, argv + 2);
	ERR_CALL_CHECK(code);
	code = cmdFileValNotExist(1, argv + 4);
	ERR_CALL_CHECK(code);
	// определить пароль
	code = cmdPwdRead(&pwd, argv[1]);
	ERR_CALL_CHECK(code);
	// прочитать личный ключ
	privkey_len = 0;
	code = cmdPrivkeyRead(0, &privkey_len, argv[2], pwd);
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	code = cmdBlobCreate(privkey, privkey_len);
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	code = cmdPrivkeyRead(privkey, 0, argv[2], pwd);
	cmdPwdClose(pwd);
	ERR_CALL_HANDLE(code, cmdBlobClose(privkey));
	// создать пустое кольцо
	code = cmdFileWrite(argv[4], 0, 0);
	ERR_CALL_HANDLE(code, cmdBlobClose(privkey));
	// определить текущую дату
	if (!tmDate2(date))
		code = ERR_BAD_TIMER;
	ERR_CALL_HANDLE(code, cmdBlobClose(privkey));
	// подписать кольцо
	code = cmdSigSign(argv[4], argv[4], argv[3], date, privkey, privkey_len);
	// завершить
	cmdBlobClose(privkey);
	return code;
}

/*
*******************************************************************************
Добавление сертификата

cvr add -pass <schema> <privkeya> <certa> <cert> <ring>
*******************************************************************************
*/

static err_t cvrAdd(int argc, char* argv[])
{
	err_t code;
	cmd_pwd_t pwd;
	void* stack;
	size_t privkey_len;
	octet* privkey;
	size_t certa_len;
	octet* certa;
	size_t cert_len;
	octet* cert;
	size_t sig_len;
	cmd_sig_t* sig;
	btok_cvc_t* cvc;
	size_t ring_len;
	void* ring;
	octet* certs;
	octet date[6];
	// самотестирование
	code = cmdStDo(CMD_ST_BIGN);
	ERR_CALL_CHECK(code);
	// обработать опции
	if (argc != 6 || !strEq(argv[0], "-pass"))
		code = ERR_CMD_PARAMS;
	ERR_CALL_CHECK(code);
	// проверить наличие/отсутствие файлов
	code = cmdFileValExist(4, argv + 2);
	ERR_CALL_CHECK(code);
	// определить пароль
	code = cmdPwdRead(&pwd, argv[1]);
	ERR_CALL_CHECK(code);
	// определить длину личного ключа
	privkey_len = 0;
	code = cmdPrivkeyRead(0, &privkey_len, argv[2], pwd);
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	// определить длину certa
	code = cmdFileReadAll(0, &certa_len, argv[3]);
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	// определить длину cert
	code = cmdFileReadAll(0, &cert_len, argv[4]);
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	// создать и разметить стек
	code = cmdBlobCreate(stack, privkey_len + certa_len + cert_len +
		sizeof(cmd_sig_t) + sizeof(btok_cvc_t));
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	privkey = (octet*)stack;
	certa = privkey + privkey_len;
	cert = certa + certa_len;
	sig = (cmd_sig_t*)(cert + cert_len);
	cvc = (btok_cvc_t*)(sig + 1);
	// прочитать личный ключ
	code = cmdPrivkeyRead(privkey, 0, argv[2], pwd);
	cmdPwdClose(pwd);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// прочитать certa
	code = cmdFileReadAll(certa, &certa_len, argv[3]);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// проверить соответствие личного ключа и certa
	code = btokCVCMatch(certa, certa_len, privkey, privkey_len);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// прочитать подпись
	code = cmdSigRead(sig, &sig_len, argv[5]);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// проверить вложенный в подпись сертификат
	if (sig->certs_len != certa_len || !memEq(sig->certs, certa, certa_len))
		code = ERR_BAD_ANCHOR;
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// проверить подпись кольца
	code = cmdSigVerify2(argv[5], argv[5], certa, certa_len);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// прочитать cert
	code = cmdFileReadAll(cert, &cert_len, argv[4]);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// проверить cert
	code = btokCVCUnwrap(cvc, cert, cert_len, 0, 0);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// прочитать кольцо
	code = cmdFileReadAll(0, &ring_len, argv[5]);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	code = cmdBlobCreate(ring, ring_len);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	code = cmdFileReadAll(ring, &ring_len, argv[5]);
	ERR_CALL_HANDLE(code, (cmdBlobClose(ring), cmdBlobClose(stack)));
	certs = (octet*)ring;
	// искать сертификат
	ASSERT(sig_len <= ring_len);
	code = cmdCVCsFind(0, certs, ring_len - sig_len, cert, cert_len);
	if (code == ERR_OK)
		code = ERR_ALREADY_EXISTS;
	else if (code == ERR_NOT_FOUND)
		code = ERR_OK;
	ERR_CALL_HANDLE(code, (cmdBlobClose(ring), cmdBlobClose(stack)));
	// добавить сертификат
	if (cert_len > ring_len)
	{
		blob_t r;
		code = cmdBlobResize(r, ring, ring_len - sig_len + cert_len);
		ERR_CALL_HANDLE(code, (cmdBlobClose(ring), cmdBlobClose(stack)));
		ring = r, certs = (octet*)ring;
	}
	memCopy(certs + ring_len - sig_len, cert, cert_len);
	// записать сертификаты в файл
	code = cmdFileWrite(argv[5], certs, ring_len - sig_len + cert_len);
	cmdBlobClose(ring);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// определить текущую дату
	if (!tmDate2(date))
		code = ERR_BAD_TIMER;
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// подписать файл
	code = cmdSigSign(argv[5], argv[5], argv[3], date, privkey, privkey_len);
	// завершить
	cmdBlobClose(stack);
	return code;
}

/*
*******************************************************************************
Удаление сертификата 

cvr del -pass <schema> <privkeya> <certa> <cert> <req>
*******************************************************************************
*/

static err_t cvrDel(int argc, char* argv[])
{
	err_t code;
	cmd_pwd_t pwd;
	void* stack;
	size_t privkey_len;
	octet* privkey;
	size_t certa_len;
	octet* certa;
	size_t cert_len;
	octet* cert;
	size_t sig_len;
	cmd_sig_t* sig;
	btok_cvc_t* cvc;
	size_t ring_len;
	void* ring;
	octet* certs;
	size_t offset;
	octet date[6];
	// самотестирование
	code = cmdStDo(CMD_ST_BIGN);
	ERR_CALL_CHECK(code);
	// обработать опции
	if (argc != 6 || !strEq(argv[0], "-pass"))
		code = ERR_CMD_PARAMS;
	ERR_CALL_CHECK(code);
	// проверить наличие/отсутствие файлов
	code = cmdFileValExist(4, argv + 2);
	ERR_CALL_CHECK(code);
	// определить пароль
	code = cmdPwdRead(&pwd, argv[1]);
	ERR_CALL_CHECK(code);
	// определить длину личного ключа
	privkey_len = 0;
	code = cmdPrivkeyRead(0, &privkey_len, argv[2], pwd);
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	// определить длину certa
	code = cmdFileReadAll(0, &certa_len, argv[3]);
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	// определить длину cert
	code = cmdFileReadAll(0, &cert_len, argv[4]);
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	// создать и разметить стек
	code = cmdBlobCreate(stack, privkey_len + certa_len + cert_len +
		sizeof(cmd_sig_t) + sizeof(btok_cvc_t));
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	privkey = (octet*)stack;
	certa = privkey + privkey_len;
	cert = certa + certa_len;
	sig = (cmd_sig_t*)(cert + cert_len);
	cvc = (btok_cvc_t*)(sig + 1);
	// прочитать личный ключ
	code = cmdPrivkeyRead(privkey, 0, argv[2], pwd);
	cmdPwdClose(pwd);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// прочитать certa
	code = cmdFileReadAll(certa, &certa_len, argv[3]);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// проверить соответствие личного ключа и certa
	code = btokCVCMatch(certa, certa_len, privkey, privkey_len);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// прочитать подпись
	code = cmdSigRead(sig, &sig_len, argv[5]);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// проверить вложенный в подпись сертификат
	if (sig->certs_len != certa_len || !memEq(sig->certs, certa, certa_len))
		code = ERR_BAD_ANCHOR;
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// проверить подпись кольца
	code = cmdSigVerify2(argv[5], argv[5], certa, certa_len);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// прочитать cert
	code = cmdFileReadAll(cert, &cert_len, argv[4]);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// проверить cert
	code = btokCVCUnwrap(cvc, cert, cert_len, 0, 0);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// прочитать кольцо
	code = cmdFileReadAll(0, &ring_len, argv[5]);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	code = cmdBlobCreate(ring, ring_len);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	code = cmdFileReadAll(ring, &ring_len, argv[5]);
	ERR_CALL_HANDLE(code, (cmdBlobClose(ring), cmdBlobClose(stack)));
	certs = (octet*)ring;
	// искать сертификат
	ASSERT(sig_len <= ring_len);
	code = cmdCVCsFind(&offset, certs, ring_len - sig_len, cert, cert_len);
	ERR_CALL_HANDLE(code, (cmdBlobClose(ring), cmdBlobClose(stack)));
	// удалить сертификат
	ASSERT(offset + cert_len + sig_len <= ring_len);
	memMove(certs + offset, certs + offset + cert_len,
		ring_len - sig_len - offset - cert_len);
	// записать сертификаты в файл
	code = cmdFileWrite(argv[5], certs, ring_len - sig_len - cert_len);
	cmdBlobClose(ring);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// определить текущую дату
	if (!tmDate2(date))
		code = ERR_BAD_TIMER;
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// подписать файл
	code = cmdSigSign(argv[5], argv[5], argv[3], date, privkey, privkey_len);
	// завершить
	cmdBlobClose(stack);
	return code;
}

/*
*******************************************************************************
Проверка кольца

cvr val <certa> <ring>
*******************************************************************************
*/

static err_t cvrVal(int argc, char* argv[])
{
	err_t code;
	void* stack;
	size_t certa_len;
	octet* certa;
	size_t sig_len;
	cmd_sig_t* sig;
	size_t ring_len;
	void* ring;
	octet* certs;
	// самотестирование
	code = cmdStDo(CMD_ST_BIGN);
	ERR_CALL_CHECK(code);
	// обработать опции
	if (argc != 2)
		code = ERR_CMD_PARAMS;
	ERR_CALL_CHECK(code);
	// проверить наличие/отсутствие файлов
	code = cmdFileValExist(2, argv);
	ERR_CALL_CHECK(code);
	// определить длину certa
	code = cmdFileReadAll(0, &certa_len, argv[0]);
	ERR_CALL_CHECK(code);
	// создать и разметить стек
	code = cmdBlobCreate(stack, certa_len + sizeof(cmd_sig_t));
	ERR_CALL_CHECK(code);
	certa = (octet*)stack;
	sig = (cmd_sig_t*)(certa + certa_len);
	// прочитать certa
	code = cmdFileReadAll(certa, &certa_len, argv[0]);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// прочитать подпись
	code = cmdSigRead(sig, &sig_len, argv[1]);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// проверить вложенный в подпись сертификат
	if (sig->certs_len != certa_len || !memEq(sig->certs, certa, certa_len))
		code = ERR_BAD_ANCHOR;
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// проверить подпись кольца
	code = cmdSigVerify2(argv[1], argv[1], certa, certa_len);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// прочитать кольцо
	code = cmdFileReadAll(0, &ring_len, argv[1]);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	code = cmdBlobCreate(ring, ring_len);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	code = cmdFileReadAll(ring, &ring_len, argv[1]);
	ERR_CALL_HANDLE(code, (cmdBlobClose(ring), cmdBlobClose(stack)));
	certs = (octet*)ring;
	// проверить сертификаты
	ASSERT(sig_len <= ring_len);
	code = cmdCVCsCheck(certs, ring_len - sig_len);
	// завершить
	cmdBlobClose(ring);
	cmdBlobClose(stack);
	return code;
}

/*
*******************************************************************************
Поиск сертификата

cvr find <ring> <cert>
*******************************************************************************
*/

static err_t cvrFind(int argc, char* argv[])
{
	err_t code;
	void* stack;
	size_t cert_len;
	octet* cert;
	size_t sig_len;
	cmd_sig_t* sig;
	size_t ring_len;
	octet* certs;
	// обработать опции
	if (argc != 2)
		return ERR_CMD_PARAMS;
	// проверить наличие файлов
	code = cmdFileValExist(2, argv);
	ERR_CALL_CHECK(code);
	// определить длину cert
	code = cmdFileReadAll(0, &cert_len, argv[1]);
	ERR_CALL_CHECK(code);
	// определить длину кольца
	code = cmdFileReadAll(0, &ring_len, argv[0]);
	ERR_CALL_CHECK(code);
	// выделить и разметить память
	code = cmdBlobCreate(stack, cert_len + MAX2(sizeof(cmd_sig_t), ring_len));
	ERR_CALL_CHECK(code);
	cert = (octet*)stack;
	certs = cert + cert_len;
	sig = (cmd_sig_t*)certs;
	// прочитать cert
	code = cmdFileReadAll(cert, &cert_len, argv[1]);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// определить длину подписи
	code = cmdSigRead(sig, &sig_len, argv[0]);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// прочитать кольцо
	code = cmdFileReadAll(certs, &ring_len, argv[0]);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// найти сертификат
	code = cmdCVCsFind(0, certs, ring_len - sig_len, cert, cert_len);
	// завершить
	cmdBlobClose(stack);
	return code;
}

/*
*******************************************************************************
Извлечение объекта

cvr extr -cert<nnn> <ring> <obj_file>
*******************************************************************************
*/

static err_t cvrExtr(int argc, char* argv[])
{
	err_t code;
	const char* scope;
	size_t num;
	void* stack;
	size_t sig_len;
	cmd_sig_t* sig;
	size_t ring_len;
	octet* certs;
	size_t offset;
	size_t cert_len;
	// обработать опции
	scope = argv[0];
	if (argc != 3 || !strStartsWith(scope, "-cert"))
		return ERR_CMD_PARAMS;
	scope += strLen("-cert");
	// определить номер сертификата
	if (!decIsValid(scope) || strLen(scope) < 1 || strLen(scope) > 8)
		return ERR_CMD_PARAMS;
	num = (size_t)decToU32(scope);
	// проверить наличие/отсутствие файлов
	code = cmdFileValExist(1, argv + 1);
	ERR_CALL_CHECK(code);
	code = cmdFileValNotExist(1, argv + 2);
	ERR_CALL_CHECK(code);
	// определить длину кольца
	code = cmdFileReadAll(0, &ring_len, argv[1]);
	ERR_CALL_CHECK(code);
	// выделить и разметить память
	code = cmdBlobCreate(stack, MAX2(sizeof(cmd_sig_t), ring_len));
	ERR_CALL_CHECK(code);
	sig = (cmd_sig_t*)stack;
	certs = (octet*)stack;
	// определить длину подписи
	code = cmdSigRead(sig, &sig_len, argv[1]);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// прочитать кольцо
	code = cmdFileReadAll(certs, &ring_len, argv[1]);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// найти сертификат
	code = cmdCVCsGet(&offset, &cert_len, certs, ring_len - sig_len, num);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// записать сертификат в файл
	code = cmdFileWrite(argv[2], certs + offset, cert_len);
	// завершить
	cmdBlobClose(stack);
	return code;
}

/*
*******************************************************************************
Печать

cvr print [-certc] <ring>
*******************************************************************************
*/

static err_t cvrPrint(int argc, char* argv[])
{
	err_t code;
	const char* scope;
	void* stack;
	size_t sig_len;
	cmd_sig_t* sig;
	size_t ring_len;
	octet* certs;
	size_t count;
	// обработать опции
	if (argc == 1)
		scope = 0;
	else if (argc == 2 && strEq(argv[0], "-certc"))
		scope = argv[0], ++scope, ++argv, --argc;
	else
		return ERR_CMD_PARAMS;
	// проверить наличие/отсутствие файлов
	code = cmdFileValExist(1, argv);
	ERR_CALL_CHECK(code);
	// определить длину кольца
	code = cmdFileReadAll(0, &ring_len, argv[0]);
	ERR_CALL_CHECK(code);
	// выделить и разметить память
	code = cmdBlobCreate(stack, MAX2(sizeof(cmd_sig_t), ring_len));
	ERR_CALL_CHECK(code);
	sig = (cmd_sig_t*)stack;
	certs = (octet*)stack;
	// определить длину подписи
	code = cmdSigRead(sig, &sig_len, argv[0]);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// прочитать кольцо
	code = cmdFileReadAll(certs, &ring_len, argv[0]);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// определить число сертификатов
	ASSERT(sig_len <= ring_len);
	code = cmdCVCsCount(&count, certs, ring_len - sig_len);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// печатать 
	if (!scope)
	{
		printf("certc: %u\n", (unsigned)count);
		if (count)
		{
			printf("certs:\n");
			code = cmdCVCsPrint(certs, ring_len - sig_len);
		}
	}
	else 
		printf("%u\n", (unsigned)count);
	// завершить
	cmdBlobClose(stack);
	return code;
}

/*
*******************************************************************************
Главная функция
*******************************************************************************
*/

static int cvrMain(int argc, char* argv[])
{
	err_t code;
	// справка
	if (argc < 2)
		return cvrUsage();
	// разбор команды
	++argv, --argc;
	if (strEq(argv[0], "init"))
		code = cvrCreate(argc - 1, argv + 1);
	else if (strEq(argv[0], "add"))
		code = cvrAdd(argc - 1, argv + 1);
	else if (strEq(argv[0], "del"))
		code = cvrDel(argc - 1, argv + 1);
	else if (strEq(argv[0], "val"))
		code = cvrVal(argc - 1, argv + 1);
	else if (strEq(argv[0], "find"))
		code = cvrFind(argc - 1, argv + 1);
	else if (strEq(argv[0], "extr"))
		code = cvrExtr(argc - 1, argv + 1);
	else if (strEq(argv[0], "print"))
		code = cvrPrint(argc - 1, argv + 1);
	else
		code = ERR_CMD_NOT_FOUND;
	// завершить
	if (code != ERR_OK || strEq(argv[0], "val") || strEq(argv[0], "find"))
		printf("bee2cmd/%s: %s\n", _name, errMsg(code));
	return code != ERR_OK ? -1 : 0;
}

/*
*******************************************************************************
Инициализация
*******************************************************************************
*/

err_t cvrInit()
{
	return cmdReg(_name, _descr, cvrMain);
}
