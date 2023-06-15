/*
*******************************************************************************
\file cvr.c
\brief Manage CV-certificate rings
\project bee2/cmd 
\created 2023.06.08
\version 2023.06.15
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "../cmd.h"
#include <bee2/core/blob.h>
#include <bee2/core/err.h>
#include <bee2/core/dec.h>
#include <bee2/core/hex.h>
#include <bee2/core/mem.h>
#include <bee2/core/prng.h>
#include <bee2/core/str.h>
#include <bee2/core/tm.h>
#include <bee2/core/util.h>
#include <bee2/crypto/belt.h>
#include <bee2/crypto/bign.h>
#include <stdio.h>

/*
*******************************************************************************
Утилита cvr

Функционал:
- создание кольца;
- добавление сертификата в кольцо;
- удаление сертификата из кольца;
- извлечение сертификата из кольца;
- печать информации о кольце.
*******************************************************************************
*/

static const char _name[] = "cvr";
static const char _descr[] = "manage certificate rings";

static int cvrUsage()
{
	printf(
		"bee2cmd/%s: %s\n"
		"Usage:\n"
		"  cvr init -pass <scheme> <privkeya> <certa> <ring>\n"
		"    init <ring> on behalf of the holder of <privkeya>/<certa>\n"
		"  cvr add -pass <scheme> <privkeya> <certa> <cert> <ring>\n"
		"    add <cert> to <ring>\n"
		"  cvr del -pass <scheme> <privkeya> <certa> <cert> <ring>\n"
		"    remove <cert> from <ring>\n"
		"  cvr val <certa> <ring>\n"
		"    validate <ring> using <certa> as an anchor\n"
		"  cvr extr {-cert<nnn>|-certa} <ring> <file>\n"
		"    extract from <ring> an object and store it in <file>\n"
		"      -cert<nnn> -- the <nnn>th included certificate\n"
		"        \\remark certificates are numbered from zero\n"
		"      -certa -- holder's certificate\n"
		"  cvr print [-certc] <cert>\n"
		"    print <cert> info: all fields or a specific field\n"
		"      -certc -- the number of included certificates\n"
		"  .\n"
		,
		_name, _descr
	);
	return -1;
}

/*
*******************************************************************************
Самотестирование
*******************************************************************************
*/

static err_t cvrSelfTest()
{
	octet stack[1024];
	bign_params params[1];
	octet privkey[32];
	octet pubkey[64];
	octet hash[32];
	const octet oid[] = {
		0x06, 0x09, 0x2A, 0x70, 0x00, 0x02, 0x00, 0x22, 0x65, 0x1F, 0x51, 
	};
	octet sig[48];
	// bign-genkeypair
	hexTo(privkey,
		"1F66B5B84B7339674533F0329C74F218"
		"34281FED0732429E0C79235FC273E269");
	ASSERT(sizeof(stack) >= prngEcho_keep());
	prngEchoStart(stack, privkey, 32);
	if (bignStdParams(params, "1.2.112.0.2.0.34.101.45.3.1") != ERR_OK ||
		bignGenKeypair(privkey, pubkey, params, prngEchoStepR,
			stack) != ERR_OK ||
		!hexEq(pubkey,
		"BD1A5650179D79E03FCEE49D4C2BD5DD"
		"F54CE46D0CF11E4FF87BF7A890857FD0"
		"7AC6A60361E8C8173491686D461B2826"
		"190C2EDA5909054A9AB84D2AB9D99A90"))
		return ERR_SELFTEST;
	// bign-valpubkey
	if (bignValPubkey(params, pubkey) != ERR_OK)
		return ERR_SELFTEST;
	// bign-sign
	if (beltHash(hash, beltH(), 13) != ERR_OK)
		return ERR_SELFTEST;
	if (bignSign2(sig, params, oid, sizeof(oid), hash, privkey,
			0, 0) != ERR_OK)
		return ERR_SELFTEST;
	if (!hexEq(sig,
		"19D32B7E01E25BAE4A70EB6BCA42602C"
		"CA6A13944451BCC5D4C54CFD8737619C"
		"328B8A58FB9C68FD17D569F7D06495FB"))
		return ERR_SELFTEST;
	if (bignVerify(params, oid, sizeof(oid), hash, sig, pubkey) != ERR_OK)
		return ERR_SELFTEST;
	sig[0] ^= 1;
	if (bignVerify(params, oid, sizeof(oid), hash, sig, pubkey) == ERR_OK)
		return ERR_SELFTEST;
	// все нормально
	return ERR_OK;
}

/*
*******************************************************************************
Вспомогательные макросы и функции
*******************************************************************************
*/

#define cmdBlobResize(b, blob, size)\
	(((b) = blobResize(blob, size)) ? ERR_OK : ERR_OUTOFMEMORY)

static err_t cvrCertsFind(size_t* offset, const octet* certs, size_t certs_len,
	const octet* cert, size_t cert_len)
{
	ASSERT(memIsValid(certs, certs_len));
	ASSERT(memIsValid(cert, cert_len));
	ASSERT(memIsValid(offset, O_PER_S));
	// цикл по сертификатам
	for (*offset = 0; *offset < certs_len;)
	{
		size_t len = btokCVCLen(certs + *offset, certs_len - *offset);
		if (len == SIZE_MAX)
			return ERR_BAD_CERTRING;
		if (len == cert_len && memEq(certs + *offset, cert, cert_len))
			return ERR_OK;
		*offset += len;
	}
	return ERR_NOT_FOUND;
}

static err_t cvrCertsGet(size_t* offset, size_t* cert_len,
	const octet* certs, size_t certs_len, size_t num)
{
	ASSERT(memIsValid(certs, certs_len));
	ASSERT(memIsValid(offset, O_PER_S));
	ASSERT(memIsValid(cert_len, O_PER_S));
	// цикл по сертификатам
	for (*offset = 0; *offset < certs_len; *offset += *cert_len)
	{
		*cert_len = btokCVCLen(certs + *offset, certs_len - *offset);
		if (*cert_len == SIZE_MAX)
			return ERR_BAD_CERTRING;
		if (num-- == 0)
			return ERR_OK;
	}
	return ERR_NOT_FOUND;
}

static err_t cvrCertsVal(const octet* certs, size_t certs_len)
{
	err_t code;
	void* stack;
	btok_cvc_t* cvc;
	size_t offset;
	// pre
	ASSERT(memIsValid(certs, certs_len));
	// выделить и разметить память
	code = cmdBlobCreate(stack, sizeof(btok_cvc_t));
	cvc = (btok_cvc_t*)stack;
	// цикл по сертификатам
	for (offset = 0; offset < certs_len;)
	{
		size_t len = btokCVCLen(certs + offset, certs_len - offset);
		code = (len == SIZE_MAX) ?
			ERR_BAD_CERTRING : btokCVCUnwrap(cvc, certs + offset, len, 0, 0);
		if (code != ERR_OK)
			break;
		offset += len;
	}
	// завершить
	cmdBlobClose(stack);
	return code;
}

/*
*******************************************************************************
Создание кольца

cvr init -pass <scheme> <privkeya> <certa> <ring>
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
	code = cvrSelfTest();
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

cvr add -pass <scheme> <privkeya> <certa> <cert> <ring>
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
	size_t offset;
	octet date[6];
	// самотестирование
	code = cvrSelfTest();
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
	// прочитать подпись
	code = cmdSigRead(sig, &sig_len, argv[5]);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// проверить вложенный в подпись сертификат
	if (sig->certs_len != certa_len || !memEq(sig->certs, certa, certa_len))
		code = ERR_BAD_ANCHOR;
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
	code = cvrCertsFind(&offset, certs, ring_len - sig_len, cert, cert_len);
	if (code == ERR_OK)
		code = ERR_ALREADY_EXISTS;
	else if (code == ERR_NOT_FOUND)
		code = ERR_OK;
	ERR_CALL_HANDLE(code, (cmdBlobClose(ring), cmdBlobClose(stack)));
	// добавить сертификат
	ASSERT(offset + sig_len == ring_len);
	if (offset + cert_len > ring_len)
	{
		blob_t r;
		code = cmdBlobResize(r, ring, offset + cert_len);
		ERR_CALL_HANDLE(code, (cmdBlobClose(ring), cmdBlobClose(stack)));
		ring = r, certs = (octet*)ring;
	}
	memCopy(certs + offset, cert, cert_len);
	// записать сертификаты в файл
	code = cmdFileWrite(argv[5], certs, offset + cert_len);
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

cvr del -pass <scheme> <privkeya> <certa> <cert> <req>
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
	code = cvrSelfTest();
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
	// прочитать подпись
	code = cmdSigRead(sig, &sig_len, argv[5]);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// проверить вложенный в подпись сертификат
	if (sig->certs_len != certa_len || !memEq(sig->certs, certa, certa_len))
		code = ERR_BAD_ANCHOR;
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
	code = cvrCertsFind(&offset, certs, ring_len - sig_len, cert, cert_len);
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
	code = cvrSelfTest();
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
	// проверить подпись кольца
	code = cmdSigVerify2(argv[1], argv[1], certa, certa_len);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// прочитать кольцо
	code = cmdFileReadAll(0, &ring_len, argv[1]);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	code = cmdBlobCreate(ring, ring_len);
	code = ring ? ERR_OK : ERR_OUTOFMEMORY;
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	code = cmdFileReadAll(ring, &ring_len, argv[1]);
	ERR_CALL_HANDLE(code, (cmdBlobClose(ring), cmdBlobClose(stack)));
	certs = (octet*)ring;
	// проверить сертификаты
	ASSERT(sig_len <= ring_len);
	code = cvrCertsVal(certs, ring_len - sig_len);
	// завершить
	cmdBlobClose(ring);
	cmdBlobClose(stack);
	return code;
}

/*
*******************************************************************************
Извлечение объекта

cvr extr {-cert<nnn>|-certa} <ring> <file>
*******************************************************************************
*/

static err_t cvrExtr(int argc, char* argv[])
{
	err_t code = ERR_OK;
	const char* scope;
	void* stack;
	size_t sig_len;
	cmd_sig_t* sig;
	// обработать опции
	scope = argv[0];
	if (argc != 3 || !strStartsWith(scope, "-cert"))
		code = ERR_CMD_PARAMS;
	ERR_CALL_CHECK(code);
	scope += strLen("-cert");
	// проверить наличие/отсутствие файлов
	code = cmdFileValExist(1, argv + 1);
	ERR_CALL_CHECK(code);
	code = cmdFileValNotExist(1, argv + 2);
	ERR_CALL_CHECK(code);
	// cert<nnn>?
	if (decIsValid(scope) && 1 <= strLen(scope) && strLen(scope) <= 3)
	{
		size_t num;
		size_t ring_len;
		octet* certs;
		size_t offset;
		size_t cert_len;
		// определить номер сертификата
		num = (size_t)decToU32(scope);
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
		code = cmdFileReadAll(stack, &ring_len, argv[1]);
		ERR_CALL_HANDLE(code, cmdBlobClose(stack));
		// найти сертификат
		code = cvrCertsGet(&offset, &cert_len, certs, ring_len - sig_len, num);
		ERR_CALL_HANDLE(code, cmdBlobClose(stack));
		// записать сертификат в файл
		code = cmdFileWrite(argv[2], certs + offset, cert_len);
		cmdBlobClose(stack);
	}
	// certa?
	else if (strEq(scope, "a"))
	{
		// выделить и разметить память
		code = cmdBlobCreate(stack, sizeof(cmd_sig_t));
		ERR_CALL_CHECK(code);
		sig = (cmd_sig_t*)stack;
		// прочитать подпись
		code = cmdSigRead(sig, &sig_len, argv[1]);
		ERR_CALL_HANDLE(code, cmdBlobClose(stack));
		// проверить вложенный в подпись сертификат
		if (sig->certs_len != btokCVCLen(sig->certs, sig->certs_len))
			code = ERR_BAD_ANCHOR;
		ERR_CALL_HANDLE(code, cmdBlobClose(stack));
		// записать сертификат в файл
		code = cmdFileWrite(argv[2], sig->certs, sig->certs_len);
		cmdBlobClose(stack);
	}
	else
		code = ERR_CMD_PARAMS;
	// завершить
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
	size_t cert_len;
	void* stack;
	octet* cert;
	btok_cvc_t* cvc;
	const char* scope = 0;
	// обработать опции
	if (argc < 1 || argc > 2)
		return ERR_CMD_PARAMS;
	if (argc == 2)
	{
		scope = argv[0];
		if (strLen(scope) < 1 || scope[0] != '-')
			return ERR_CMD_PARAMS;
		++scope, --argc, ++argv;
	}
	// проверить наличие/отсутствие файлов
	code = cmdFileValExist(1, argv);
	ERR_CALL_CHECK(code);
	// определить длину сертификата
	code = cmdFileReadAll(0, &cert_len, argv[0]);
	ERR_CALL_CHECK(code);
	// выделить память и разметить ее
	code = cmdBlobCreate(stack, cert_len + sizeof(btok_cvc_t));
	ERR_CALL_CHECK(code);
	cert = (octet*)stack;
	cvc = (btok_cvc_t*)(cert + cert_len);
	// прочитать сертификат
	code = cmdFileReadAll(cert, &cert_len, argv[0]);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// разобрать сертификат
	code = btokCVCUnwrap(cvc, cert, cert_len, 0, 0);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// печатать содержимое
	code = cmdCVCPrint(cvc, scope);
	// завершить
	cmdBlobClose(stack);
	return code;
}

/*
*******************************************************************************
Главная функция
*******************************************************************************
*/

int cvrMain(int argc, char* argv[])
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
	else if (strEq(argv[0], "extr"))
		code = cvrExtr(argc - 1, argv + 1);
	else if (strEq(argv[0], "print"))
		code = cvrPrint(argc - 1, argv + 1);
	else
		code = ERR_CMD_NOT_FOUND;
	// завершить
	if (code != ERR_OK || strEq(argv[0], "val"))
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
