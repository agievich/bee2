/*
*******************************************************************************
\file cvc.c
\brief Manage CV-certificates
\project bee2/cmd 
\created 2022.07.12
\version 2022.10.27
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "../cmd.h"
#include <bee2/core/blob.h>
#include <bee2/core/err.h>
#include <bee2/core/hex.h>
#include <bee2/core/mem.h>
#include <bee2/core/prng.h>
#include <bee2/core/str.h>
#include <bee2/core/tm.h>
#include <bee2/core/util.h>
#include <bee2/crypto/belt.h>
#include <bee2/crypto/bign.h>
#include <bee2/crypto/btok.h>
#include <stdio.h>

/*
*******************************************************************************
Утилита cvc

Функционал:
- выпуск самоподписанного сертификата;
- создание предсертификата (запроса на выпуск);
- выпуск сертификата;
- проверка цепочки сертификатов;
- проверка соответствия между сертификатом и личным ключом;
- печать полей сертификата.

Пример:
  bee2cmd kg gen -l256 -pass pass:root privkey0
  bee2cmd kg gen -l192 -pass pass:trent privkey1
  bee2cmd kg gen -pass pass:alice privkey2
  bee2cmd cvc root -authority BYCA0000 -from 220707 -until 990707 \
	-pass pass:root -eid EEEEEEEEEE -esign 7777 privkey0 cert0
  bee2cmd cvc print cert0
  bee2cmd cvc req -pass pass:trent  -authority BYCA0000 -holder BYCA1000 \
	-from 220712 -until 221130 -eid DDDDDDDDDD -esign 3333 privkey1 req1
  bee2cmd cvc iss -pass pass:root privkey0 cert0 req1 cert1
  bee2cmd cvc req -authority BYCA1000 -from 220712 -until 391231 -esign 1111 \
	-holder "590082394654" -pass pass:alice -eid 8888888888 privkey2 req2
  bee2cmd cvc iss -pass pass:trent privkey1 cert1 req2 cert2
  bee2cmd cvc match -pass pass:alice privkey2 cert2
  bee2cmd cvc val cert0 cert0
  bee2cmd cvc val -date 220712 cert0 cert1
  bee2cmd cvc val -date 221201 cert0 cert1 cert2
*******************************************************************************
*/

static const char _name[] = "cvc";
static const char _descr[] = "manage CV-certificates";

static int cvcUsage()
{
	printf(
		"bee2cmd/%s: %s\n"
		"Usage:\n"
		"  cvc root options <privkeya> <certa>\n"
		"    issue a self-signed certificate <certa>\n"
		"  cvc req options <privkey> <req>\n"
		"    generate a pre-certificate <req>\n"
		"  cvc iss options <privkeya> <certa> <req> <cert>\n"
		"    issue <cert> based on <req> and subordinate to <certa>\n"
		"  cvc val options <certa> <certb> ... <cert>\n"
		"    validate <certb> ... <cert> using <certa> as an anchor\n"
		"  cvc match options <privkey> <cert>\n"
		"    check the match between <privkey> and <cert>\n"
		"  cvc print <cert>\n"
		"    print <cert> info\n"
		"  .\n"
		"  <privkey>, <privkeya>\n"
		"    containers with private keys\n"
		"  options:\n"
		"    -authority <name> -- authority (issuer)  [root], req\n"
		"    -holder <name> -- holder (owner)         [root], req\n"
		"    -from <YYMMDD> -- starting date          root, req\n"
		"    -until <YYMMDD> -- expiration date       root, req\n"
		"    -eid <10*hex> -- eId access template     [root], [req]\n"
		"    -esign <4*hex> -- eSign access template  [root], [req]\n"
		"    -pass <scheme> -- password description   root, req, iss, match\n"
		"    -date <YYMMDD> -- validation date        [val]\n",
		_name, _descr
	);
	return -1;
}

/*
*******************************************************************************
Самотестирование
*******************************************************************************
*/

static err_t cvcSelfTest()
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
Разбор опций командной строки

Опции возвращаются по адресам cvc, pwd, date. Любой из адресов может быть
нулевым, и тогда соответствующая опция не возвращается. Более того, ее указание
в командной строке считается ошибкой.

В случае успеха по адресу readc возвращается число обработанных аргументов.
*******************************************************************************
*/

static err_t cvcParseOptions(btok_cvc_t* cvc, cmd_pwd_t* pwd, octet date[6],
	int* readc, int argc, char* argv[])
{
	err_t code = ERR_OK;
	bool_t eid = FALSE;
	bool_t esign = FALSE;
	// pre
	ASSERT(memIsNullOrValid(cvc, sizeof(btok_cvc_t)));
	ASSERT(memIsNullOrValid(pwd, sizeof(cmd_pwd_t)));
	ASSERT(memIsNullOrValid(date, 6));
	ASSERT(memIsValid(readc, sizeof(int)));
	// подготовить выходные данные
	cvc ? memSetZero(cvc, sizeof(btok_cvc_t)) : 0;
	pwd ? *pwd = 0 : 0;
	date ? memSetZero(date, 6) : 0;
	// обработать опции
	*readc = argc;
	while (argc && strStartsWith(*argv, "-"))
	{
		if (argc < 2)
		{
			code = ERR_CMD_PARAMS;
			break;
		}
		// authority
		if (strEq(argv[0], "-authority"))
		{
			if (!cvc)
			{
				code = ERR_CMD_PARAMS;
				break;
			}
			if (strLen(cvc->authority))
			{
				code = ERR_CMD_DUPLICATE;
				break;
			}
			--argc, ++argv;
			ASSERT(argc > 0);
			if (!strLen(*argv) || strLen(*argv) + 1 > sizeof(cvc->authority))
			{
				code = ERR_BAD_NAME;
				break;
			}
			strCopy(cvc->authority, *argv);
			--argc, ++argv;
		}
		// holder
		else if (strEq(argv[0], "-holder"))
		{
			if (!cvc)
			{
				code = ERR_CMD_PARAMS;
				break;
			}
			if (strLen(cvc->holder))
			{
				code = ERR_CMD_DUPLICATE;
				break;
			}
			--argc, ++argv;
			ASSERT(argc > 0);
			if (!strLen(*argv) || strLen(*argv) + 1 > sizeof(cvc->holder))
			{
				code = ERR_BAD_NAME;
				break;
			}
			strCopy(cvc->holder, *argv);
			--argc, ++argv;
		}
		// from
		else if (strEq(*argv, "-from"))
		{
			if (!cvc)
			{
				code = ERR_CMD_PARAMS;
				break;
			}
			if (!memIsZero(cvc->from, 6))
			{
				code = ERR_CMD_DUPLICATE;
				break;
			}
			--argc, ++argv;
			if (strLen(*argv) != 6 || !strIsNumeric(*argv))
			{
				code = ERR_BAD_DATE;
				break;
			}
			memCopy(cvc->from, *argv, 6);
			cvc->from[0] -= '0', cvc->from[1] -= '0', cvc->from[2] -= '0';
			cvc->from[3] -= '0', cvc->from[4] -= '0', cvc->from[5] -= '0';
			if (!tmDateIsValid2(cvc->from))
			{
				code = ERR_BAD_DATE;
				break;
			}
			--argc, ++argv;
		}
		// until
		else if (strEq(*argv, "-until"))
		{
			if (!cvc)
			{
				code = ERR_CMD_PARAMS;
				break;
			}
			if (!memIsZero(cvc->until, 6))
			{
				code = ERR_CMD_DUPLICATE;
				break;
			}
			--argc, ++argv;
			if (strLen(*argv) != 6 || !strIsNumeric(*argv))
			{
				code = ERR_BAD_DATE;
				break;
			}
			memCopy(cvc->until, *argv, 6);
			cvc->until[0] -= '0', cvc->until[1] -= '0', cvc->until[2] -= '0';
			cvc->until[3] -= '0', cvc->until[4] -= '0', cvc->until[5] -= '0';
			if (!tmDateIsValid2(cvc->until))
			{
				code = ERR_BAD_DATE;
				break;
			}
			--argc, ++argv;
		}
		// eid
		else if (strEq(*argv, "-eid"))
		{
			if (!cvc)
			{
				code = ERR_CMD_PARAMS;
				break;
			}
			if (eid)
			{
				code = ERR_CMD_DUPLICATE;
				break;
			}
			--argc, ++argv;
			if (strLen(*argv) != 10 || !hexIsValid(*argv))
			{
				code = ERR_BAD_ACL;
				break;
			}
			hexTo(cvc->hat_eid, *argv);
			eid = TRUE;
			--argc, ++argv;
		}
		// esign
		else if (strEq(*argv, "-esign"))
		{
			if (!cvc)
			{
				code = ERR_CMD_PARAMS;
				break;
			}
			if (esign)
			{
				code = ERR_CMD_DUPLICATE;
				break;
			}
			--argc, ++argv;
			if (strLen(*argv) != 4 || !hexIsValid(*argv))
			{
				code = ERR_BAD_ACL;
				break;
			}
			hexTo(cvc->hat_esign, *argv);
			esign = TRUE;
			--argc, ++argv;
		}
		// password
		else if (strEq(*argv, "-pass"))
		{
			if (!pwd)
			{
				code = ERR_CMD_PARAMS;
				break;
			}
			if (*pwd)
			{
				code = ERR_CMD_DUPLICATE;
				break;
			}
			--argc, ++argv;
			if ((code = cmdPwdRead(pwd, *argv)) != ERR_OK)
				break;
			--argc, ++argv;
		}
		// date
		else if (strEq(*argv, "-date"))
		{
			if (!date)
			{
				code = ERR_CMD_PARAMS;
				break;
			}
			if (!memIsZero(date, 6))
			{
				code = ERR_CMD_DUPLICATE;
				break;
			}
			--argc, ++argv;
			if (strLen(*argv) != 6 || !strIsNumeric(*argv))
			{
				code = ERR_BAD_DATE;
				break;
			}
			memCopy(date, *argv, 6);
			date[0] -= '0', date[1] -= '0', date[2] -= '0';
			date[3] -= '0', date[4] -= '0', date[5] -= '0';
			if (!tmDateIsValid2(date))
			{
				code = ERR_BAD_DATE;
				break;
			}
			--argc, ++argv;
		}
		else
		{
			code = ERR_CMD_PARAMS;
			break;
		}
	}
	// проверить, что запрошенные данные определены
	// \remark корректность cvc будет проверена позже
	// \remark параметр date не является обязательным
	if (code == ERR_OK && pwd && !*pwd)
		code = ERR_CMD_PARAMS;
	// завершить
	if (code != ERR_OK && pwd)
		cmdPwdClose(*pwd), *pwd = 0;
	else
		*readc -= argc;
	return code;
}

/*
*******************************************************************************
Выпуск самоподписанного сертификата

cvc root options <privkeya> <certa>
*******************************************************************************
*/

static err_t cvcRoot(int argc, char* argv[])
{
	err_t code;
	btok_cvc_t cvc;
	cmd_pwd_t pwd;
	int readc;
	size_t privkey_len;
	octet* privkey;
	size_t cert_len;
	octet* cert;
	// самотестирование
	code = cvcSelfTest();
	ERR_CALL_CHECK(code);
	// обработать опции
	code = cvcParseOptions(&cvc, &pwd, 0, &readc, argc, argv);
	ERR_CALL_CHECK(code);
	argc -= readc, argv += readc;
	if (argc != 2)
		code = ERR_CMD_PARAMS;
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	// доопределить cvc и проверить, что authority == holder
	if (!strLen(cvc.authority))
		strCopy(cvc.authority, cvc.holder);
	else if (!strLen(cvc.holder))
		strCopy(cvc.holder, cvc.authority);
	if (!strEq(cvc.authority, cvc.holder))
		code = ERR_BAD_NAME;
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	// проверить наличие/отсутствие файлов
	code = cmdFileValExist(1, argv);
	ERR_CALL_CHECK(code);
	code = cmdFileValNotExist(1, argv + 1);
	ERR_CALL_CHECK(code);
	// прочитать личный ключ
	privkey_len = 0;
	code = cmdPrivkeyRead(0, &privkey_len, argv[0], pwd);
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	code = cmdBlobCreate(privkey, privkey_len);
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	code = cmdPrivkeyRead(privkey, 0, argv[0], pwd);
	cmdPwdClose(pwd);
	ERR_CALL_HANDLE(code, cmdBlobClose(privkey));
	// определить длину сертификата
	ASSERT(cvc.pubkey_len == 0);
	code = btokCVCWrap(0, &cert_len, &cvc, privkey, privkey_len);
	ERR_CALL_HANDLE(code, cmdBlobClose(privkey));
	ASSERT(cvc.pubkey_len != 0);
	// создать сертификат
	code = cmdBlobCreate(cert, cert_len);
	ERR_CALL_HANDLE(code, cmdBlobClose(privkey));
	code = btokCVCWrap(cert, 0, &cvc, privkey, privkey_len);
	cmdBlobClose(privkey);
	ERR_CALL_HANDLE(code, cmdBlobClose(cert));
	// записать сертификат
	code = cmdFileWrite(argv[1], cert, cert_len);
	// завершить
	cmdBlobClose(cert);
	return code;
}

/*
*******************************************************************************
Создание предсертификата (запроса)

cvc req options <privkey> <req>
*******************************************************************************
*/

static err_t cvcReq(int argc, char* argv[])
{
	err_t code;
	btok_cvc_t cvc;
	cmd_pwd_t pwd;
	int readc;
	size_t privkey_len;
	octet* privkey;
	size_t req_len;
	octet* req;
	// самотестирование
	code = cvcSelfTest();
	ERR_CALL_CHECK(code);
	// обработать опции
	code = cvcParseOptions(&cvc, &pwd, 0, &readc, argc, argv);
	ERR_CALL_CHECK(code);
	argc -= readc, argv += readc;
	if (argc != 2)
		code = ERR_CMD_PARAMS;
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	// проверить, что authority != holder
	if (strEq(cvc.authority, cvc.holder))
		code = ERR_BAD_NAME;
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	// проверить наличие/отсутствие файлов
	code = cmdFileValExist(1, argv);
	ERR_CALL_CHECK(code);
	code = cmdFileValNotExist(1, argv + 1);
	ERR_CALL_CHECK(code);
	// прочитать личный ключ
	privkey_len = 0;
	code = cmdPrivkeyRead(0, &privkey_len, argv[0], pwd);
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	code = cmdBlobCreate(privkey, privkey_len);
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	code = cmdPrivkeyRead(privkey, 0, argv[0], pwd);
	cmdPwdClose(pwd);
	ERR_CALL_HANDLE(code, cmdBlobClose(privkey));
	// определить длину предсертификата
	ASSERT(cvc.pubkey_len == 0);
	code = btokCVCWrap(0, &req_len, &cvc, privkey, privkey_len);
	ERR_CALL_HANDLE(code, cmdBlobClose(privkey));
	ASSERT(cvc.pubkey_len != 0);
	// создать предсертификат
	code = cmdBlobCreate(req, req_len);
	ERR_CALL_HANDLE(code, cmdBlobClose(privkey));
	code = btokCVCWrap(req, 0, &cvc, privkey, privkey_len);
	cmdBlobClose(privkey);
	ERR_CALL_HANDLE(code, cmdBlobClose(req));
	// записать сертификат
	code = cmdFileWrite(argv[1], req, req_len);
	// завершить
	cmdBlobClose(req);
	return code;
}

/*
*******************************************************************************
Выпуск сертификата

cvc iss options <privkeya> <certa> <req> <cert>
*******************************************************************************
*/

static err_t cvcIss(int argc, char* argv[])
{
	err_t code;
	cmd_pwd_t pwd;
	int readc;
	size_t privkeya_len;
	octet* privkeya;
	size_t certa_len;
	size_t req_len;
	size_t cert_len;
	void* stack;
	octet* certa;
	octet* req;
	octet* cert;
	btok_cvc_t* cvc;
	// самотестирование
	code = cvcSelfTest();
	ERR_CALL_CHECK(code);
	// обработать опции
	code = cvcParseOptions(0, &pwd, 0, &readc, argc, argv);
	ERR_CALL_CHECK(code);
	argc -= readc, argv += readc;
	if (argc != 4)
		code = ERR_CMD_PARAMS;
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	// проверить наличие/отсутствие файлов
	code = cmdFileValExist(3, argv);
	ERR_CALL_CHECK(code);
	code = cmdFileValNotExist(1, argv + 3);
	ERR_CALL_CHECK(code);
	// прочитать личный ключ
	privkeya_len = 0;
	code = cmdPrivkeyRead(0, &privkeya_len, argv[0], pwd);
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	code = cmdBlobCreate(privkeya, privkeya_len);
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	code = cmdPrivkeyRead(privkeya, 0, argv[0], pwd);
	cmdPwdClose(pwd);
	ERR_CALL_HANDLE(code, cmdBlobClose(privkeya));
	// определить длины входных сертификата и запроса
	code = cmdFileReadAll(0, &certa_len, argv[1]);
	ERR_CALL_HANDLE(code, cmdBlobClose(privkeya));
	code = cmdFileReadAll(0, &req_len, argv[2]);
	ERR_CALL_HANDLE(code, cmdBlobClose(privkeya));
	// построить оценку сверху для cert_len: req_len + расширение_подписи
	cert_len = req_len + (96 - 48);
	// выделить память и разметить ее
	code = cmdBlobCreate(stack, certa_len + req_len + cert_len +
		sizeof(btok_cvc_t));
	ERR_CALL_HANDLE(code, cmdBlobClose(privkeya));
	certa = (octet*)stack;
	req = certa + certa_len;
	cert = req + req_len;
	cvc = (btok_cvc_t*)(cert + cert_len);
	// прочитать сертификат
	code = cmdFileReadAll(certa, &certa_len, argv[1]);
	ERR_CALL_HANDLE(code, (cmdBlobClose(privkeya), cmdBlobClose(stack)));
	// прочитать запрос
	code = cmdFileReadAll(req, &req_len, argv[2]);
	ERR_CALL_HANDLE(code, (cmdBlobClose(privkeya), cmdBlobClose(stack)));
	// разобрать запрос
	code = btokCVCUnwrap(cvc, req, req_len, cvc->pubkey, 0);
	ERR_CALL_HANDLE(code, (cmdBlobClose(privkeya), cmdBlobClose(stack)));
	// выпустить сертификат
	code = btokCVCIss(cert, &cert_len, cvc, certa, certa_len, privkeya,
		privkeya_len);
	ASSERT(cert_len <= req_len + 96 - 48);
	cmdBlobClose(privkeya);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// записать сертификат
	code = cmdFileWrite(argv[3], cert, cert_len);
	// завершить
	cmdBlobClose(stack);
	return code;
}

/*
*******************************************************************************
Проверка

cvc val options <certa> <certb> ... <cert>
*******************************************************************************
*/

static err_t cvcVal(int argc, char* argv[])
{
	err_t code;
	octet date[6];
	int readc;
	const size_t cert_max_len = 512;
	size_t cert_len;
	void* stack;
	octet* cert;
	btok_cvc_t* cvc;
	btok_cvc_t* cvc1;
	// самотестирование
	code = cvcSelfTest();
	ERR_CALL_CHECK(code);
	// обработать опции
	code = cvcParseOptions(0, 0, date, &readc, argc, argv);
	ERR_CALL_CHECK(code);
	argc -= readc, argv += readc;
	if (argc < 2)
		code = ERR_CMD_PARAMS;
	ERR_CALL_CHECK(code);
	// обработать дату
	if (memIsZero(date, 6) && !tmDate2(date))
		code = ERR_BAD_TIMER;
	ERR_CALL_CHECK(code);
	// проверить наличие/отсутствие файлов
	code = cmdFileValExist(argc, argv);
	ERR_CALL_CHECK(code);
	// выделить память и разметить ее
	code = cmdBlobCreate(stack, cert_max_len + 2 * sizeof(btok_cvc_t));
	ERR_CALL_CHECK(code);
	cert = (octet*)stack;
	cvc = (btok_cvc_t*)(cert + cert_max_len);
	cvc1 = cvc + 1;
	// прочитать первый сертификат
	code = cmdFileReadAll(0, &cert_len, argv[0]);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	code = cert_len <= cert_max_len ? ERR_OK : ERR_BAD_CERT;
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	code = cmdFileReadAll(cert, &cert_len, argv[0]);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// разобрать первый сертификат
	code = btokCVCUnwrap(cvc, cert, cert_len, 0, 0);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// цикл по сертификатам
	for (--argc, ++argv; argc--; ++argv)
	{
		// прочитать очередной сертификат
		code = cmdFileReadAll(0, &cert_len, *argv);
		ERR_CALL_HANDLE(code, cmdBlobClose(stack));
		code = cert_len <= cert_max_len ? ERR_OK : ERR_BAD_CERT;
		ERR_CALL_HANDLE(code, cmdBlobClose(stack));
		code = cmdFileReadAll(cert, &cert_len, *argv);
		ERR_CALL_HANDLE(code, cmdBlobClose(stack));
		// проверить очередной сертификат
		code = btokCVCVal2(cvc1, cert, cert_len, cvc, 
			argc == 0 ? date : 0);
		ERR_CALL_HANDLE(code, cmdBlobClose(stack));
		// подготовиться к проверке следующего сертификата
		memCopy(cvc, cvc1, sizeof(btok_cvc_t));
	}
	// завершить
	cmdBlobClose(stack);
	return code;
}

/*
*******************************************************************************
Выпуск сертификата

cvc match options <privkey> <cert>
*******************************************************************************
*/

static err_t cvcMatch(int argc, char* argv[])
{
	err_t code;
	cmd_pwd_t pwd;
	int readc;
	size_t privkey_len;
	octet* privkey;
	size_t cert_len;
	octet* cert;
	// самотестирование
	code = cvcSelfTest();
	ERR_CALL_CHECK(code);
	// обработать опции
	code = cvcParseOptions(0, &pwd, 0, &readc, argc, argv);
	ERR_CALL_CHECK(code);
	argc -= readc, argv += readc;
	if (argc != 2)
		code = ERR_CMD_PARAMS;
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	// проверить наличие/отсутствие файлов
	code = cmdFileValExist(2, argv);
	ERR_CALL_CHECK(code);
	// прочитать личный ключ
	privkey_len = 0;
	code = cmdPrivkeyRead(0, &privkey_len, argv[0], pwd);
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	code = cmdBlobCreate(privkey, privkey_len);
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	code = cmdPrivkeyRead(privkey, 0, argv[0], pwd);
	cmdPwdClose(pwd);
	ERR_CALL_HANDLE(code, cmdBlobClose(privkey));
	// определить длину сертификата
	code = cmdFileReadAll(0, &cert_len, argv[1]);
	ERR_CALL_HANDLE(code, cmdBlobClose(privkey));
	// прочитать сертификат
	code = cmdBlobCreate(cert, cert_len);
	ERR_CALL_HANDLE(code, cmdBlobClose(privkey));
	code = cmdFileReadAll(cert, &cert_len, argv[1]);
	ERR_CALL_HANDLE(code, (cmdBlobClose(privkey), cmdBlobClose(cert)));
	// проверить соответствие
	code = btokCVCMatch(cert, cert_len, privkey, privkey_len);
	// завершить
	cmdBlobClose(cert);
	cmdBlobClose(privkey);
	return code;
}

/*
*******************************************************************************
Печать

cvc print <cert>
*******************************************************************************
*/

static err_t cvcPrint(int argc, char* argv[])
{
	err_t code;
	size_t cert_len;
	void* stack;
	octet* cert;
	btok_cvc_t* cvc;
	// обработать опции
	if (argc != 1)
		return ERR_CMD_PARAMS;
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
	code = cmdCVCPrint(cvc);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// завершить
	cmdBlobClose(stack);
	return ERR_OK;
}

/*
*******************************************************************************
Главная функция
*******************************************************************************
*/

int cvcMain(int argc, char* argv[])
{
	err_t code;
	// справка
	if (argc < 2)
		return cvcUsage();
	// разбор команды
	++argv, --argc;
	if (strEq(argv[0], "root"))
		code = cvcRoot(argc - 1, argv + 1);
	else if (strEq(argv[0], "req"))
		code = cvcReq(argc - 1, argv + 1);
	else if (strEq(argv[0], "iss"))
		code = cvcIss(argc - 1, argv + 1);
	else if (strEq(argv[0], "val"))
		code = cvcVal(argc - 1, argv + 1);
	else if (strEq(argv[0], "match"))
		code = cvcMatch(argc - 1, argv + 1);
	else if (strEq(argv[0], "print"))
		code = cvcPrint(argc - 1, argv + 1);
	else
		code = ERR_CMD_NOT_FOUND;
	// завершить
	if (code != ERR_OK || 
		code == ERR_OK && (strEq(argv[0], "val") || strEq(argv[0], "match")))
		printf("bee2cmd/%s: %s\n", _name, errMsg(code));
	return (int)code;
}

/*
*******************************************************************************
Инициализация
*******************************************************************************
*/

err_t cvcInit()
{
	return cmdReg(_name, _descr, cvcMain);
}
