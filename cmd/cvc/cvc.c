/*
*******************************************************************************
\file cvc.c
\brief Manage CV-certificates
\project bee2/cmd 
\created 2022.07.12
\version 2023.12.17
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
  # подготовка ключей
  bee2cmd kg gen -l256 -pass pass:root privkey0
  bee2cmd kg gen -l192 -pass pass:trent privkey1
  bee2cmd kg gen -pass pass:alice privkey2
  bee2cmd kg extr -pass pass:alice privkey2 pubkey2
  # выпуск сертификатов
  bee2cmd cvc root -authority BYCA0000 -from 220707 -until 990707 \
    -pass pass:root -eid EEEEEEEEEE -esign 7777 privkey0 cert0
  bee2cmd cvc print cert0
  bee2cmd cvc print -holder cert0
  bee2cmd cvc extr cert0 pubkey0
  bee2cmd cvc req -pass pass:trent -authority BYCA0000 -holder BYCA1023 \
    -from 220712 -until 221130 -eid DDDDDDDDDD -esign 3333 privkey1 req1
  bee2cmd cvc iss -pass pass:root privkey0 cert0 req1 cert1
  bee2cmd cvc req -authority BYCA1023 -from 220712 -until 391231 -esign 1111 \
    -holder 590082394654 -pass pass:alice -eid 8888888888 privkey2 req2
  bee2cmd cvc iss -pass pass:trent privkey1 cert1 req2 cert2
  # проверка сертификатов
  bee2cmd cvc match -pass pass:alice privkey2 cert2
  bee2cmd cvc val cert0 cert0
  bee2cmd cvc val -date 220712 cert0 cert1
  bee2cmd cvc val -date 000000 cert0 cert1 cert2
  # сокращение срока действия
  bee2cmd cvc shorten -until 391230 -pass pass:trent privkey1 cert1 cert2
*******************************************************************************
*/

static const char _name[] = "cvc";
static const char _descr[] = "manage CV-certificates";

static int cvcUsage()
{
	printf(
		"bee2cmd/%s: %s\n"
		"Usage:\n"
		"  cvc root [options] <privkeya> <certa>\n"
		"    issue a self-signed certificate <certa>\n"
		"  cvc req [options] <privkey> <req>\n"
		"    generate a pre-certificate <req>\n"
		"  cvc iss [options] <privkeya> <certa> <req> <cert>\n"
		"    issue <cert> based on <req> and subordinate to <certa>\n"
		"  cvc shorten [options] <privkeya> <certa> <cert>\n"
		"    shorten the lifetime of <cert> subordinate to <certa>\n"
		"  cvc val [options] <certa> <certb> ... <cert>\n"
		"    validate <certb> ... <cert> using <certa> as an anchor\n"
		"  cvc match [options] <privkey> <cert>\n"
		"    check the match between <privkey> and <cert>\n"
		"  cvc extr <cert> <pubkey>\n"
		"    extract <pubkey> from <cert>\n"
		"  cvc print [field] <cert>\n"
		"    print <cert> info: all fields or a specific field\n"
		"  .\n"
		"  <privkey>, <privkeya>\n"
		"    containers with private keys\n"
		"  <pubkey>\n"
		"    file with a public key\n"
		"  options:\n"
		"    -authority <name> -- authority       [root] req\n"
		"    -holder <name> -- holder             [root] req [iss]\n"
		"    -from <YYMMDD> -- starting date      root req [iss]\n"
		"    -until <YYMMDD> -- expiration date   root req [iss] cut\n"
		"    -eid <10*hex> -- eId access mask     [root] [req] [iss]\n"
		"    -esign <4*hex> -- eSign access mask  [root] [req] [iss]\n"
		"    -pass <schema> -- password           root req iss shorten match\n"
		"    -date <YYMMDD> -- validation date    [val]\n"
		"  field:\n"
		"    {-authority|-holder|-from|-until|-eid|-esign|-pubkey|-sig}\n"
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
	if (bignParamsStd(params, "1.2.112.0.2.0.34.101.45.3.1") != ERR_OK ||
		bignKeypairGen(privkey, pubkey, params, prngEchoStepR,
			stack) != ERR_OK ||
		!hexEq(pubkey,
		"BD1A5650179D79E03FCEE49D4C2BD5DD"
		"F54CE46D0CF11E4FF87BF7A890857FD0"
		"7AC6A60361E8C8173491686D461B2826"
		"190C2EDA5909054A9AB84D2AB9D99A90"))
		return ERR_SELFTEST;
	// bign-valpubkey
	if (bignPubkeyVal(params, pubkey) != ERR_OK)
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

По адресам eid и esign возвращаются признаки наличия в командной строке
одноименных опций. При указании нулевого адреса наличие в командной строке
соответствующей опции считается ошибкой. Передача ненулевого eid (ожидаются
флаги доступа к eId) и нулевого cvc (флаги некуда сохранить) является ошибкой.
Логика распространяется на указатель esign.

Передача ненулевого pwd является запросом на построение пароля по параметрам
командной строки. Запрос должен быть обязательно исполнен.

В случае успеха по адресу readc возвращается число обработанных аргументов.
*******************************************************************************
*/

static err_t cvcParseOptions(btok_cvc_t* cvc, bool_t* eid, bool_t* esign, 
	cmd_pwd_t* pwd, octet date[6], int* readc, int argc, char* argv[])
{
	err_t code = ERR_OK;
	// pre
	ASSERT(memIsNullOrValid(cvc, sizeof(btok_cvc_t)));
	ASSERT(memIsNullOrValid(eid, sizeof(bool_t)));
	ASSERT(memIsNullOrValid(esign, sizeof(bool_t)));
	ASSERT(memIsNullOrValid(pwd, sizeof(cmd_pwd_t)));
	ASSERT(memIsNullOrValid(date, 6));
	ASSERT(memIsValid(readc, sizeof(int)));
	// подготовить выходные данные
	cvc ? memSetZero(cvc, sizeof(btok_cvc_t)) : 0;
	eid ? *eid = 0 : 0;
	esign ? *esign = 0 : 0;
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
			ASSERT(argc > 0);
			code = cmdDateParse(cvc->from, *argv);
			if (code != ERR_OK)
				break;
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
			ASSERT(argc > 0);
			code = cmdDateParse(cvc->until, *argv);
			if (code != ERR_OK)
				break;
			--argc, ++argv;
		}
		// eid
		else if (strEq(*argv, "-eid"))
		{
			if (!cvc || !eid)
			{
				code = ERR_CMD_PARAMS;
				break;
			}
			if (*eid)
			{
				code = ERR_CMD_DUPLICATE;
				break;
			}
			--argc, ++argv;
			ASSERT(argc > 0);
			if (strLen(*argv) != 10 || !hexIsValid(*argv))
			{
				code = ERR_BAD_ACL;
				break;
			}
			hexTo(cvc->hat_eid, *argv);
			*eid = TRUE;
			--argc, ++argv;
		}
		// esign
		else if (strEq(*argv, "-esign"))
		{
			if (!cvc || !esign)
			{
				code = ERR_CMD_PARAMS;
				break;
			}
			if (*esign)
			{
				code = ERR_CMD_DUPLICATE;
				break;
			}
			--argc, ++argv;
			ASSERT(argc > 0);
			if (strLen(*argv) != 4 || !hexIsValid(*argv))
			{
				code = ERR_BAD_ACL;
				break;
			}
			hexTo(cvc->hat_esign, *argv);
			*esign = TRUE;
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
			ASSERT(argc > 0);
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
			ASSERT(argc > 0);
			code = cmdDateParse(date, *argv);
			if (code != ERR_OK)
				break;
			--argc, ++argv;
		}
		else
		{
			code = ERR_CMD_PARAMS;
			break;
		}
	}
	// проверить, что запрошенные данные определены
	// \\remark корректность cvc будет проверена позже
	// \\remark параметр date не является обязательным
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

cvc root [options] <privkeya> <certa>

\remark Обязательные опции: pass, authority и/или holder, from, until.
Разрешенные: eid, esign.
*******************************************************************************
*/

static err_t cvcRoot(int argc, char* argv[])
{
	err_t code;
	btok_cvc_t cvc[1];
	bool_t eid;
	bool_t esign;
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
	code = cvcParseOptions(cvc, &eid, &esign, &pwd, 0, &readc, argc, argv);
	ERR_CALL_CHECK(code);
	argc -= readc, argv += readc;
	if (argc != 2)
		code = ERR_CMD_PARAMS;
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	// доопределить cvc и проверить, что authority == holder
	if (!strLen(cvc->authority))
		strCopy(cvc->authority, cvc->holder);
	else if (!strLen(cvc->holder))
		strCopy(cvc->holder, cvc->authority);
	if (!strEq(cvc->authority, cvc->holder))
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
	ASSERT(cvc->pubkey_len == 0);
	code = btokCVCWrap(0, &cert_len, cvc, privkey, privkey_len);
	ERR_CALL_HANDLE(code, cmdBlobClose(privkey));
	ASSERT(cvc->pubkey_len != 0);
	// создать сертификат
	code = cmdBlobCreate(cert, cert_len);
	ERR_CALL_HANDLE(code, cmdBlobClose(privkey));
	code = btokCVCWrap(cert, 0, cvc, privkey, privkey_len);
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

cvc req [options] <privkey> <req>

\remark Обязательные опции: pass, authority, holder, from, until.
Разрешенные: eid, esign.
*******************************************************************************
*/

static err_t cvcReq(int argc, char* argv[])
{
	err_t code;
	btok_cvc_t cvc[1];
	bool_t eid;
	bool_t esign;
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
	code = cvcParseOptions(cvc, &eid, &esign, &pwd, 0, &readc, argc, argv);
	ERR_CALL_CHECK(code);
	argc -= readc, argv += readc;
	if (argc != 2)
		code = ERR_CMD_PARAMS;
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	// проверить, что authority != holder
	if (strEq(cvc->authority, cvc->holder))
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
	ASSERT(cvc->pubkey_len == 0);
	code = btokCVCWrap(0, &req_len, cvc, privkey, privkey_len);
	ERR_CALL_HANDLE(code, cmdBlobClose(privkey));
	ASSERT(cvc->pubkey_len != 0);
	// создать предсертификат
	code = cmdBlobCreate(req, req_len);
	ERR_CALL_HANDLE(code, cmdBlobClose(privkey));
	code = btokCVCWrap(req, 0, cvc, privkey, privkey_len);
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

cvc iss [options] <privkeya> <certa> <req> <cert>

\remark Обязательные опции: pass.
Разрешенные: holder, from, until, eid, esign.

\remark Поле holder в командной строке подавляет одноименное поле в <req>.
Другими словами, эмитент может изменять имя владельца в его сертификате.
Например, имеется последовательность имен, и эмитент выбирает в ней первое
неиспользованное имя.

\remark Поля from и until в командной строке подавляют одноименные поля
в <req>. Другими словами, эмитент может изменять срок действия сертификата.

\remark Поля eid и esign в командной строке накладываются побитово по правилу
AND на одноименные поля в <req>. Другими словами, эмитент может ужесточать
права доступа, например, cледуя определенной политике доступа.
*******************************************************************************
*/

static err_t cvcIss(int argc, char* argv[])
{
	err_t code;
	btok_cvc_t cvc0[1];
	bool_t eid;
	bool_t esign;
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
	code = cvcParseOptions(cvc0, &eid, &esign, &pwd, 0, &readc, argc, argv);
	ERR_CALL_CHECK(code);
	// есть запрещенные опции?
	if (strLen(cvc0->authority))
		code = ERR_CMD_PARAMS;
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	// некорректное число аргументов?
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
	// перенести в сертификат опции командной строки
	if (strLen(cvc0->holder))
		strCopy(cvc->holder, cvc0->holder);
	if (!memIsZero(cvc0->from, 6))
		memCopy(cvc->from, cvc0->from, 6);
	if (!memIsZero(cvc0->until, 6))
		memCopy(cvc->until, cvc0->until, 6);
	if (eid)
	{
		size_t pos;
		for (pos = 0; pos < sizeof(cvc->hat_eid); ++pos)
			cvc->hat_eid[pos] &= cvc0->hat_eid[pos];
	}
	if (esign)
	{
		size_t pos;
		for (pos = 0; pos < sizeof(cvc->hat_esign); ++pos)
			cvc->hat_esign[pos] &= cvc0->hat_esign[pos];
	}
	// выпустить сертификат
	code = btokCVCIss(cert, &cert_len, cvc, certa, certa_len, privkeya,
		privkeya_len);
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
Сокращение срока действия сертификата

cvc shorten [options] <privkeya> <certa> <cert>

\remark Обязательные опции: pass, until.
*******************************************************************************
*/

static err_t cvcShorten(int argc, char* argv[])
{
	err_t code;
	btok_cvc_t cvc0[1];
	cmd_pwd_t pwd;
	int readc;
	size_t privkeya_len;
	octet* privkeya;
	size_t certa_len;
	size_t cert_len;
	void* stack;
	octet* certa;
	octet* cert;
	btok_cvc_t* cvc;
	// самотестирование
	code = cvcSelfTest();
	ERR_CALL_CHECK(code);
	// обработать опции
	code = cvcParseOptions(cvc0, 0, 0, &pwd, 0, &readc, argc, argv);
	ERR_CALL_CHECK(code);
	// нужные опции установлены и нет запрещенных опций?
	if (strLen(cvc0->authority) || strLen(cvc0->holder) ||
		!memIsZero(cvc0->from, 6) || memIsZero(cvc0->until, 6))
		code = ERR_CMD_PARAMS;
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	// некорректное число аргументов?
	argc -= readc, argv += readc;
	if (argc != 3)
		code = ERR_CMD_PARAMS;
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	// проверить наличие/отсутствие файлов
	code = cmdFileValExist(3, argv);
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
	// определить длины сертификатов
	code = cmdFileReadAll(0, &certa_len, argv[1]);
	ERR_CALL_HANDLE(code, cmdBlobClose(privkeya));
	code = cmdFileReadAll(0, &cert_len, argv[2]);
	ERR_CALL_HANDLE(code, cmdBlobClose(privkeya));
	// выделить память и разметить ее
	code = cmdBlobCreate(stack, certa_len + cert_len + sizeof(btok_cvc_t));
	ERR_CALL_HANDLE(code, cmdBlobClose(privkeya));
	certa = (octet*)stack;
	cert = certa + certa_len;
	cvc = (btok_cvc_t*)(cert + cert_len);
	// прочитать сертификаты
	code = cmdFileReadAll(certa, &certa_len, argv[1]);
	ERR_CALL_HANDLE(code, (cmdBlobClose(privkeya), cmdBlobClose(stack)));
	code = cmdFileReadAll(cert, &cert_len, argv[2]);
	ERR_CALL_HANDLE(code, (cmdBlobClose(privkeya), cmdBlobClose(stack)));
	// проверить сертификат
	code = btokCVCVal(cert, cert_len, certa, certa_len, 0);
	ERR_CALL_HANDLE(code, (cmdBlobClose(privkeya), cmdBlobClose(stack)));
	// разобрать сертификат
	code = btokCVCUnwrap(cvc, cert, cert_len, 0, 0);
	ERR_CALL_HANDLE(code, (cmdBlobClose(privkeya), cmdBlobClose(stack)));
	// срок действия действительно сокращается?
	if (memCmp(cvc->until, cvc0->until, 6) < 0)
		code = ERR_BAD_DATE;
	ERR_CALL_HANDLE(code, (cmdBlobClose(privkeya), cmdBlobClose(stack)));
	// перенести в сертификат новую дату окончания
	memCopy(cvc->until, cvc0->until, 6);
	// выпустить сертификат
	code = btokCVCIss(cert, 0, cvc, certa, certa_len, privkeya,	privkeya_len);
	cmdBlobClose(privkeya);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// записать сертификат
	code = cmdFileWrite(argv[2], cert, cert_len);
	// завершить
	cmdBlobClose(stack);
	return code;
}

/*
*******************************************************************************
Проверка цепочки

cvc val [options] <certa> <certb> ... <cert>

\remark Разрешенные опции: date.
  
\remark Дата проверки, указанная в options, касается только последнего
сертификата цепочки -- дата должна попадать в срок действия сертификата.
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
	code = cvcParseOptions(0, 0, 0, 0, date, &readc, argc, argv);
	ERR_CALL_CHECK(code);
	argc -= readc, argv += readc;
	if (argc < 2)
		code = ERR_CMD_PARAMS;
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
		if (argc == 0 && !memIsZero(date, 6))
			code = btokCVCVal2(cvc1, cert, cert_len, cvc, date);
		else 
			code = btokCVCVal2(cvc1, cert, cert_len, cvc, 0);
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
Проверка соответствия между личным ключом и сертификатом

cvc match [options] <privkey> <cert>

\remark Обязательные опции: pass.
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
	code = cvcParseOptions(0, 0, 0, &pwd, 0, &readc, argc, argv);
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
Извлечение открытого ключа

cvc extr <cert> <pubkey>
*******************************************************************************
*/

static err_t cvcExtr(int argc, char* argv[])
{
	err_t code;
	size_t cert_len;
	void* stack;
	octet* cert;
	btok_cvc_t* cvc;
	// обработать опции
	if (argc != 2)
		return ERR_CMD_PARAMS;
	// проверить наличие/отсутствие файлов
	code = cmdFileValExist(1, argv);
	ERR_CALL_CHECK(code);
	code = cmdFileValNotExist(1, argv + 1);
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
	// сохранить открытый ключ
	code = cmdFileWrite(argv[1], cvc->pubkey, cvc->pubkey_len);
	// завершить
	cmdBlobClose(stack);
	return code;
}

/*
*******************************************************************************
Печать

cvc print [-{authority|holder|from|until|eid|esign|pubkey|sig}] <cert>
*******************************************************************************
*/

static err_t cvcPrint(int argc, char* argv[])
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
	else if (strEq(argv[0], "shorten"))
		code = cvcShorten(argc - 1, argv + 1);
	else if (strEq(argv[0], "val"))
		code = cvcVal(argc - 1, argv + 1);
	else if (strEq(argv[0], "match"))
		code = cvcMatch(argc - 1, argv + 1);
	else if (strEq(argv[0], "extr"))
		code = cvcExtr(argc - 1, argv + 1);
	else if (strEq(argv[0], "print"))
		code = cvcPrint(argc - 1, argv + 1);
	else
		code = ERR_CMD_NOT_FOUND;
	// завершить
	if (code != ERR_OK || strEq(argv[0], "val") || strEq(argv[0], "match"))
		printf("bee2cmd/%s: %s\n", _name, errMsg(code));
	return code != ERR_OK ? -1 : 0;
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
