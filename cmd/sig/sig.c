/*
*******************************************************************************
\file sig.c
\brief Sign files and verify signatures
\project bee2/cmd
\created 2022.08.01
\version 2022.10.27
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "../cmd.h"
#include <bee2/core/blob.h>
#include <bee2/core/err.h>
#include <bee2/core/mem.h>
#include <bee2/core/hex.h>
#include <bee2/core/prng.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include <bee2/crypto/belt.h>
#include <bee2/crypto/bign.h>
#include <stdio.h>

/*
*******************************************************************************
Утилита sig

Функционал:
- выработка ЭЦП;
- проверка ЭЦП;
- печать ЭЦП.

Пример:
[подготовка ключей]
  bee2cmd kg gen -l256 -pass pass:root privkey0
  bee2cmd kg gen -l192 -pass pass:trent privkey1
  bee2cmd kg gen -pass pass:alice privkey2
  bee2cmd kg pub -pass pass:alice pubkey2
[выпуск сертификатов]
  bee2cmd cvc root -authority BYCA0000 -from 220707 -until 990707 \
    -pass pass:root -eid EEEEEEEEEE -esign 7777 privkey0 cert0
  bee2cmd cvc print cert0
  bee2cmd cvc req -pass pass:trent  -authority BYCA0000 -holder BYCA1000 \
    -from 220712 -until 221130 -eid DDDDDDDDDD -esign 3333 privkey1 req1
  bee2cmd cvc iss -pass pass:root privkey0 cert0 req1 cert1
  bee2cmd cvc req -authority BYCA1000 -from 220712 -until 391231 -esign 1111 \
    -holder "590082394654" -pass pass:alice -eid 8888888888 privkey2 req2
  bee2cmd cvc iss -pass pass:trent privkey1 cert1 req2 cert2
[внешняя подпись]
  bee2cmd sig sign -certs "cert2 cert1 cert0" -pass pass:alice privkey2 \
    file sig_file
  bee2cmd sig vfy -anchor cert0 file sig_file
  bee2cmd sig vfy -pubkey pubkey2 file sig_file
  bee2cmd sig print sig_file
[встроенная подпись]
  bee2cmd sig sign -certs "cert2 cert1 cert0" -pass pass:alice privkey2 \
    file file
  bee2cmd sig vfy -anchor cert0 file file
  bee2cmd sig vfy -pubkey pubkey2 file file
  bee2cmd sig print file
*******************************************************************************
*/

static const char _name[] = "sig";
static const char _descr[] = "sign files and verify signatures";

/*
*******************************************************************************
Справка по использованию
*******************************************************************************
*/
static int sigUsage()
{
    printf(
        "bee2cmd/%s: %s\n"
        "Usage:\n"
        "  sig sign [-certs <certs>] -pass <scheme> <privkey> <file> <sig>\n"
        "    sign <file> using <privkey> and store the signature in <sig>\n"
		"  sig vfy {-pubkey <pubkey> | -anchor <anchor>} <file> <sig>\n"
		"    verify <sig> of <file> using either <pubkey> or <anchor>\n"
		"  sig print <sig>\n"
		"    print a signature stored in <sig>\n"
		"  .\n"
		"  <privkey>\n"
        "    container with a private key\n"
		"  <pubkey>\n"
		"    file with a public key in hex\n"
		"  <anchor>\n"
		"    file with a trusted sertificate\n"
		"  options:\n"
        "    -certs <certs> -- certificate chain\n"
        "    -pass <scheme> -- password description\n",
        _name, _descr
    );
    return -1;
}

/*
*******************************************************************************
Самотестирование
*******************************************************************************
*/

static err_t sigSelfTest()
{
	octet state[1024];
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
	ASSERT(sizeof(state) >= prngEcho_keep());
	prngEchoStart(state, privkey, 32);
	if (bignStdParams(params, "1.2.112.0.2.0.34.101.45.3.1") != ERR_OK ||
		bignGenKeypair(privkey, pubkey, params, prngEchoStepR,
			state) != ERR_OK ||
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
Выработка подписи

 sig sign [-certs <certs>] -pass <scheme> <file> <sig>
*******************************************************************************
*/

static err_t sigSign(int argc, char* argv[])
{
	err_t code;
	const char* certs = 0;
	cmd_pwd_t pwd = 0;
	size_t privkey_len;
	octet* privkey;
	// самотестирование
	code = sigSelfTest();
	ERR_CALL_CHECK(code);
	// разобрать опции
	while (argc && strStartsWith(*argv, "-"))
	{
		if (argc < 2)
		{
			code = ERR_CMD_PARAMS;
			break;
		}
		if (strStartsWith(*argv, "-certs"))
		{
			if (certs)
			{
				code = ERR_CMD_DUPLICATE;
				break;
			}
			++argv, --argc;
			ASSERT(argc > 0);
			certs = *argv;
			++argv, --argc;
		}
		else if (strStartsWith(*argv, "-pass"))
		{
			if (pwd)
			{
				code = ERR_CMD_DUPLICATE;
				break;
			}
			++argv, --argc;
			ASSERT(argc > 0);
			code = cmdPwdRead(&pwd, *argv);
			if (code != ERR_OK)
				break;
			ASSERT(cmdPwdIsValid(pwd));
			++argv, --argc;
		}
		else
		{
			code = ERR_CMD_PARAMS;
			break;
		}
	}
	if (code == ERR_OK && (!pwd || argc != 3))
		code = ERR_CMD_PARAMS;
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	// проверить наличие <privkey> и <file>
	code = cmdFileValExist(2, argv);
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	// получить разрешение на перезапись <sig>
	if (!cmdFileAreSame(argv[1], argv[2]))
	{
		code = cmdFileValNotExist(1, argv + 2);
		ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	}
	// прочитать личный ключ
	privkey_len = 0;
	code = cmdPrivkeyRead(0, &privkey_len, argv[0], pwd);
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	code = cmdBlobCreate(privkey, privkey_len);
	ERR_CALL_HANDLE(code, cmdPwdClose(pwd));
	code = cmdPrivkeyRead(privkey, 0, argv[0], pwd);
	cmdPwdClose(pwd);
	ERR_CALL_HANDLE(code, cmdBlobClose(privkey));
	// подписать
	code = cmdSigSign(argv[2], argv[1], certs, privkey, privkey_len);
	// завершить
	cmdBlobClose(privkey);
	return code;
}

/*
*******************************************************************************
Проверка подписи

 sig vfy {-pubkey <pubkey> | -anchor <anchor>} <file> <sig>
*******************************************************************************
*/

static err_t sigVfy(int argc, char* argv[])
{
	err_t code;
	size_t count;
	octet* stack;
	// самотестирование
	code = sigSelfTest();
	ERR_CALL_CHECK(code);
	// проверить опции
	if (argc != 4 ||
		!strEq(argv[0], "-pubkey") && !strEq(argv[0], "-anchor"))
		return ERR_CMD_PARAMS;
	// проверить наличие {<pubkey> | <anchor>} <file> <sig>
	code = cmdFileValExist(3, argv + 1);
	ERR_CALL_CHECK(code);
	// прочитать pubkey / anchor
	code = cmdFileReadAll(0, &count, argv[1]);
	ERR_CALL_CHECK(code);
	code = cmdBlobCreate(stack, count);
	ERR_CALL_CHECK(code);
	code = cmdFileReadAll(stack, &count, argv[1]);
	ERR_CALL_CHECK(code);
	// проверить подпись
	if (strEq(argv[0], "-pubkey"))
		code = cmdSigVerify(argv[2], argv[3], stack, count);
	else
		code = cmdSigVerify2(argv[2], argv[3], stack, count);
	// завершить
	cmdBlobClose(stack);
	return code;
}

/*
*******************************************************************************
 Печать подписи

 sig print <sig>
*******************************************************************************
*/

static err_t sigPrint(int argc, char * argv[])
{
	err_t code;
	// обработать опции
	if (argc != 1)
		return ERR_CMD_PARAMS;
	// проверить наличие файла подписи
	code = cmdFileValExist(1, argv);
	ERR_CALL_CHECK(code);
	// печатать подпись
	return cmdSigPrint(argv[0]);
}

/*
*******************************************************************************
  Главная функция
*******************************************************************************
*/

static int sigMain(int argc, char* argv[])
{
    err_t code;
	// справка
    if (argc < 2)
        return sigUsage();
	// разбор команды
    --argc, ++argv;
    if (strEq(argv[0], "sign"))
        code = sigSign(argc - 1, argv + 1);
    else if (strEq(argv[0], "vfy"))
        code = sigVfy(argc - 1, argv + 1);
    else if (strEq(argv[0], "print"))
        code = sigPrint(argc - 1, argv + 1);
    else
		code = ERR_CMD_NOT_FOUND;
	// завершить
	if (code != ERR_OK ||
		code == ERR_OK && strEq(argv[0], "vfy"))
		printf("bee2cmd/%s: %s\n", _name, errMsg(code));
	return (int)code;
}

err_t sigInit()
{
    return cmdReg(_name, _descr, sigMain);
}
