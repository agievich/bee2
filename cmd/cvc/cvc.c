/*
*******************************************************************************
\file cvc.c
\brief Manage CV-certificates
\project bee2/cmd 
\created 2022.07.12
\version 2022.07.12
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "../cmd.h"
#include <bee2/core/blob.h>
#include <bee2/core/dec.h>
#include <bee2/core/err.h>
#include <bee2/core/hex.h>
#include <bee2/core/mem.h>
#include <bee2/core/prng.h>
#include <bee2/core/rng.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include <bee2/crypto/bign.h>
#include <bee2/crypto/btok.h>
#include <stdio.h>

/*
*******************************************************************************
Утилита cvc

Функционал:
- выпуск самоподписанного сертификата;
- выпуск предсертификата (запроса на выпуск);
- выпуск сертификата;
- проверка цепочки сертификатов;
- печать полей сертификата.

Примеры:
  bee2cmd cvc print cert
*******************************************************************************
*/

static const char _name[] = "cvc";
static const char _descr[] = "manage CV-certificates";

static int cvcUsage()
{
	printf(
		"bee2cmd/%s: %s\n"
		"Usage:\n"
		"  cvc root <data> -pass <scheme> <privkeya> <certa>\n"
		"    issue a self-signed certificate <certa> using <privkeya>\n"
		"  cvc req <data> -pass <scheme> <privkey> <req>\n"
		"    generate a pre-certificate <req> using <privkey>\n"
		"  cvc iss -pass <scheme> <privkeya> <certa> <req> <cert>\n"
		"    process <req> and issue <cert> subordinate to <certa> using <privkeya>\n"
		"  cvc val [-date <YYMMDD>] <certa> <certb> ... <cert>\n"
		"    validate <certb> ... <cert> using <certa> as an anchor\n"
		"  cvc print <cert>\n"
		"    print <cert> info\n"
		"  <data>:\n"
		"    -authority <name> -- authority (issuer)\n"
		"    -holder <name> -- holder (owner)\n"
		"    -from <YYMMDD> -- starting date\n"
		"    -until <YYMMDD> -- expiration date\n"
		"    -eid <hex> -- eId access template (10 hex symbols)\n"
		"    -esign <hex> -- eSign access template (4 hex symbols)\n"
		"  options:\n"
		"    -date <YYMMDD> -- validation date for <cert>\n"
		"    -pass <scheme> -- description of a password to access <privkey>\n",
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
	octet state[1024];
	bign_params params[1];
	octet privkey[32];
	octet pubkey[64];
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
	// все нормально
	return ERR_OK;
}

/*
*******************************************************************************
Самоподписанный сертификат
*******************************************************************************
*/

static err_t cvcRoot(int argc, char* argv[])
{
	return ERR_NOT_IMPLEMENTED;
}

/*
*******************************************************************************
Предсертификат (запрос)
*******************************************************************************
*/

static err_t cvcReq(int argc, char* argv[])
{
	return ERR_NOT_IMPLEMENTED;
}

/*
*******************************************************************************
Выпуск
*******************************************************************************
*/

static err_t cvcIss(int argc, char* argv[])
{
	return ERR_NOT_IMPLEMENTED;
}

/*
*******************************************************************************
Проверка
*******************************************************************************
*/

static err_t cvcVal(int argc, char* argv[])
{
	return ERR_NOT_IMPLEMENTED;
}


/*
*******************************************************************************
Печать
*******************************************************************************
*/

static err_t cvcPrint(int argc, char* argv[])
{
	err_t code;
	size_t cert_len;
	void* state;
	octet* cert;
	btok_cvc_t* cvc;
	char* hex;
	// обработать опции
	if (argc != 1)
		return ERR_CMD_PARAMS;
	// обработать файл
	if (!cmdFileValExist(argc, argv))
		return ERR_FILE_NOT_FOUND;
	if ((cert_len = cmdFileSize(argv[0])) == SIZE_MAX)
		return ERR_FILE_READ;
	if (cert_len > 512)
		return ERR_BAD_FORMAT;
	// выделить и разметить память
	state = blobCreate(cert_len + sizeof(btok_cvc_t) + 2 * 128 + 1);
	if (!state)
		return ERR_OUTOFMEMORY;
	cert = (octet*)state;
	cvc = (btok_cvc_t*)(cert + cert_len);
	hex = (char*)(cvc + 1);
	// читать сертификат
	{
		FILE* fp;
		code = (fp = fopen(argv[0], "rb")) ? ERR_OK : ERR_FILE_OPEN;
		ERR_CALL_HANDLE(code, blobClose(state));
		cert_len = fread(cert, 1, cert_len, fp);
		fclose(fp);
		ERR_CALL_HANDLE(code, blobClose(state));
	}
	// разобрать сертификат
	code = btokCVCUnwrap(cvc, cert, cert_len, 0, 0);
	ERR_CALL_HANDLE(code, blobClose(state));
	// печать содержимого
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
	hexFrom(hex, cvc->pubkey, cvc->pubkey_len);
	printf(
		"from = 20%c%c-%c%c-%c%c\n"
		"until = 20%c%c-%c%c-%c%c\n"
		"sig = %s\n",
		cvc->from[0] + '0', cvc->from[1] + '0',
		cvc->from[2] + '0',	cvc->from[3] + '0',
		cvc->from[4] + '0', cvc->from[5] + '0',
		cvc->until[0] + '0', cvc->until[1] + '0',
		cvc->until[2] + '0', cvc->until[3] + '0',
		cvc->until[4] + '0', cvc->until[5] + '0',
		cvc->sig);
	// завершить
	return ERR_OK;
}

int cvcMain(int argc, char* argv[])
{
	err_t code;
	// справка
	if (argc < 3)
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
	else if (strEq(argv[0], "print"))
		code = cvcPrint(argc - 1, argv + 1);
	else
		code = ERR_CMD_NOT_FOUND;
	if (code != ERR_OK)
	{
		printf("bee2cmd/%s: %s\n", _name, errMsg(code));
		return -1;
	}
	return 0;
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
