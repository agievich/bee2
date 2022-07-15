/*
*******************************************************************************
\file cvc.c
\brief Manage CV-certificates
\project bee2/cmd 
\created 2022.07.12
\version 2022.07.15
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
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
		"  cvc root options <privkeya> <certa>\n"
		"    issue a self-signed certificate <certa>\n"
		"  cvc req options <privkey> <req>\n"
		"    generate a pre-certificate <req>\n"
		"  cvc iss options <privkeya> <certa> <req> <cert>\n"
		"    issue <cert> based on <req> and subordinate to <certa>\n"
		"  cvc val options <certa> <certb> ... <cert>\n"
		"    validate <certb> ... <cert> using <certa> as an anchor\n"
		"  cvc print <cert>\n"
		"    print <cert> info\n"
		"  .\n"
		"  <privkey>, <privkeya>\n"
		"    containers with private keys\n"
		"  options:\n"
		"    -authority <name> -- authority (issuer)  // [root], req\n"
		"    -holder <name> -- holder (owner)         // [root], req\n"
		"    -from <YYMMDD> -- starting date          // root, req\n"
		"    -until <YYMMDD> -- expiration date       // root, req\n"
		"    -eid <10*hex> -- eId access template     // [root], [req]\n"
		"    -esign <4*hex> -- eSign access template  // [root], [req]\n"
		"    -pass <scheme> -- password description   // root, req, iss\n"
		"    -date <YYMMDD> -- validation date        // [val]\n",
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
Чтение / запись
*******************************************************************************
*/

err_t cmdCVCWrite(const octet cert[], size_t cert_len, const char* file)
{
	err_t code;
	// pre
	ASSERT(memIsValid(cert, cert_len));
	ASSERT(strIsValid(file));
	// записать
	{
		FILE* fp;
		code = (fp = fopen(file, "wb")) ? ERR_OK : ERR_FILE_CREATE;
		ERR_CALL_CHECK(code);
		code = (cert_len == fwrite(cert, 1, cert_len, fp)) ?
			ERR_OK : ERR_FILE_WRITE;
		fclose(fp);
	}
	// завершить
	return code;
}

err_t cmdCVCRead(octet cert[], size_t* cert_len, const char* file)
{
	err_t code = ERR_OK;
	size_t len;
	// pre
	ASSERT(memIsNullOrValid(cert_len, O_PER_S));
	ASSERT(strIsValid(file));
	// определить длину файла
	if ((len = cmdFileSize(file)) == SIZE_MAX)
		return ERR_FILE_READ;
	if (cert_len)
		*cert_len = len;
	// читать
	if (cert)
	{
		FILE* fp;
		ASSERT(memIsValid(cert, len));
		code = (fp = fopen(file, "rb")) ? ERR_OK : ERR_FILE_OPEN;
		ERR_CALL_CHECK(code);
		code = (len == fread(cert, 1, len, fp)) ? ERR_OK : ERR_FILE_READ;
		fclose(fp);
	}
	// завершить
	return code;
}


/*
*******************************************************************************
Разбор опций командной строки

Опции возвращаются по адресам cvc, pwd, date. Лююой из адресов может быть
нулевым, и тогда соответствующая опция не возвращается. Более того, ее указание
в командной строке считается ошибкой.

В случае успеха по адресу readc возвращается число обработанных аргументов.
*******************************************************************************
*/

static err_t cvcParseOptions(btok_cvc_t* cvc, cmd_pwd_t* pwd, octet date[6],
	int* readc, int argc, char* argv[])
{
	err_t code;
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
	if (!argc || argc % 2)
		return ERR_CMD_PARAMS;
	*readc = argc;
	while (argc && strStartsWith(*argv, "-"))
	{
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
	// \warning корректность cvc не проверяется
	if (code == ERR_OK && (pwd && !*pwd || date && memIsZero(date, 6)))
		code = ERR_CMD_PARAMS;
	// завершить
	if (code != ERR_OK)
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
	code = cmdCVCWrite(cert, cert_len, argv[1]);
	cmdBlobClose(cert);
	// завершить
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
	code = cmdCVCWrite(req, req_len, argv[1]);
	cmdBlobClose(req);
	// завершить
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
	void* state;
	octet* certa;
	octet* req;
	octet* cert;
	btok_cvc_t* cvc;
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
	code = cmdCVCRead(0, &certa_len, argv[1]);
	ERR_CALL_HANDLE(code, cmdBlobClose(privkeya));
	code = cmdCVCRead(0, &req_len, argv[2]);
	ERR_CALL_HANDLE(code, cmdBlobClose(privkeya));
	// построить оценку сверху для cert_len: req_len + расширение_подписи
	cert_len = req_len + (96 - 48);
	// выделить память и разметить ее
	code = cmdBlobCreate(state, certa_len + req_len + cert_len +
		sizeof(btok_cvc_t));
	ERR_CALL_HANDLE(code, cmdBlobClose(privkeya));
	certa = (octet*)state;
	req = certa + certa_len;
	cert = req + req_len;
	cvc = (btok_cvc_t*)(cert + cert_len);
	// прочитать сертификат
	code = cmdCVCRead(certa, 0, argv[1]);
	ERR_CALL_HANDLE(code, (cmdBlobClose(privkeya), cmdBlobClose(state)));
	// прочитать запрос
	code = cmdCVCRead(req, 0, argv[2]);
	ERR_CALL_HANDLE(code, (cmdBlobClose(privkeya), cmdBlobClose(state)));
	// разобрать запрос
	code = btokCVCUnwrap(cvc, req, req_len, cvc->pubkey, 0);
	ERR_CALL_HANDLE(code, (cmdBlobClose(privkeya), cmdBlobClose(state)));
	// выпустить сертификат
	code = btokCVCIss(cert, &cert_len, cvc, certa, certa_len, privkeya,
		privkeya_len);
	ASSERT(cert_len <= req_len + 96 - 48);
	cmdBlobClose(privkeya);
	ERR_CALL_HANDLE(code, cmdBlobClose(state));
	// записать сертификат
	code = cmdCVCWrite(cert, cert_len, argv[3]);
	cmdBlobClose(state);
	// завершить
	return code;
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

cvc print <cert>
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
	// проверить наличие/отсутствие файлов
	code = cmdFileValExist(1, argv);
	ERR_CALL_CHECK(code);
	// определить длину сертификата
	code = cmdCVCRead(0, &cert_len, argv[0]);
	ERR_CALL_CHECK(code);
	// выделить память и разметить ее
	code = cmdBlobCreate(state, cert_len + sizeof(btok_cvc_t) + 2 * 128 + 1);
	ERR_CALL_CHECK(code);
	cert = (octet*)state;
	cvc = (btok_cvc_t*)(cert + cert_len);
	hex = (char*)(cvc + 1);
	// прочитать сертификат
	code = cmdCVCRead(cert, 0, argv[0]);
	ERR_CALL_HANDLE(code, cmdBlobClose(state));
	// разобрать сертификат
	code = btokCVCUnwrap(cvc, cert, cert_len, 0, 0);
	ERR_CALL_HANDLE(code, cmdBlobClose(state));
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
		"from = 20%c%c-%c%c-%c%c\n"
		"until = 20%c%c-%c%c-%c%c\n"
		"sig = %s\n",
		cvc->from[0] + '0', cvc->from[1] + '0',
		cvc->from[2] + '0',	cvc->from[3] + '0',
		cvc->from[4] + '0', cvc->from[5] + '0',
		cvc->until[0] + '0', cvc->until[1] + '0',
		cvc->until[2] + '0', cvc->until[3] + '0',
		cvc->until[4] + '0', cvc->until[5] + '0',
		hex);
	// завершить
	cmdBlobClose(state);
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
	// завершить
	if (code != ERR_OK || code == ERR_OK && strEq(argv[0], "val"))
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
