/*
*******************************************************************************
\file cvr.c
\brief Manage CV-certificate rings
\project bee2/cmd 
\created 2023.06.08
\version 2023.06.13
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
Вспомогательные функции
*******************************************************************************
*/

static err_t cvrFindCert(size_t* offset, const char* ring_file,
	const octet* cert, size_t cert_len, size_t sig_len)
{
	const size_t prefix_len = 8;
	err_t code;
	size_t size;
	FILE* fp;
	void* stack;
	octet* cert1;
	size_t len;
	// pre
	ASSERT(strIsValid(ring_file));
	ASSERT(memIsValid(cert, cert_len));
	ASSERT(memIsNullOrValid(offset, O_PER_S));
	ASSERT(cert_len >= 8);
	// определить размер файла
	size = cmdFileSize(ring_file);
	if (size == SIZE_MAX || size < sig_len)
		return ERR_BAD_CERTRING;
	size -= sig_len;
	// открыть файл
	fp = fopen(ring_file, "rb");
	if (!fp)
		return ERR_FILE_OPEN;
	// выделить и разметить память
	code = cmdBlobCreate(stack, cert_len);
	ERR_CALL_HANDLE(code, fclose(fp));
	cert1 = (octet*)stack;
	// просмотреть сертификаты кольца
	for (*offset = 0; *offset < size; )
	{
		// читать префикс сертификата
		len = fread(cert1, 1, prefix_len, fp);
		if (len != prefix_len)
		{
			code = ERR_FILE_READ;
			break;
		}
		// читать длину сертификата
		len = btokCVCLen(cert1, size - *offset);
		if (len == SIZE_MAX || len < prefix_len)
		{
			code = ERR_BAD_CERTRING;
			break;
		}
		// подходящая длина?
		if (len == cert_len)
		{
			// читать сертификат
			if (fread(cert1 + prefix_len, 1, len - prefix_len, fp) !=
				len - prefix_len)
			{
				code = ERR_FILE_READ;
				break;
			}
			// подходящий сертификат?
			if (memEq(cert, cert1, cert_len))
				break;
		}
		else
		{
			long delta;
			// определить смещение
			delta = (long)(len - prefix_len);
			if ((size_t)delta != len - prefix_len)
			{
				code = ERR_OVERFLOW;
				break;
			}
			// сместиться
			if (fseek(fp, delta, SEEK_CUR) != 0)
			{
				code = ERR_FILE_READ;
				break;
			}
		}
		// к следующему сертификату
		*offset += len;
	}
	// выход за границы?
	if (*offset > size)
		code = ERR_BAD_CERTRING;
	// просто не найден?
	else if (code == ERR_OK && *offset == size)
		code = ERR_NOT_FOUND;
	// завершить
	cmdBlobClose(stack);
	fclose(fp);
	return code;
}

static err_t cvrAddCert(const char* ring_file, size_t offset,
	const octet* cert, size_t cert_len)
{
	err_t code = ERR_OK;
	FILE* fp;
	// pre
	ASSERT(strIsValid(ring_file));
	ASSERT(memIsValid(cert, cert_len));
	// открыть файл
	fp = fopen(ring_file, "r+b");
	if (!fp)
		return ERR_FILE_OPEN;
	// сместиться в файле
	if ((size_t)(long)offset != offset)
		code = ERR_OVERFLOW;
	ERR_CALL_HANDLE(code, fclose(fp));
	if (fseek(fp, (long)offset, SEEK_SET) != 0)
		code = ERR_FILE_READ;
	// записать сертификат
	if (fwrite(cert, 1, cert_len, fp) != cert_len)
		code = ERR_FILE_WRITE;
	fclose(fp);
	ERR_CALL_CHECK(code);
	// обрезать файл
	code = cmdFileTrunc(ring_file, offset + cert_len);
	// завершить
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
	// искать cert в кольце
	code = cvrFindCert(&offset, argv[5], cert, cert_len, sig_len);
	if (code == ERR_OK)
		code = ERR_ALREADY_EXISTS;
	else if (code == ERR_NOT_FOUND)
		code = ERR_OK;
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// добавить cert в кольцо
	code = cvrAddCert(argv[5], offset, cert, cert_len);
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// определить текущую дату
	if (!tmDate2(date))
		code = ERR_BAD_TIMER;
	ERR_CALL_HANDLE(code, cmdBlobClose(stack));
	// подписать
	code = cmdSigSign(argv[5], argv[5], argv[3], date, privkey, privkey_len);
	// завершить
	cmdBlobClose(stack);
	return code;
}

/*
*******************************************************************************
Удаление сертификата 

cvr del -pass <scheme> <privkeya> <cert> <req>
*******************************************************************************
*/

static err_t cvrDel(int argc, char* argv[])
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
Проверка кольца

cvr val <certa> <cert>
*******************************************************************************
*/

static err_t cvrVal(int argc, char* argv[])
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
Извлечение объекта

cvr extr {-cert<nnn>|-certa} <ring> <file>
*******************************************************************************
*/

static err_t cvrExtr(int argc, char* argv[])
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
