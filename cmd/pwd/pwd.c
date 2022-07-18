/*
*******************************************************************************
\file pwd.c
\brief Generate and manage passwords
\project bee2/cmd 
\created 2022.06.23
\version 2022.07.18
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
#include <bee2/crypto/bels.h>
#include <bee2/crypto/belt.h>
#include <bee2/crypto/bign.h>
#include <bee2/crypto/bpki.h>
#include <bee2/crypto/brng.h>
#include <stdio.h>

/*
*******************************************************************************
Утилита pwd

Функционал:
- построение пароля по заданной схеме;
- проверочное определение ранее построенного пароля;
- печать ранее построенного пароля.

Допустимые схемы построения паролей определены в модуле cmd.h при описании 
функций cmdPwdGen(), cmdPwdRead().

Пример:
  bee2cmd pwd gen share:"-l256 -t3 -pass pass:zed s1 s2 s3 s4 s5"
  bee2cmd pwd gen share:"-l192 -pass share:\"-pass pass:zed s1 s2 s3\"
    ss1 ss2 ss3"
  bee2cmd pwd val share:"-pass share:\"-pass pass:zed s2 s4 s1\" ss3 ss1"
  bee2cmd pwd print share:"-pass share:\"-pass pass:zed s2 s4 s1\" ss3 ss1"
*******************************************************************************
*/

static const char _name[] = "pwd";
static const char _descr[] = "generate and manage passwords";

static int pwdUsage()
{
	printf(
		"bee2cmd/%s: %s\n"
		"Usage:\n"
		"  pwd gen <scheme>\n"
		"    generate a password according to <scheme>\n"
		"  pwd val <scheme>\n"
		"    validate a password built by <scheme>\n"
		"  pwd print <scheme>\n"
		"    print a password built by <scheme>\n",
		_name, _descr
	);
	return -1;
}


/*
*******************************************************************************
Самотестирование
*******************************************************************************
*/

static err_t pwdSelfTest()
{
	const char pwd[] = "B194BAC80A08F53B";
	octet state[1024];
	octet buf[5 * (32 + 1)];
	octet buf1[32];
	// bels-share: разделение и сборка
	if (belsShare3(buf, 5, 3, 32, beltH()) != ERR_OK)
		return ERR_SELFTEST;
	if (belsRecover2(buf1, 1, 32, buf) != ERR_OK ||
		memEq(buf1, beltH(), 32))
		return ERR_SELFTEST;
	if (belsRecover2(buf1, 2, 32, buf) != ERR_OK ||
		memEq(buf1, beltH(), 32))
		return ERR_SELFTEST;
	if (belsRecover2(buf1, 3, 32, buf) != ERR_OK ||
		!memEq(buf1, beltH(), 32))
		return ERR_SELFTEST;
	// brng-ctr: тест Б.2
	ASSERT(sizeof(state) >= brngCTR_keep());
	memCopy(buf, beltH(), 96);
	brngCTRStart(state, beltH() + 128, beltH() + 128 + 64);
	brngCTRStepR(buf, 96, state);
	if (!hexEq(buf,
		"1F66B5B84B7339674533F0329C74F218"
		"34281FED0732429E0C79235FC273E269"
		"4C0E74B2CD5811AD21F23DE7E0FA742C"
		"3ED6EC483C461CE15C33A77AA308B7D2"
		"0F51D91347617C20BD4AB07AEF4F26A1"
		"AD1362A8F9A3D42FBE1B8E6F1C88AAD5"))
		return ERR_SELFTEST;
	// pbkdf2 тест E.5
	beltPBKDF2(buf, (const octet*)"B194BAC80A08F53B", strLen(pwd), 10000,
		beltH() + 128 + 64, 8);
	if (!hexEq(buf,
		"3D331BBBB1FBBB40E4BF22F6CB9A689E"
		"F13A77DC09ECF93291BFE42439A72E7D"))
		return FALSE;
	// belt-kwp: тест A.21
	ASSERT(sizeof(state) >= beltKWP_keep());
	beltKWPStart(state, beltH() + 128, 32);
	memCopy(buf, beltH(), 32);
	memCopy(buf + 32, beltH() + 32, 16);
	beltKWPStepE(buf, 48, state);
	if (!hexEq(buf,
		"49A38EE108D6C742E52B774F00A6EF98"
		"B106CBD13EA4FB0680323051BC04DF76"
		"E487B055C69BCF541176169F1DC9F6C8"))
		return FALSE;
	// все нормально
	return ERR_OK;
}

/*
*******************************************************************************
Генерация пароля
*******************************************************************************
*/

static err_t pwdGen(int argc, char* argv[])
{
	err_t code = ERR_OK;
	cmd_pwd_t pwd = 0;
	// самотестирование
	code = pwdSelfTest();
	ERR_CALL_CHECK(code);
	// запустить ГСЧ
	code = cmdRngStart(TRUE);
	ERR_CALL_CHECK(code);
	// тестировать ГСЧ
	code = cmdRngTest();
	ERR_CALL_CHECK(code);
	// разобрать опции и генерировать пароль
	code = (argc == 1) ? cmdPwdGen(&pwd, *argv) : ERR_CMD_PARAMS;
	cmdPwdClose(pwd);
	return code;
}

/*
*******************************************************************************
Проверка пароля
*******************************************************************************
*/

static err_t pwdVal(int argc, char* argv[])
{
	err_t code = ERR_OK;
	cmd_pwd_t pwd = 0;
	// самотестирование
	code = pwdSelfTest();
	ERR_CALL_CHECK(code);
	// разобрать опции и определить пароль
	code = (argc == 1) ? cmdPwdRead(&pwd, *argv) : ERR_CMD_PARAMS;
	cmdPwdClose(pwd);
	return code;
}

/*
*******************************************************************************
Печать пароля
*******************************************************************************
*/

static err_t pwdPrint(int argc, char* argv[])
{
	err_t code = ERR_OK;
	cmd_pwd_t pwd = 0;
	// разобрать опции и определить пароль
	code = (argc == 1) ? cmdPwdRead(&pwd, *argv) : ERR_CMD_PARAMS;
	ERR_CALL_CHECK(code);
	// печатать пароль
	printf("%s\n", pwd);
	cmdPwdClose(pwd);
	return code;
}

/*
*******************************************************************************
Главная функция
*******************************************************************************
*/

int pwdMain(int argc, char* argv[])
{
	err_t code;
	// справка
	if (argc < 3)
		return pwdUsage();
	// разбор
	++argv, --argc;
	if (strEq(argv[0], "gen"))
		code = pwdGen(argc - 1, argv + 1);
	else if (strEq(argv[0], "val"))
		code = pwdVal(argc - 1, argv + 1);
	else if (strEq(argv[0], "print"))
		code = pwdPrint(argc - 1, argv + 1);
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

err_t pwdInit()
{
	return cmdReg(_name, _descr, pwdMain);
}
