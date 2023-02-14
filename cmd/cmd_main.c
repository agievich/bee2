/*
*******************************************************************************
\file cmd_main.c
\brief Command-line interface to Bee2: main
\project bee2/cmd
\created 2022.06.07
\version 2022.11.03
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "cmd.h"
#include <bee2/core/err.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include <stdio.h>

/*
*******************************************************************************
Регистрация команд
*******************************************************************************
*/

typedef struct
{
	const char* name;	/*!< имя команды */
	const char* descr;	/*!< описание команды */
	cmd_main_i fn;		/*!< точка входа команды */
} cmd_entry_t;

static size_t _count = 0;		/*< число команд */
static cmd_entry_t _cmds[32];	/*< перечень команд */

err_t cmdReg(const char* name, const char* descr, cmd_main_i fn)
{
	size_t pos;
	// неверный формат?
	if (!strIsValid(name) || 0 == strLen(name) || strLen(name) > 8 ||
		!strIsValid(descr) || strLen(descr) > 60)
		return ERR_BAD_FORMAT;
	// команда уже зарегистрирована?
	for (pos = 0; pos < _count; ++pos)
		if (strEq(_cmds[pos].name, name))
			return ERR_CMD_EXISTS;
	// нет места?
	if (pos == COUNT_OF(_cmds))
		return ERR_OUTOFMEMORY;
	// зарегистрировать
	_cmds[pos].name = name;
	_cmds[pos].descr = descr;
	_cmds[pos].fn = fn;
	++_count;
	return ERR_OK;
}

/*
*******************************************************************************
Справка
*******************************************************************************
*/

int cmdUsage()
{
	size_t pos;
	// перечень команд
	printf(
		"Usage:\n"
		"  bee2cmd {");
	for (pos = 0; pos + 1 < _count; ++pos)
		printf("%s|", _cmds[pos].name);
	printf("%s} ...\n", _cmds[pos].name);
	// краткая справка по каждой команде
	for (pos = 0; pos < _count; ++pos)
		printf("    %s%*s%s\n",
			_cmds[pos].name,
			(int)(12 - strLen(_cmds[pos].name)), "",
			_cmds[pos].descr);
	return -1;
}

/*
*******************************************************************************
Самопроверка подписи

\remark Используется проверочный открытый ключ Q -- базовая точка G кривой
bign-curve256v1: Q = G. Этому ключу соответствует личный ключ d = 1.
*******************************************************************************
*/

static err_t cmdSelfCheck()
{
	static const octet pubkey[64] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x93, 0x6A, 0x51, 0x04, 0x18, 0xCF, 0x29, 0x1E,
		0x52, 0xF6, 0x08, 0xC4, 0x66, 0x39, 0x91, 0x78,
		0x5D, 0x83, 0xD6, 0x51, 0xA3, 0xC9, 0xE4, 0x5C,
		0x9F, 0xD6, 0x16, 0xFB, 0x3C, 0xFC, 0xF7, 0x6B,
	};
	return cmdSigSelfVerify(pubkey, sizeof(pubkey));
}

/*
*******************************************************************************
Инициализация
*******************************************************************************
*/

extern err_t verInit();
extern err_t bsumInit();
extern err_t pwdInit();
extern err_t kgInit();
extern err_t cvcInit();
extern err_t sigInit();
extern err_t esInit();
#ifdef OS_WIN
extern err_t stampInit();
#endif


err_t cmdInit()
{
	err_t code;
	code = verInit();
	ERR_CALL_CHECK(code);
	code = bsumInit();
	ERR_CALL_CHECK(code);
	code = pwdInit();
	ERR_CALL_CHECK(code);
	code = kgInit();
	ERR_CALL_CHECK(code);
	code = cvcInit();
	ERR_CALL_CHECK(code);
    code = sigInit();
	ERR_CALL_CHECK(code);
    code = esInit();
	ERR_CALL_CHECK(code);
#ifdef OS_WIN
	code = stampInit();
	ERR_CALL_CHECK(code);
#endif
	return code;
}

/*
*******************************************************************************
Главная функция
*******************************************************************************
*/

int main(int argc, char* argv[])
{
	err_t code;
	size_t pos;
	// старт
	code = cmdInit();
	if (code != ERR_OK)
	{
		printf("bee2cmd: %s\n", errMsg(code));
		return -1;
	}
	// справка
	if (argc < 2)
		return cmdUsage();
	// демонстрационный контроль целостности (результат игнорируется!)
	cmdSelfCheck();
	// обработка команды
	for (pos = 0; pos < _count; ++pos)
		if (strEq(argv[1], _cmds[pos].name))
			return _cmds[pos].fn(argc - 1,  argv + 1);
	printf("bee2cmd: %s\n", errMsg(ERR_CMD_NOT_FOUND));
	return -1;
}
