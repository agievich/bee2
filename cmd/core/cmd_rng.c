/*
*******************************************************************************
\file cmd_rng.c
\brief Command-line interface to Bee2: random number generation
\project bee2/cmd 
\created 2022.06.08
\version 2024.06.14
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "../cmd.h"
#include <bee2/core/blob.h>
#include <bee2/core/err.h>
#include <bee2/core/mem.h>
#include <bee2/core/prng.h>
#include <bee2/core/rng.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include <bee2/crypto/belt.h>
#include <stdio.h>

/*
*******************************************************************************
Терминал

\thanks
https://www.flipcode.com/archives/_kbhit_for_Linux.shtml
(Morgan McGuire [morgan@cs.brown.edu])
https://stackoverflow.com/questions/29335758/using-kbhit-and-getch-on-linux
https://askcodes.net/questions/how-to-implement-getch---function-of-c-in-linux-
*******************************************************************************
*/

#ifdef OS_UNIX

#include <termios.h>
#include <unistd.h>
#include <stdio.h>

static bool_t cmdTermEcho(bool_t on)
{
	bool_t prev;
	struct termios attr;
	fflush(stdout);
	tcgetattr(STDIN_FILENO, &attr);
	prev = (attr.c_lflag & ECHO) != 0;
	if (on)
		attr.c_lflag |= ECHO;
	else
		attr.c_lflag &= ~ECHO;
	tcsetattr(STDIN_FILENO, TCSANOW, &attr);
	return prev;
}

#else

static bool_t cmdTermEcho(bool_t on)
{
	static bool_t state;
	bool_t ret = state;
	state = on;
	return ret;
}

#endif

/*
*******************************************************************************
ГСЧ

\todo В cmdRngKbRead() проверяется, что таймер обновлялся не реже 1 раза
в 50 нс, т.е. с частотой не ниже 20 МГц. Для сравнения, в СТБ 34.101.27
объявлен порог в 600 МГц. При соблюдении этого порога оценка энтропии
клавиатурного источника не падала ниже 27.1 битов на наблюдение.
Следует уточнить оценки энтропии при снижения порога частоты.
*******************************************************************************
*/

err_t cmdRngKbRead(tm_ticks_t data[128])
{
	const tm_ticks_t freq = tmFreq(); /* число обновлений таймера в секунду */
	const tm_ticks_t max_delay = freq * 5; /* 5 с */
	const tm_ticks_t min_delay = freq / 20; /* 50 мс */
	register tm_ticks_t ticks;
	register tm_ticks_t t;
	err_t code;
	size_t pos;
	bool_t echo;
	int ch;
	// pre
	ASSERT(memIsValid(data, sizeof(tm_ticks_t) * 128));
	// таймер достаточно точен?
	code = freq >= 20000000u ? ERR_OK : ERR_FILE_NOT_FOUND;
	ERR_CALL_CHECK(code);
	// приглашение к сбору энтропии
	printf("Collecting entropy from keyboard...\n");
	printf("Please, press different keys avoiding repetitions and long pauses:\n");
	for (pos = 128; pos; pos -= 2)
		printf("%c", '*');
	printf("\r");
	// сбор энтропии
	echo = cmdTermEcho(FALSE);
	ASSERT(pos == 0);
	for (ticks = tmTicks(), ch = 0; pos < 128; )
	{
		int c;
		// превышен интервал ожидания?
		t = tmTicks();
		if (t > ticks + max_delay)
		{
			code = ERR_TIMEOUT;
			break;
		}
		// клавиша не нажата? нажата слишком быcтро?
		// нажали ту же клавишу? функциональную клавишу?
		if (!cmdTermKbhit() || t < ticks + min_delay ||
			(c = cmdTermGetch()) == ch || c == 0 || c == 0xE0)
			continue;
		// обрабатать нажатие
		data[pos++] = t - ticks, ticks = t, ch = c;
		if (pos % 2)
			printf(".");
	}
	ticks = t = 0;
	cmdTermEcho(echo);
	printf("\n");
	return code;
}

static err_t prngEchoRead(size_t* read, void* buf, size_t count, void* state)
{
	ASSERT(memIsValid(read, O_PER_S));
	prngEchoStepR(buf, count, state);
	*read = count;
	return ERR_OK;
}

err_t cmdRngStart(bool_t verbose)
{
	err_t code;
	// ГСЧ уже запущен?
	if (rngIsValid())
		return ERR_OK;
	// печать информации об источниках
	if (verbose)
	{
		const char* sources[] = { "trng", "trng2", "sys", "sys2", "timer" };
		size_t pos;
		size_t count;
		size_t read;
		printf("Starting RNG[");
		for (pos = count = 0; pos < COUNT_OF(sources); ++pos)
			if (rngESRead(&read, 0, 0, sources[pos]) == ERR_OK)
				printf(count++ ? ", %s" : "%s", sources[pos]);
		printf("]... ");
	}
	// энтропии достаточно?
	code = rngESHealth();
	if (code == ERR_OK)
		code = rngCreate(0, 0);
	// нет, подключить клавиатурный источник
	else if (code == ERR_NOT_ENOUGH_ENTROPY)
	{
		void* stack;
		tm_ticks_t* data;
		octet* hash;
		void* state;
		// выделить и разметить память
		code = cmdBlobCreate(stack, 128 * sizeof(tm_ticks_t) +
			MAX2(beltHash_keep(), prngEcho_keep()));
		ERR_CALL_CHECK(code);
		data = (tm_ticks_t*)stack;
		hash = (octet*)data;
		state = data + 128;
		// собрать данные от клавиатурного источника
		code = cmdRngKbRead(data);
		ERR_CALL_HANDLE(code, cmdBlobClose(stack));
		// хэшировать
		beltHashStart(state);
		beltHashStepH(data, 128 * sizeof(tm_ticks_t), state);
		beltHashStepG(hash, state);
		// запустить echo-генератор
		prngEchoStart(state, hash, 32);
		// запустить генератор
		code = rngCreate(prngEchoRead, state);
		// освободить память
		cmdBlobClose(stack);
	}
	if (verbose)
		printf("%s\n", errMsg(code));
	return code;
}
