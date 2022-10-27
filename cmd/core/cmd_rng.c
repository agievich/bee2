/*
*******************************************************************************
\file cmd_rng.c
\brief Command-line interface to Bee2: random number generation
\project bee2/cmd 
\created 2022.06.08
\version 2022.10.27
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "../cmd.h"
#include <bee2/core/blob.h>
#include <bee2/core/err.h>
#include <bee2/core/mem.h>
#include <bee2/core/rng.h>
#include <bee2/core/str.h>
#include <bee2/core/tm.h>
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

В функции cmdKbRead() реализован клавиатурный источник энтропии. Реализация
соответствует СТБ 34.101.27-2011 (Б.7):
- при нажатии клавиш фиксируются значения высокоточного таймера (регистр TSC);
- разность между значениями регистра сохраняется, если друг за другом нажаты
  две различные клавиши и интервал между нажатиями более 50 мс;
- всего сохраняется 128 разностей;
- собранные разности объединяются и хэшируются;
- хэш-значение (32 октета) возвращается в качестве энтропийных данных.

Дополнительно в cmdKbRead() проверяется, что интервал между нажатиями клавиш
не превышает 5 секунд. При отсутствии активности со стороны пользователя
сбор данных от источника будет прекращен.

\warning В реализации требуется, чтобы таймер обновлялся не реже 1 раза
в 50 нс, т.е. с частотой не ниже 20 МГц. Для сравнения, в СТБ 34.101.27
объявлен порог в 600 МГц. При соблюдении этого порога оценка энтропии
клавиатурного источника не падала ниже 27.1 битов на наблюдение.

В функции cmdRngStart() проверяются требования СТБ 34.101.27-2020 уровня 1:
наличие работоспособного физического источника энтропии или двух различных
работоспособных источников. Если недостает одного источника, то задействуется
клавиатурный.
*******************************************************************************
*/

static err_t cmdKbRead(size_t* read, void* buf, size_t count, void* state)
{
	const tm_ticks_t freq = tmFreq(); /* число обновлений таймера в секунду */
	const tm_ticks_t max_delay = freq * 5; /* 5 с */
	const tm_ticks_t min_delay = freq /  20; /* 50 мс */
	err_t code = ERR_OK;
	void* stack;
	void* hash_state;
	tm_ticks_t* diff;
	register tm_ticks_t ticks;
	register tm_ticks_t t;
	size_t reps;
	bool_t echo;
	int ch;
	// pre
	ASSERT(memIsValid(read, sizeof(size_t)));
	ASSERT(memIsValid(buf, count));
	// таймер достаточно точен?
	if (freq < 20000000u)
		return ERR_FILE_NOT_FOUND;
	// подготовить стек
	code = cmdBlobCreate(stack, sizeof(tm_ticks_t) + beltHash_keep());
	ERR_CALL_CHECK(code);
	diff = (tm_ticks_t*)stack;
	hash_state = diff + 1;
	beltHashStart(hash_state);
	// приглашение к сбору энтропии
	printf("Collecting entropy from keyboard...\n");
	printf("Please, press different keys avoiding repetitions and long pauses:\n");
	for (reps = 128; reps; reps -= 2)
		printf("%c", '*');
	printf("\r");
	// сбор энтропии
	echo = cmdTermEcho(FALSE);
	for (*read = 0, ticks = tmTicks(), ch = 0; count; )
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
		*diff = t - ticks, ticks = t, ch = c;
		if (reps % 2)
			printf(".");
		// хэшировать
		beltHashStepH(diff, sizeof(tm_ticks_t), hash_state);
		// накоплено 128 наблюдений?
		if (++reps == 128)
		{
			size_t hash_len = MIN2(32, count);
			beltHashStepG2(buf, hash_len, hash_state);
			buf = (octet*)buf + hash_len;
			*read += hash_len, count -= hash_len;
			printf("\n");
			if (count)
			{
				for (; reps; reps -= 2)
					printf("%c", '*');
				printf("\r");
			}
		}
    }
	ticks = t = 0;
	cmdBlobClose(stack);
	cmdTermEcho(echo);
	return code;
}

err_t cmdRngStart(bool_t verbose)
{
	err_t code;
	if (verbose)
	{
		const char* sources[] = { "trng", "trng2", "sys", "timer" };
		size_t pos;
		size_t count;
		size_t read;
		printf("Starting RNG[");
		for (pos = count = 0; pos < COUNT_OF(sources); ++pos)
			if (rngESRead(&read, 0, 0, sources[pos]) == ERR_OK)
				printf(count++ ? ", %s" : "%s", sources[pos]);
		printf("]... ");
	}
	code = rngESHealth();
	if (code == ERR_OK)
		code = rngCreate(0, 0);
	else if (code == ERR_NOT_ENOUGH_ENTROPY)
		code = rngCreate(cmdKbRead, 0);
	if (verbose)
		printf("%s\n", errMsg(code));
	return code;
}
