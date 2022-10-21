/*
*******************************************************************************
\file cmd_core.c
\brief Command-line interface to Bee2: useful functions
\project bee2/cmd 
\created 2022.06.08
\version 2022.10.21
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "cmd.h"
#include <bee2/core/blob.h>
#include <bee2/core/err.h>
#include <bee2/core/mem.h>
#include <bee2/core/rng.h>
#include <bee2/core/str.h>
#include <bee2/core/tm.h>
#include <bee2/core/util.h>
#include <bee2/crypto/belt.h>
#include <bee2/crypto/bels.h>
#include <bee2/crypto/bign.h>
#include <bee2/crypto/brng.h>
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
//#include <fcntl.h>
#include <sys/select.h>
#include <sys/ioctl.h>

static bool_t termEcho(bool_t echo)
{
	bool_t prev;
	struct termios attr;
	fflush(stdout);
	tcgetattr(STDIN_FILENO, &attr);
	prev = (attr.c_lflag & ECHO) != 0;
	if (echo)
		attr.c_lflag |= ECHO;
	else
		attr.c_lflag &= ~ECHO;
	tcsetattr(STDIN_FILENO, TCSANOW, &attr);
	return prev;
}

static bool_t termKbhit()
{
	struct termios oldattr, newattr;
	int bytesWaiting;
	tcgetattr(STDIN_FILENO, &oldattr);
	newattr = oldattr;
	newattr.c_lflag &= ~ICANON;
	tcsetattr(STDIN_FILENO, TCSANOW, &newattr);
	ioctl(STDIN_FILENO, FIONREAD, &bytesWaiting);
	tcsetattr(STDIN_FILENO, TCSANOW, &oldattr);
	return bytesWaiting > 0;
}

int termGetch()
{
	struct termios oldattr, newattr;
	int ch;
	fflush(stdout);
	tcgetattr(STDIN_FILENO, &oldattr);
	newattr = oldattr;
	newattr.c_lflag &= ~ICANON;
	newattr.c_cc[VMIN] = 1;
	newattr.c_cc[VTIME] = 0;
	tcsetattr(STDIN_FILENO, TCSANOW, &newattr);
	ch = getchar();
	tcsetattr(STDIN_FILENO, TCSANOW, &oldattr);
	return ch;
}

#elif defined OS_WIN

#include <conio.h>

static bool_t termEcho(bool_t echo)
{
	return TRUE;
}

#define termKbhit _kbhit
#define termGetch _getch

#else

static bool_t termEcho(bool_t echo)
{
	return TRUE;
}

static bool_t termKbhit()
{
	return FALSE;
}

int termGetch()
{
	char ch;
	scanf(" %c", &ch);
	return ch;
}

#endif

/*
*******************************************************************************
Файлы
*******************************************************************************
*/

size_t cmdFileSize(const char* file)
{
	FILE* fp;
	long int size;
	ASSERT(strIsValid(file));
	if (!(fp = fopen(file, "rb")))
		return SIZE_MAX;
	if (fseek(fp, 0, SEEK_END))
	{
		fclose(fp);
		return SIZE_MAX;
	}
	size = ftell(fp);
	fclose(fp);
	return (size == -1L) ? SIZE_MAX : (size_t)size;
}

err_t cmdFileValNotExist(int count, char* files[])
{
	FILE* fp;
	int ch;
	for (; count--; files++)
	{
		ASSERT(strIsValid(*files));
		if (fp = fopen(*files, "rb"))
		{
			fclose(fp);
			printf("Some files already exist. Overwrite [y/n]?");
			do
				ch = termGetch();
			while (ch != 'Y' && ch != 'y' && ch != 'N' && ch != 'n' && ch != '\n');
			printf("\n");
			if (ch == 'N' || ch == 'n' || ch == '\n')
				return ERR_FILE_EXISTS;
			break;
		}
	}
	return ERR_OK;
}

err_t cmdFileValExist(int count, char* files[])
{
	FILE* fp;
	for (; count--; files++)
	{
		ASSERT(strIsValid(*files));
		if (!(fp = fopen(*files, "rb")))
			return ERR_FILE_NOT_FOUND;
		fclose(fp);
	}
	return ERR_OK;
}

err_t cmdFileRead(
        octet* buf,
        size_t* buf_len,
        const char * file
) {
    size_t len;

    ASSERT(memIsNullOrValid(buf_len, O_PER_S));
    ASSERT(strIsValid(file));

    len = cmdFileSize(file);
    if (len == SIZE_MAX)
        return ERR_FILE_READ;

    if (buf)
        len = cmdFileRead2(buf, len, file);

    if (len == SIZE_MAX)
        return ERR_FILE_OPEN;

    if (buf_len)
        *buf_len = len;

    return ERR_OK;
}

size_t cmdFileRead2(
        octet* buf,
        size_t buf_len,
        const char * file
) {
    err_t code;
    size_t len;
    FILE* fp;

    ASSERT(strIsValid(file));
    ASSERT(memIsValid(buf, buf_len));

    code = (fp = fopen(file, "rb")) ? ERR_OK : ERR_FILE_OPEN;
    ERR_CALL_CHECK(code);
    len = fread(buf, 1, buf_len, fp);
    fclose(fp);

    return len;
}

err_t cmdFileWrite(
        const octet* buf,
        size_t buf_len,
        const char* file
){
    err_t code;
    FILE* fp;

    ASSERT(memIsValid(buf, buf_len));
    ASSERT(strIsValid(file));

    code = (fp = fopen(file, "wb")) ? ERR_OK : ERR_FILE_CREATE;
    ERR_CALL_CHECK(code);
    code = (buf_len == fwrite(buf, 1, buf_len, fp)) ?
           ERR_OK : ERR_FILE_WRITE;
    fclose(fp);

    return code;
}

/*
*******************************************************************************
Командная строка
*******************************************************************************
*/

#ifdef OS_UNIX

#include <wordexp.h>

err_t cmdArgCreate(int* argc, char*** argv, const char* args)
{
	wordexp_t we[1];
	size_t count;
	int pos;
	// входной контроль
	ASSERT(strIsValid(args));
	ASSERT(memIsDisjoint2(argv, sizeof(char**), argc, sizeof(int)));
	// разбить args на строки широких символов
	switch (wordexp(args, we, 0))
	{
	case 0:
		break;
	case WRDE_NOSPACE:
		return ERR_OUTOFMEMORY;
	default:
		return ERR_CMD_PARAMS;
	}
	*argv = 0, *argc = we->we_wordc;
	// обработать отсутствие аргументов
	if (*argc == 0)
	{
		wordfree(we);
		return ERR_OK;
	}
	// перенести аргументы в блоб
	count = (size_t)(*argc) * sizeof(char*);
	for (pos = 0; pos < *argc; ++pos)
		count += strLen(we->we_wordv[pos]) + 1;
	if (!(*argv = blobCreate(count)))
	{
		wordfree(we);
		return ERR_OUTOFMEMORY;
	}
	count = (size_t)(*argc) * sizeof(char*);
	for (pos = 0; pos < *argc; ++pos)
	{
		(*argv)[pos] = (char*)*argv + count;
		strCopy((*argv)[pos], we->we_wordv[pos]);
		count += strLen((*argv)[pos]) + 1;
	}
	// завершить
	wordfree(we);
	return ERR_OK;
}

#elif defined OS_WIN

#include <windows.h>

err_t cmdArgCreate(int* argc, char*** argv, const char* args)
{
	wchar_t* argsw = 0;
	wchar_t** argvw = 0;
	size_t count;
	int pos;
	// pre
	ASSERT(strIsValid(args));
	ASSERT(memIsDisjoint2(argv, sizeof(char**), argc, O_PER_S));
	// разбить args на строки широких символов
	if (!(argsw = memAlloc((strLen(args) + 1) * sizeof(wchar_t))))
		return ERR_OUTOFMEMORY;
	if (!MultiByteToWideChar(CP_ACP, 0, args, -1, argsw, (int)strLen(args) + 1) ||
		!(argvw = CommandLineToArgvW(argsw, argc)))
	{
		memFree(argsw);
		return ERR_CMD_PARAMS;
	}
	memFree(argsw);
	ASSERT(*argc >= 0);
	// обработать отсутствие аргументов
	*argv = 0;
	if (*argc == 0)
		return ERR_OK;
	// перенести аргументы в блоб
	count = (size_t)(*argc) * sizeof(char*);
	for (pos = 0; pos < *argc; ++pos)
	{
		int len = WideCharToMultiByte(CP_ACP, 0, argvw[pos], -1,
			NULL, 0, NULL, NULL);
		if (!len)
		{
			LocalFree(argvw);
			return ERR_CMD_PARAMS;
		}
		count += (size_t)len;
	}
	if (!(*argv = blobCreate(count)))
	{
		LocalFree(argvw);
		return ERR_OUTOFMEMORY;
	}
	count = (size_t)(*argc) * sizeof(char*);
	for (pos = 0; pos < *argc; ++pos)
	{
		int len;
		(*argv)[pos] = (char*)*argv + count;
		len = WideCharToMultiByte(CP_ACP, 0, argvw[pos], -1, NULL, 0,
			NULL, NULL);
		ASSERT(len);
		WideCharToMultiByte(CP_ACP, 0, argvw[pos], -1, (*argv)[pos], len,
			NULL, NULL);
		count += (size_t)len;
	}
	// завершить
	LocalFree(argvw);
	return ERR_OK;
}

#else

#error "Not implemented"

#endif

void cmdArgClose(char** argv)
{
	blobClose(argv);
}

/*
*******************************************************************************
ГСЧ

В функции cmdKbRead() реализован клавиатурный источник энтропии. Реализация
соответствует СТБ 34.101.27-2011 (Б.7):
- при нажатии клавиш фиксируются значения регистра TSC (высокоточный таймер);
- разность между значениями регистра сохраняется, если друг за другом нажаты
  две различные клавиши и интервал между нажатиями более 50 мс;
- всего сохраняется 128 разностей;
- собранные разности объединяются и хэшируются;
- хэш-значение (32 октета) возвращается в качестве энтропийных данных.

Дополнительно в cmdKbRead() проверяется, что интервал между нажатиями клавиш
не превышает 5 секунд. При отсутствии активности со стороны пользователя
сбор данных от источника будет прекращен.

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
	if (B_PER_W == 16 || freq < 1000000000u)
		return ERR_FILE_NOT_FOUND;
	// подготовить стек
	stack = blobCreate(sizeof(tm_ticks_t) + beltHash_keep());
	if (!stack)
		return ERR_OUTOFMEMORY;
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
	echo = termEcho(FALSE);
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
		if (!termKbhit() || t < ticks + min_delay ||
			(c = termGetch()) == ch || c == 0 || c == 0xE0)
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
	blobClose(stack);
	termEcho(echo);
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
	else if (code = ERR_NOT_ENOUGH_ENTROPY)
		code = rngCreate(cmdKbRead, 0);
	if (verbose)
		printf("%s\n", errMsg(code));
	return code;
}
