/*
*******************************************************************************
\file cmd_core.c
\brief Command-line interface to Bee2: useful functions
\project bee2/cmd 
\created 2022.06.08
\version 2022.07.18
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
#include <bee2/core/util.h>
#include <bee2/crypto/belt.h>
#include <bee2/crypto/bels.h>
#include <bee2/crypto/bign.h>
#include <bee2/crypto/brng.h>
#include <stdio.h>

/*
*******************************************************************************
Консоль
*******************************************************************************
*/

#ifdef OS_UNIX

#include <termios.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/select.h>
#include <sys/ioctl.h>

static bool_t _kbhit()
{
    static bool_t _initialized = FALSE;

    if (!_initialized) {
        struct termios term;
        tcgetattr(STDIN_FILENO, &term);
        term.c_lflag &= ~ICANON;
        term.c_lflag &= ~( ECHO );
        tcsetattr(STDIN_FILENO, TCSANOW, &term);
        setbuf(stdin, NULL);
        _initialized = TRUE;
    }

    int bytesWaiting;
    ioctl(STDIN_FILENO, FIONREAD, &bytesWaiting);
    return bytesWaiting;
}

int getch()
{
	struct termios oldattr, newattr;
	int ch;
	fflush(stdout);
	tcgetattr(STDIN_FILENO, &oldattr);
	newattr = oldattr;
	newattr.c_lflag &= ~( ICANON );
	newattr.c_lflag &= ~( ECHO );
	newattr.c_cc[VMIN] = 1;
	newattr.c_cc[VTIME] = 0;
	tcsetattr(STDIN_FILENO, TCSANOW, &newattr);
	ch = getchar();
	tcsetattr(STDIN_FILENO, TCSANOW, &oldattr);
	return ch;
}

#elif defined OS_WIN

#include <conio.h>

#define _kbhit kbhit
#define getch _getch

#else

int getch()
{
	char ch;
	scanf(" %c", &ch);
	return ch;
}

bool_t _kbhit() {
    return true;
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
				ch = getch();
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
*******************************************************************************
*/

#if defined OS_WIN

#include <profileapi.h>

static inline u64 cmdReadTCS()
{
	LARGE_INTEGER cnt;
    QueryPerformanceCounter(&cnt);
	return cnt.QuadPart;
}

static inline u64 cmdGetProcessorFrequency()
{
	LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);
	return freq.QuadPart;
}

#elif defined OS_LINUX

#include <time.h>
static u64 cmdReadTCS()
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) < 0)
        return 0;
    return ts.tv_sec * 1000000000L + ts.tv_nsec;
}

static u64 cmdGetProcessorFrequency()
{
    u64 start = cmdReadTCS();
    u64 overhead = cmdReadTCS() - start;
    start = cmdReadTCS();
    usleep(1000000);
    return cmdReadTCS() - start - overhead;
}

#elif defined OS_APPLE

#include <mach/mach_time.h>

#define cmdReadTCS mach_absolute_time

static u64 cmdGetProcessorFrequency()
{
    u64 start = cmdReadTCS();
    u64 overhead = cmdReadTCS() - start;
    start = cmdReadTCS();
    usleep(1000000);
    return cmdReadTCS()  - start - overhead;
}

#else

static inline u64 cmdReadTCS(){
    return 0;
}

static inline u64 cmdGetProcessorFrequency(){
    return 0;
}

#endif

static u64 _freq = 0;

static err_t cmdRngKeyboardSource(size_t* read, void* buf, size_t count, void* state)
{

    const word _min_delay = 50;
    const word _timeout_delay = 10000;

    u8 tick;
    u64 min_ticks;
    u64 timeout_ticks;
    u64 prevtime;
    u64 diff;
    u64 curtime;
    int prevchar;
    int curchar;
    size_t pos = 0;

    ASSERT(memIsValid(buf,count));

    if (_freq <= 0)
        _freq = cmdGetProcessorFrequency();
    if (_freq <= 0)
        return ERR_BAD_ENTROPY;

    prevchar = '\0';
    prevtime = cmdReadTCS();
    min_ticks = _freq * _min_delay / 1000;
    timeout_ticks = _freq * _timeout_delay / 1000;

    printf("Collecting entropy from keyboard...\n");
    printf("Press different buttons %lu times with >%lu ms delay\n", count, _min_delay);

    if (read)
        *read = 0;

    for(size_t i = 0 ; i < count; i++){
        printf(".");
    }
    printf("\n");
    while (pos < count)
    {
        while (!_kbhit())
        {
            if (cmdReadTCS() - prevtime > timeout_ticks)
                return ERR_TIMEOUT;
        }

        curchar = getch();

        if (curchar == prevchar || curchar == 0 || curchar == 0xE0)
            continue;

        curtime = cmdReadTCS();

        diff = curtime - prevtime;

        if (diff < min_ticks)
            continue;
        tick = diff % 256;
        memCopy(buf + pos, &tick, 1);
        prevchar = curchar;
        prevtime = curtime;
        pos++;
        printf(".");
        if (read)
            *read = *read +1;
    }
    printf("\n");
    return ERR_OK;
}

err_t cmdRngStart(bool_t verbose)
{
	err_t code;

    code = cmdRngTest();
	if (verbose)
	{
		const char* sources[] = { "trng", "trng2", "sys", "timer" };
		size_t pos;
		size_t count;
		size_t read;
		printf("Starting RNG[");
		for (pos = count = 0; pos < COUNT_OF(sources); ++pos)
			if (rngReadSource(&read, 0, 0, sources[pos]) == ERR_OK)
				printf(count++ ? ", %s" : "%s", sources[pos]);
		printf("]... ");
	}
	code = rngCreate(code != ERR_OK ? cmdRngKeyboardSource : 0, 0);
	if (verbose)
		printf("%s\n", errMsg(code));
	return code;
}

err_t cmdRngTest()
{
	const char* sources[] = { "trng", "trng2", "timer", "sys" };
	octet buf[2500];
	bool_t trng = FALSE;
	size_t valid_sources = 0;
	size_t pos;
	// пробежать источники
	for (pos = 0; pos < COUNT_OF(sources); ++pos)
	{
		size_t read;
		if (rngReadSource(&read, buf, 2500, sources[pos]) != ERR_OK ||
			read != 2500)
			continue;
		// статистическое тестирование
		if (!rngTestFIPS1(buf) || !rngTestFIPS2(buf) ||
			!rngTestFIPS3(buf) || !rngTestFIPS4(buf))
			continue;
		// зафиксировать источник
		valid_sources++;
		if (strEq(sources[pos], "trng") || strEq(sources[pos], "trng2"))
		{
			trng = TRUE;
			break;
		}
	}
    // нет ни физического источника, ни двух разнотипных?
    if (!trng && valid_sources < 2)
        return ERR_BAD_ENTROPY;
    // все нормально
    return ERR_OK;
}
