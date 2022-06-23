/*
*******************************************************************************
\file cmd_core.c
\brief Command-line interface to Bee2: useful functions
\project bee2/cmd 
\created 2022.06.08
\version 2022.06.21
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

#define getch _getch

#else

int getch()
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
	FILE* fp = 0;
	long int size;
	ASSERT(strIsValid(file));
	if (!(fp = fopen(file, "rb")))
		return SIZE_MAX;
	if (fseek(fp, 0, SEEK_END) || (size = ftell(fp)) == -1L)
	{
		fclose(fp);
		return SIZE_MAX;
	}
	return (size_t)size;
}

bool_t cmdFileValNotExist(int count, char* files[])
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
			printf(" ");
			if (ch == 'N' || ch == 'n' || ch == '\n')
				return FALSE;
			break;
		}
	}
	return TRUE;
}

bool_t cmdFileValExist(int count, char* files[])
{
	FILE* fp;
	for (; count--; files++)
	{
		ASSERT(strIsValid(*files));
		if (!(fp = fopen(*files, "rb")))
			return FALSE;
		fclose(fp);
	}
	return TRUE;
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

err_t cmdRngTest()
{
	const char* sources[] = { "trng", "trng2", "timer", "sys" };
	octet buf[2500];
	bool_t trng = FALSE;
	size_t valid_sources = 0, i;
	// пробежать источники
	for (i = 0; i < COUNT_OF(sources); ++i)
	{
		size_t read;
		if (rngReadSource(&read, buf, 2500, sources[i]) != ERR_OK ||
			read != 2500)
			continue;
		// статистическое тестирование
		if (!rngTestFIPS1(buf) || !rngTestFIPS2(buf) ||
			!rngTestFIPS3(buf) || !rngTestFIPS4(buf))
			continue;
		// зафиксировать источник
		valid_sources++;
		if (strEq(sources[i], "trng") || strEq(sources[i], "trng2"))
			trng = TRUE;
	}
	// нет ни физического источника, ни двух разнотипных?
	if (!trng && valid_sources < 2)
		return ERR_BAD_ENTROPY;
	// все нормально
	return ERR_OK;
}
