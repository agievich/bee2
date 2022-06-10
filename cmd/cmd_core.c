/*
*******************************************************************************
\file cmd_core.c
\brief Command-line interface to Bee2: useful functions
\project bee2/cmd 
\created 2022.06.08
\version 2022.06.10
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "cmd.h"
#include <bee2/core/err.h>
#include <bee2/core/rng.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include <stdio.h>

/*
*******************************************************************************
Консоль
*******************************************************************************
*/

#ifdef OS_WIN

#include <conio.h>

#define getch _getch

#elif defined OS_UNIX

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

err_t cmdValFilesNotExist(int argc, const char* argv[])
{
	FILE* fp;
	int ch;
	for (; argc--; argv++)
		if (fp = fopen(*argv, "rb"))
		{
			fclose(fp);
			printf("Some files already exist. Overwrite [y/n]?");
			do
				ch = getch();
			while (ch != 'Y' && ch != 'y' && ch != 'N' && ch != 'n' && ch != '\n');
			printf("... ");
			if (ch == 'N' || ch == 'n' || ch == '\n')
				return ERR_FILE_EXISTS;
			break;
		}
	return ERR_OK;
}

err_t cmdValFilesExist(int argc, const char* argv[])
{
	FILE* fp;
	for (; argc--; argv++)
	{
		if (!(fp = fopen(*argv, "rb")))
			return ERR_FILE_NOT_FOUND;
		fclose(fp);
	}
	return ERR_OK;
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
