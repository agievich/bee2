/*
*******************************************************************************
\file beltsum.c
\brief A file hashing utility based on belt-hash
\project bee2/apps/beltsum 
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2014.10.28
\version 2016.07.22
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include <stdio.h>
#include <locale.h>
#include <bee2/core/mem.h>
#include <bee2/core/hex.h>
#include <bee2/core/util.h>
#include <bee2/crypto/belt.h>

static void beltsumUsage()
{
	printf(
		"bee2/beltsum: STB 34.101.31 hashing\n"
		"[bee2 version %s]\n"
		"Usage: beltsum [file_name]\n"
		"    file_name -- file to hash\n", 
		utilVersion());
}

int main(int argc, char* argv[])
{
	FILE* fp;
	octet hash_state[4096];
	octet hash_buf[4096];
	size_t count;
	char szHash[8 * 8 + 8];
	// поддержка русских имен файлов
	setlocale(LC_ALL, "russian_belarus.1251");
	// разобрать командную строку
	if (argc != 2)
	{
		beltsumUsage();
		return -1;
	}
	// открыть файл
	fp = fopen(argv[1], "rb");
	if (!fp)
	{
		printf("File \"%s\" not found\n", argv[1]);
		return -1;
	}
	// хэшировать
	ASSERT(beltHash_keep() <= sizeof(hash_state));
	beltHashStart(hash_state);
	while (1)
	{
		count = fread(hash_buf, 1, sizeof(hash_buf), fp);
		if (count == 0)
		{
			if (ferror(fp) != 0)
			{
				fclose(fp);
				printf("File \"%s\" read error\n", argv[1]);
				return -1;
			}
			break;
		}
		beltHashStepH(hash_buf, count, hash_state);
	}
	// закрыть файл и завершить хэширование
	fclose(fp);
	beltHashStepG(hash_state, hash_state);
	// преобразовать в шестнадцатеричную строку
	hexFrom(szHash, hash_state, 32);
	memMove(szHash + 7 * 8 + 7, szHash + 7 * 8, 9);
	memMove(szHash + 6 * 8 + 6, szHash + 6 * 8, 8);
	memMove(szHash + 5 * 8 + 5, szHash + 5 * 8, 8);
	memMove(szHash + 4 * 8 + 4, szHash + 4 * 8, 8);
	memMove(szHash + 3 * 8 + 3, szHash + 3 * 8, 8);
	memMove(szHash + 2 * 8 + 2, szHash + 2 * 8, 8);
	memMove(szHash + 1 * 8 + 1, szHash + 1 * 8, 8);
	szHash[8] = szHash[17] = szHash[26] = szHash[35] =
		szHash[44] = szHash[53] = szHash[62] = ' ';
	// печать на консоль
	printf("%s & %s\n", argv[1], szHash);
	// завершение
	return 0;
}
