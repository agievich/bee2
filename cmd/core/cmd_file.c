/*
*******************************************************************************
\file cmd_file.c
\brief Command-line interface to Bee2: file management
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
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include <stdio.h>
#include <stdlib.h>

/*
*******************************************************************************
Размер файла
*******************************************************************************
*/

size_t cmdFileSize(const char* file)
{
	FILE* fp;
	long size;
	ASSERT(strIsValid(file));
	if (!(fp = fopen(file, "rb")))
		return SIZE_MAX;
	if (fseek(fp, 0, SEEK_END))
	{
		fclose(fp);
		return SIZE_MAX;
	}
	size = ftell(fp);
	if (fclose(fp) != 0)
		size = -1;
	return (size < 0) ? SIZE_MAX : (size_t)size;
}

/*
*******************************************************************************
Чтение / запись
*******************************************************************************
*/

err_t cmdFileWrite(const char* file, const void* buf, size_t count)
{
	FILE* fp;
	// pre
	ASSERT(strIsValid(file));
	ASSERT(memIsValid(buf, count));
	// записать
	if (!(fp = fopen(file, "wb")))
		return ERR_FILE_CREATE;
	if (count != fwrite(buf, 1, count, fp))
	{
		fclose(fp);
		return ERR_FILE_WRITE;
	}
	if (fclose(fp) != 0)
		return ERR_BAD_FILE;
	return ERR_OK;
}

err_t cmdFileAppend(const char* file, const void* buf, size_t count)
{
	FILE* fp;
	// pre
	ASSERT(strIsValid(file));
	ASSERT(memIsValid(buf, count));
	// дописать
	if (!(fp = fopen(file, "ab")))
		return ERR_FILE_OPEN;
	if (count != fwrite(buf, 1, count, fp))
	{
		fclose(fp);
		return ERR_FILE_WRITE;
	}
	if (fclose(fp) != 0)
		return ERR_BAD_FILE;
	return ERR_OK;
}

err_t cmdFileReadAll(void* buf, size_t* count, const char* file)
{
	// pre
	ASSERT(memIsValid(count, O_PER_S));
	ASSERT(strIsValid(file));
	// читать
	if (buf)
	{
		FILE* fp;
		ASSERT(memIsValid(buf, *count));
		if (!(fp = fopen(file, "rb")))
			return ERR_FILE_OPEN;
		if (fread(buf, 1, *count, fp) != *count || getc(fp) != EOF)
		{
			fclose(fp);
			return ERR_FILE_READ;
		}	
		if (fclose(fp) != 0)
			return ERR_BAD_FILE;
	}
	// определить длину файла
	else
	{
		size_t size;
		if ((size = cmdFileSize(file)) == SIZE_MAX)
			return ERR_FILE_READ;
		*count = size;
	}
	return ERR_OK;
}

/*
*******************************************************************************
Дублирование
*******************************************************************************
*/

err_t cmdFileDup(const char* ofile, const char* ifile, size_t skip,
	size_t count)
{
	const size_t buf_size = 4096;
	err_t code;
	FILE* ifp;
	FILE* ofp;
	void* buf;
	// pre
	ASSERT(strIsValid(ifile) && strIsValid(ofile));
	// переполнение?
	if ((size_t)(long)skip != skip)
		return ERR_OVERFLOW;
	// открыть входной файл
	ifp = fopen(ifile, "rb");
	if (!ifp)
		return ERR_FILE_OPEN;
	// пропустить skip октетов
	if (fseek(ifp, (long)skip, SEEK_SET))
	{
		fclose(ifp);
		return ERR_FILE_READ;
	}
	// открыть выходной файл
	ofp = fopen(ofile, "wb");
	if (!ofp)
	{
		fclose(ifp);
		return ERR_FILE_CREATE;
	}
	// подготовить память
	code = cmdBlobCreate(buf, buf_size);
	ERR_CALL_HANDLE(code, (fclose(ofp), fclose(ifp)));
	// дублировать count октетов
	if (count != SIZE_MAX)
		while (count && code == ERR_OK)
		{
			size_t c = MIN2(buf_size, count);
			if (fread(buf, 1, c, ifp) != c)
				code = ERR_FILE_READ;
			else if (fwrite(buf, 1, c, ofp) != c)
				code = ERR_FILE_WRITE;
			count -= c;
		}
	// дублировать все
	else
		while (count && code == ERR_OK)
		{
			count = fread(buf, 1, buf_size, ifp);
			if (count != buf_size && !feof(ifp))
				code = ERR_FILE_READ;
			else if (fwrite(buf, 1, count, ofp) != count)
				code = ERR_FILE_WRITE;
		}
	// завершить
	cmdBlobClose(buf);
	if (fclose(ofp) != 0)
		code = (code != ERR_OK) ? code : ERR_BAD_FILE;
	if (fclose(ifp) != 0)
		code = (code != ERR_OK) ? code : ERR_BAD_FILE;
	return code;
}

/*
*******************************************************************************
Проверки
*******************************************************************************
*/

err_t cmdFileValNotExist(int count, char* files[])
{
	FILE* fp;
	int ch;
	for (; count--; files++)
	{
		ASSERT(strIsValid(*files));
		if (fp = fopen(*files, "rb"))
		{
			if (fclose(fp) != 0)
				return ERR_BAD_FILE;
			if (printf("Some files already exist. Overwrite [y/n]?") < 0)
				return ERR_FILE_EXISTS;
			do
				ch = cmdTermGetch();
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
		if (fclose(fp) != 0)
			return ERR_BAD_FILE;
	}
	return ERR_OK;
}

bool_t cmdFileAreSame(const char* file1, const char* file2)
{
	bool_t ret;
#ifdef OS_UNIX
	char* path1 = realpath(file1, 0);
	char* path2 = realpath(file2, 0);
	ret = path1 && path2 && strEq(path1, path2);
	free(path1), free(path2);
#elif defined OS_WIN
	char* path1 = _fullpath(0, file1, 0);
	char* path2 = _fullpath(0, file2, 0);
	ret = path1 && path2 && strEq(path1, path2);
	free(path1), free(path2);
#else
	ret = strEq(file1, file2);
#endif
	return ret;
}
