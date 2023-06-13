/*
*******************************************************************************
\file cmd_file.c
\brief Command-line interface to Bee2: file management
\project bee2/cmd 
\created 2022.06.08
\version 2023.06.13
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
	fclose(fp);
	return (size == -1L) ? SIZE_MAX : (size_t)size;
}

#if defined OS_UNIX

#include <unistd.h>

err_t cmdFileTrunc(const char* file, size_t size)
{
	ASSERT(strIsValid(file));
	if ((size_t)(long)size != size)
		return ERR_OVERFLOW;
	return truncate(file, (off_t)size) == 0 ? ERR_OK : ERR_FILE_WRITE;
}

#elif defined OS_WIN

#include <windows.h>

err_t cmdFileTrunc(const char* file, size_t size)
{
	err_t code = ERR_OK;
	HANDLE h;
	ASSERT(strIsValid(file));
	if ((size_t)(LONG)size != size)
		return ERR_OVERFLOW;
	if ((h = CreateFileA(file, GENERIC_WRITE, FILE_SHARE_WRITE, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE)
		return ERR_FILE_OPEN;
	if (SetFilePointer(h, (LONG)size, 0, FILE_BEGIN) ==
		INVALID_SET_FILE_POINTER)
		code = ERR_FILE_READ;
	else if (!SetEndOfFile(h))
		code = ERR_FILE_WRITE;
	CloseHandle(h);
	return code;
}

#else

#error "Not implemented"

#endif

/*
*******************************************************************************
Чтение / запись
*******************************************************************************
*/

err_t cmdFileWrite(const char* file, const octet buf[], size_t count)
{
	err_t code;
	FILE* fp;
	// pre
	ASSERT(strIsValid(file));
	ASSERT(memIsValid(buf, count));
	// записать
	code = (fp = fopen(file, "wb")) ? ERR_OK : ERR_FILE_CREATE;
	ERR_CALL_CHECK(code);
	code = count == fwrite(buf, 1, count, fp) ? ERR_OK : ERR_FILE_WRITE;
	fclose(fp);
	// завершить
	return code;
}

err_t cmdFileAppend(const char* file, const octet buf[], size_t count)
{
	err_t code;
	FILE* fp;
	// pre
	ASSERT(strIsValid(file));
	ASSERT(memIsValid(buf, count));
	// записать
	code = (fp = fopen(file, "ab")) ? ERR_OK : ERR_FILE_OPEN;
	ERR_CALL_CHECK(code);
	code = count == fwrite(buf, 1, count, fp) ? ERR_OK : ERR_FILE_WRITE;
	fclose(fp);
	// завершить
	return code;
}

err_t cmdFileReadAll(octet buf[], size_t* count, const char* file)
{
	err_t code;
	// pre
	ASSERT(memIsValid(count, O_PER_S));
	ASSERT(strIsValid(file));
	// читать
	if (buf)
	{
		FILE* fp;
		octet o[1];
		ASSERT(memIsValid(buf, *count));
		code = (fp = fopen(file, "rb")) ? ERR_OK : ERR_FILE_OPEN;
		ERR_CALL_CHECK(code);
		if (fread(buf, 1, *count, fp) != *count || fread(o, 1, 1, fp) != 0)
			code = ERR_FILE_READ;
		fclose(fp);
	}
	// определить длину файла
	else
	{
		size_t size = cmdFileSize(file);
		code = size != SIZE_MAX ? ERR_OK : ERR_FILE_READ;
		ERR_CALL_CHECK(code);
		*count = size;
	}
	return code;
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
		while (code == ERR_OK)
		{
			size_t c = fread(buf, 1, buf_size, ifp);
			if (c != buf_size && !feof(ifp))
				code = ERR_FILE_READ;
			else if (fwrite(buf, 1, c, ofp) != c)
				code = ERR_FILE_WRITE;
		}
	// завершить
	cmdBlobClose(buf);
	fclose(ofp), fclose(ifp);
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
			fclose(fp);
			printf("Some files already exist. Overwrite [y/n]?");
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
		fclose(fp);
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
