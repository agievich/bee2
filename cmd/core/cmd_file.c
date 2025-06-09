/*
*******************************************************************************
\file cmd_file.c
\brief Command-line interface to Bee2: file management
\project bee2/cmd 
\created 2022.06.08
\version 2025.06.09
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <stdlib.h>
#include <errno.h>
#include <bee2/core/der.h>
#include <bee2/core/err.h>
#include <bee2/core/file.h>
#include <bee2/core/mem.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include "bee2/cmd.h"

/*
*******************************************************************************
Размер файла
*******************************************************************************
*/

size_t cmdFileSize(const char* name)
{
	err_t code;
	file_t file;
	size_t size;
	// pre
	ASSERT(strIsValid(name));
	// определить размер
	code = cmdFileOpen(file, name, "rb");
	ERR_CALL_CHECK(code);
	size = fileSize(file);
	code = cmdFileClose2(file);
	return (size == SIZE_MAX || code != ERR_OK) ? SIZE_MAX : size;
}

/*
*******************************************************************************
Чтение / запись
*******************************************************************************
*/

err_t cmdFileWrite(const char* name, const void* buf, size_t count)
{
	err_t code;
	file_t file;
	// pre
	ASSERT(strIsValid(name));
	ASSERT(memIsValid(buf, count));
	// записать
	code = cmdFileOpen(file, name, "wb");
	ERR_CALL_CHECK(code);
	code = fileWrite(&count, buf, count, file);
	ERR_CALL_HANDLE(code, cmdFileClose(file));
	return cmdFileClose2(file);
}

err_t cmdFilePrepend(const char* name, const void* buf, size_t count)
{
	const size_t buf1_size = 4096;
	err_t code;
	file_t file;
	size_t size;
	size_t pos;
	void* buf1;
	// pre
	ASSERT(strIsValid(name));
	ASSERT(memIsValid(buf, count));
	// открыть файл
	code = cmdFileOpen(file, name, "r+b");
	if (code != ERR_OK)
	{
		// не открывается, но существует?
		code = cmdFileOpen(file, name, "rb");
		if (code == ERR_OK)
		{
			cmdFileClose(file);
			return ERR_FILE_OPEN;
		}
		// не существует => создать
		return cmdFileWrite(name, buf, count);
	}
	// определить размер файла
	if ((size = fileSize(file)) == SIZE_MAX)
	{
		cmdFileClose(file);
		return ERR_FILE_READ;
	}
	// сдвинуть содержимое файла вправо
	code = cmdBlobCreate(buf1, buf1_size);
	ERR_CALL_HANDLE(code, cmdFileClose(file));
	for (pos = size; code == ERR_OK && pos;)
	{
		size_t c;
		c = MIN2(buf1_size, pos), pos -= c;
		if (!fileSeek(file, pos, SEEK_SET) ||
			fileRead2(buf1, c, file) != c ||
			!fileSeek(file, pos + count, SEEK_SET))
			code = ERR_FILE_READ;
		else
			code = fileWrite(&c, buf1, c, file);
	}
	cmdBlobClose(buf1);
	ERR_CALL_HANDLE(code, cmdFileClose(file));
	// дописать в начало
	if (!fileSeek(file, 0, SEEK_SET))
		code = ERR_FILE_READ;
	else
		code = fileWrite(&count, buf, count, file);
	ERR_CALL_HANDLE(code, cmdFileClose(file));
	// завершить
	return cmdFileClose2(file);
}

err_t cmdFileAppend(const char* name, const void* buf, size_t count)
{
	err_t code;
	file_t file;
	// pre
	ASSERT(strIsValid(name));
	ASSERT(memIsValid(buf, count));
	// дописать в конец
	code = cmdFileOpen(file, name, "ab");
	ERR_CALL_CHECK(code);
	code = fileWrite(&count, buf, count, file);
	ERR_CALL_HANDLE(code, cmdFileClose(file));
	return cmdFileClose2(file);
}

err_t cmdFileReadAll(void* buf, size_t* count, const char* name)
{
	err_t code;
	file_t file;
	// pre
	ASSERT(memIsValid(count, O_PER_S));
	ASSERT(strIsValid(name));
	// открыть файл
	code = cmdFileOpen(file, name, "rb");
	ERR_CALL_CHECK(code);
	// определить длину файла
	if (!buf)
	{
		*count = cmdFileSize(name);
		if (*count == SIZE_MAX)
			code = ERR_FILE_READ;
	}
	// читать
	else
	{
		ASSERT(memIsValid(buf, *count));
		if (fileRead2(buf, *count, file) != *count)
			code = ERR_FILE_READ;
		else if (fileSize(file) != *count)
			code = ERR_BAD_FILE;
	}
	ERR_CALL_HANDLE(code, cmdFileClose(file));
	return cmdFileClose2(file);
}

/*
*******************************************************************************
Обрезка
*******************************************************************************
*/

err_t cmdFileBehead(const char* name, size_t count)
{
	const size_t buf_size = 4096;
	err_t code;
	file_t file;
	size_t size;
	size_t pos;
	void* buf;
	// pre
	ASSERT(strIsValid(name));
	// открыть файл
	code = cmdFileOpen(file, name, "r+b");
	ERR_CALL_CHECK(code);
	// определить размер файла
	if ((size = fileSize(file)) == SIZE_MAX)
		code = ERR_FILE_READ;
	else if (size < count)
		code = ERR_FILE_SIZE;
	ERR_CALL_HANDLE(code, cmdFileClose(file));
	// сдвинуть содержимое файла влево
	code = cmdBlobCreate(buf, buf_size);
	ERR_CALL_HANDLE(code, cmdFileClose(file));
	for (pos = 0; code == ERR_OK && pos < size - count;)
	{
		size_t c = MIN2(buf_size, size - count - pos);
		if (!fileSeek(file, pos + count, SEEK_SET) ||
			fileRead2(buf, c, file) != c ||
			!fileSeek(file, pos, SEEK_SET))
			code = ERR_FILE_READ;
		else
			code = fileWrite(&c, buf, c, file);
		pos += c;
	}
	cmdBlobClose(buf);
	ERR_CALL_HANDLE(code, cmdFileClose(file));
	// обрезать файл
	if (!fileTrunc(file, size - count))
		code = ERR_FILE_WRITE;
	ERR_CALL_HANDLE(code, cmdFileClose(file));
	// завершить
	return cmdFileClose2(file);
}

err_t cmdFileDrop(const char* name, size_t count)
{
	err_t code;
	file_t file;
	size_t size;
	// pre
	ASSERT(strIsValid(name));
	// открыть файл
	code = cmdFileOpen(file, name, "r+b");
	ERR_CALL_CHECK(code);
	// определить размер файла
	if ((size = fileSize(file)) == SIZE_MAX)
		code = ERR_FILE_READ;
	else if (size < count)
		code = ERR_FILE_SIZE;
	ERR_CALL_HANDLE(code, cmdFileClose(file));
	// обрезать файл
	if (!fileTrunc(file, size - count))
		code = ERR_FILE_WRITE;
	ERR_CALL_HANDLE(code, cmdFileClose(file));
	// завершить
	return cmdFileClose2(file);
}

/*
*******************************************************************************
Дублирование
*******************************************************************************
*/

err_t cmdFileDup(const char* oname, const char* iname, size_t skip,
	size_t count)
{
	const size_t buf_size = 4096;
	err_t code;
	file_t ifile;
	file_t ofile;
	void* buf;
	// pre
	ASSERT(strIsValid(iname) && strIsValid(oname));
	// открыть входной файл
	code = cmdFileOpen(ifile, iname, "rb");
	ERR_CALL_CHECK(code);
	// пропустить skip октетов
	if (!fileSeek(ifile, skip, SEEK_SET))
	{
		cmdFileClose(ifile);
		return ERR_FILE_READ;
	}
	// открыть выходной файл
	code = cmdFileOpen(ofile, oname, "wb");
	ERR_CALL_HANDLE(code, cmdFileClose(ifile));
	// подготовить память
	code = cmdBlobCreate(buf, buf_size);
	ERR_CALL_HANDLE(code, (cmdFileClose(ofile), cmdFileClose(ifile)));
	// дублировать count октетов
	if (count != SIZE_MAX)
		while (count && code == ERR_OK)
		{
			size_t c = MIN2(buf_size, count);
			if (fileRead2(buf, c, ifile) != c)
				code = ERR_FILE_READ;
			else
				code = fileWrite(&c, buf, c, ofile);
			count -= c;
		}
	// дублировать все
	else
		while (count && code == ERR_OK)
		{
			count = fileRead2(buf, buf_size, ifile);
			if (count == SIZE_MAX)
				code = ERR_FILE_READ;
			else 
				code = fileWrite(&count, buf, count, ofile);
		}
	// завершить
	cmdBlobClose(buf);
	ERR_CALL_HANDLE(code, (cmdFileClose(ofile), cmdFileClose(ifile)));
	code = cmdFileClose2(ofile);
	ERR_CALL_HANDLE(code, cmdFileClose(ifile));
	return cmdFileClose2(ifile);
}

/*
*******************************************************************************
Проверки
*******************************************************************************
*/

err_t cmdFileValNotExist(int count, char* names[])
{
	err_t code;
	file_t file;
	int ch;
	for (; count--; names++)
	{
		ASSERT(strIsValid(*names));
		code = cmdFileOpen(file, *names, "rb");
		if (code == ERR_OK)
		{
			code = cmdFileClose2(file);
			ERR_CALL_CHECK(code);
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

err_t cmdFileValExist(int count, char* names[])
{
	err_t code;
	file_t file;
	for (; count--; names++)
	{
		ASSERT(strIsValid(*names));
		code = cmdFileOpen(file, *names, "rb");
		if (code != ERR_OK)
			return ERR_FILE_NOT_FOUND;
		code = cmdFileClose2(file);
		ERR_CALL_CHECK(code);
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

/*
*******************************************************************************
Аффиксы
*******************************************************************************
*/

err_t cmdFilePrefixRead(octet* prefix, size_t* count, const char* name,
	size_t offset)
{
	const size_t buf_size = 16;
	err_t code;
	file_t file;
	size_t size;
	void* buf;
	size_t c;
	u32 tag;
	size_t len;
	// pre
	ASSERT(strIsValid(name));
	ASSERT(memIsValid(count, O_PER_S));
	// открыть файл
	code = cmdFileOpen(file, name, "rb");
	ERR_CALL_CHECK(code);
	// определить размер файла
	if ((size = fileSize(file)) == SIZE_MAX)
		code = ERR_FILE_READ;
	else if (offset >= size)
		code = ERR_FILE_SIZE;
	ERR_CALL_HANDLE(code, cmdFileClose(file));
	// подготовить память
	code = cmdBlobCreate(buf, buf_size);
	ERR_CALL_HANDLE(code, cmdFileClose(file));
	// прочитать заголовок префикса
	c = MIN2(buf_size, size - offset);
	if (!fileSeek(file, offset, SEEK_SET) ||
		fileRead2(buf, c, file) != c)
		code = ERR_FILE_READ;
	ERR_CALL_HANDLE(code, (cmdBlobClose(buf), cmdFileClose(file)));
	// определить длину префикса
	c = derTLDec(&tag, &len, buf, c);
	if (c == SIZE_MAX || offset + c + len > size)
		code = ERR_BAD_FORMAT;
	ERR_CALL_HANDLE(code, (cmdBlobClose(buf), cmdFileClose(file)));
	c += len;
	// прочитать префикс
	cmdBlobClose(buf);
	code = cmdBlobCreate(buf, c);
	ERR_CALL_HANDLE(code, cmdFileClose(file));
	if (!fileSeek(file, offset, SEEK_SET) ||
		fileRead2(buf, c, file) != c)
		code = ERR_FILE_READ;
	ERR_CALL_HANDLE(code, (cmdBlobClose(buf), cmdFileClose(file)));
	// закрыть файл
	code = cmdFileClose2(file);
	ERR_CALL_HANDLE(code, cmdBlobClose(buf));
	// проверить префикс
	if (!derIsValid3(buf, c))
		code = ERR_BAD_FORMAT;
	ERR_CALL_HANDLE(code, cmdBlobClose(buf));
	// возвратить префикс и его длину
	if (prefix)
	{
		ASSERT(memIsValid(prefix, *count));
		if (*count < c)
			code = ERR_OUTOFMEMORY;
		else
			memCopy(prefix, buf, c);
	}
	*count = c;
	// завершить
	cmdBlobClose(buf);
	return code;
}

err_t cmdFileSuffixRead(octet* suffix, size_t* count, const char* name,
	size_t offset)
{
	const size_t buf_size = 16;
	err_t code;
	file_t file;
	size_t size;
	void* buf;
	size_t c;
	u32 tag;
	size_t len;
	// pre
	ASSERT(strIsValid(name));
	ASSERT(memIsValid(count, O_PER_S));
	// открыть файл
	code = cmdFileOpen(file, name, "rb");
	ERR_CALL_CHECK(code);
	// определить размер файла
	if ((size = fileSize(file)) == SIZE_MAX)
		code = ERR_FILE_READ;
	else if (offset >= size)
		code = ERR_FILE_SIZE;
	ERR_CALL_HANDLE(code, cmdFileClose(file));
	// подготовить память
	code = cmdBlobCreate(buf, buf_size);
	ERR_CALL_HANDLE(code, cmdFileClose(file));
	// прочитать заголовок суффикса
	c = MIN2(buf_size, size - offset);
	if (!fileSeek(file, size - offset - c, SEEK_SET) ||
		fileRead2(buf, c, file) != c)
		code = ERR_FILE_READ;
	ERR_CALL_HANDLE(code, (cmdBlobClose(buf), cmdFileClose(file)));
	// развернуть суффикс
	memRev(buf, c);
	// определить длину суффикса
	c = derTLDec(&tag, &len, buf, c);
	if (c == SIZE_MAX || offset + c + len > size)
		code = ERR_BAD_FORMAT;
	ERR_CALL_HANDLE(code, (cmdBlobClose(buf), cmdFileClose(file)));
	c += len;
	// прочитать суффикс
	cmdBlobClose(buf);
	code = cmdBlobCreate(buf, c);
	ERR_CALL_HANDLE(code, cmdFileClose(file));
	if (!fileSeek(file, size - offset - c, SEEK_SET) ||
		fileRead2(buf, c, file) != c)
		code = ERR_FILE_READ;
	ERR_CALL_HANDLE(code, (cmdBlobClose(buf), cmdFileClose(file)));
	// закрыть файл
	code = cmdFileClose2(file);
	ERR_CALL_HANDLE(code, cmdBlobClose(buf));
	// проверить суффикс
	memRev(buf, c);
	if (!derIsValid3(buf, c))
		code = ERR_BAD_FORMAT;
	ERR_CALL_HANDLE(code, cmdBlobClose(buf));
	memRev(buf, c);
	// возвратить суффикс и его длину
	if (suffix)
	{
		ASSERT(memIsValid(suffix, *count));
		if (*count < c)
			code = ERR_OUTOFMEMORY;
		else
			memCopy(suffix, buf, c);
	}
	*count = c;
	// завершить
	cmdBlobClose(buf);
	return code;
}

/*
*******************************************************************************
Удаление
*******************************************************************************
*/

#ifdef OS_UNIX

#include <unistd.h>
#define cmdFileUnlink unlink

#elif defined OS_WIN

#include <io.h>
#include <stdio.h>
#define cmdFileUnlink _unlink

#else

static int cmdFileUnlink(const char* name)
{
	errno = ENOSYS;
	return -1;
}

#endif

err_t cmdFileDel(const char* name)
{
	ASSERT(strIsValid(name));
	if (cmdFileUnlink(name) == 0)
		return ERR_OK;
	switch (errno)
	{
	case EACCES:
		return ERR_FILE_READ;
	case ENOENT:
		return ERR_FILE_NOT_FOUND;
	case ENOSYS:
		return ERR_NOT_IMPLEMENTED;
	default:
		return ERR_BAD_FILE;
	}
}
