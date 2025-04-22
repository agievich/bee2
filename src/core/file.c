/*
*******************************************************************************
\file file.c
\brief File management
\project bee2 [cryptographic library]
\created 2025.04.11
\version 2025.04.16
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/core/err.h"
#include "bee2/core/file.h"
#include "bee2/core/mem.h"
#include "bee2/core/str.h"
#include "bee2/core/util.h"

#ifdef _MSC_VER
	#include <io.h>
#else
	#include <unistd.h>
	#include <sys/types.h>
#endif

/*
*******************************************************************************
Открытие / создание / закрытие
*******************************************************************************
*/

file_t fileOpen(const char* name, const char* mode)
{
	ASSERT(strIsValid(name));
	ASSERT(strIsValid(mode));
	return fopen(name, mode);
}

file_t fileTmp()
{
	return tmpfile();
}

bool_t fileClose(file_t file)
{
	ASSERT(fileIsValid(file));
	return fclose(file) ? FALSE : TRUE;
}

/*
*******************************************************************************
Файловый указатель
*******************************************************************************
*/

bool_t fileSeek(file_t file, size_t offset, int origin)
{
	ASSERT(fileIsValid(file));
	return (size_t)(long)offset == offset &&
		fseek(file, (long)offset, origin) == 0;
}

size_t fileTell(file_t file)
{
	long pos;
	ASSERT(fileIsValid(file));
	pos = ftell(file);
	if (pos == -1L || (long)(size_t)pos != pos)
		return SIZE_MAX;
	return (size_t)pos;
}

/*
*******************************************************************************
Проверка
*******************************************************************************
*/

bool_t fileIsValid(const file_t file)
{
	return memIsValid(file, sizeof(FILE));
}

/*
*******************************************************************************
Чтение / запись
*******************************************************************************
*/

err_t fileWrite(size_t* written, const void* buf, size_t count, file_t file)
{
	ASSERT(memIsValid(buf, count));
	ASSERT(fileIsValid(file));
	ASSERT(memIsValid(written, O_PER_S));
	*written = fwrite(buf, 1, count, file);
	if (*written != count)
		return ERR_FILE_WRITE;
	return ERR_OK;
}

size_t fileWrite2(file_t file, const void* buf, size_t count)
{
	size_t written;
	if (fileWrite(&written, buf, count, file) != ERR_OK)
		return SIZE_MAX;
	return written;
}

bool_t fileFlush(file_t file)
{
	ASSERT(fileIsValid(file));
	return fflush(file) == 0;
}

err_t fileRead(size_t* read, void* buf, size_t count, file_t file)
{
	ASSERT(memIsValid(buf, count));
	ASSERT(fileIsValid(file));
	ASSERT(memIsValid(read, O_PER_S));
	*read = fread(buf, 1, count, file);
	if (*read != count)
		return feof(file) ? ERR_MAX : ERR_FILE_READ;
	return ERR_OK;
}

size_t fileRead2(void* buf, size_t count, file_t file)
{
	err_t code;
	size_t read;
	code = fileRead(&read, buf, count, file);
	if (code != ERR_OK && code != ERR_MAX)
		return SIZE_MAX;
	return read;
}

bool_t filePuts(file_t file, const char* str)
{
	ASSERT(strIsValid(str));
	ASSERT(fileIsValid(file));
	return fputs(str, file) >= 0;
}

char* fileGets(char* str, size_t count, file_t file)
{
	ASSERT(memIsValid(str, count));
	ASSERT(fileIsValid(file));
	if (count <= 1 || (size_t)(int)count != count)
		return 0;
	return fgets(str, (int)count, file);
}

/*
*******************************************************************************
Размер
*******************************************************************************
*/

size_t fileSize(file_t file)
{
	ASSERT(fileIsValid(file));
	return fileSeek(file, 0, SEEK_END) ? fileTell(file) : SIZE_MAX;
}

bool_t fileTrunc(file_t file, size_t size)
{
	ASSERT(fileIsValid(file));
#ifdef _MSC_VER
	return (size_t)(__int64)size == size &&
		_chsize_s(_fileno(file), (__int64)size) == 0;
#else
	return (size_t)(off_t)size == size &&
		ftruncate(fileno(file), (off_t)size) == 0;
#endif
}
