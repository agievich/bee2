/*
*******************************************************************************
\file rng_sys.c
\brief Random number generation: system entropy sources
\project bee2 [cryptographic library]
\created 2014.10.13
\version 2025.10.08
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/core/err.h"
#include "bee2/core/file.h"
#include "bee2/core/mem.h"
#include "bee2/core/util.h"

/*
*******************************************************************************
Системный источник

Системные источники Windows:
- функция CryptGenRandom() поверх стандартного провайдера PROV_RSA_FULL;
- функция RtlGenRandom(). 

Системный источник Unix:
- файл dev/urandom.

Дополнительный системный источник Linix:
- функция RAND_bytes() библиотеки OpenSSL/libcrypto.

Анализ источников:
* https://eprint.iacr.org/2005/029;
* https://eprint.iacr.org/2006/086;
* https://eprint.iacr.org/2007/419;
* https://eprint.iacr.org/2012/251;
* https://eprint.iacr.org/2014/167;
* https://eprint.iacr.org/2016/367;
* https://eprint.iacr.org/2022/558;
* https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/Studies/
  LinuxRNG/LinuxRNG_EN_V5_7.pdf;
* https://wiki.openssl.org/index.php/Random_Numbers;
* https://blog.cr.yp.to/20170723-random.html;
* https://www.2uo.de/myths-about-urandom;
* https://git.kernel.org/pub/scm/linux/kernel/git/crng/random.git/commit/?
  id=186873c549df11b63e17062f863654e1501e1524.

\remark Файл dev/random -- это, так называемый, блокирующий источник,
который не выдает данные, пока не будет накоплено достаточно энтропии.
Именно этот источник рекомендуется использовать в криптографических 
приложениях. Однако в наших экспериментах чтение из файла dev/random иногда 
выполнялось экстремально долго (возможно это связано с тем, что программы 
запускались под виртуальной машиной). Поэтому было решено использовать чтение
из dev/urandom. Это неблокирующий источник, который всегда выдает данные.

\remark Установка флагов CRYPT_VERIFYCONTEXT и CRYPT_SILENT при вызове
CryptAcquireContextW() снижает риск ошибочного завершения функции.

\remark На платформе OS_UNIX функция rngSys2Read() реализуется по-разному
в зависимости от использования инструмента MemSan (Memory Sanitizer).
Дело в том, что MemSan обнаруживает неинициализированные переменные в 
библиотеке OpenSSL/libcrypto, которая используется в rngSys2Read().

\todo Более тонкий поиск libcrypto.so.
*******************************************************************************
*/

#if defined OS_WIN

#include <windows.h>
#include <wincrypt.h>
#include <ntsecapi.h>

err_t rngSysRead(void* buf, size_t* read, size_t count)
{
	HCRYPTPROV hprov = 0;
	// pre
	ASSERT(memIsValid(read, O_PER_S));
	ASSERT(memIsValid(buf, count));
	ASSERT((size_t)(DWORD)count == count);
	// открыть провайдер
	if (!CryptAcquireContextW(&hprov, 0, 0, PROV_RSA_FULL,
		CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
		return ERR_FILE_NOT_FOUND;
	// получить данные
	*read = 0;
	if (!CryptGenRandom(hprov, (DWORD)count, (octet*)buf))
	{
		CryptReleaseContext(hprov, 0);
		return ERR_BAD_ENTROPY;
	}
	// завершение
	CryptReleaseContext(hprov, 0);
	*read = count;
	return ERR_OK;
}

err_t rngSys2Read(void* buf, size_t* read, size_t count)
{
	// pre
	ASSERT(memIsValid(read, O_PER_S));
	ASSERT(memIsValid(buf, count));
	ASSERT((size_t)(ULONG)count == count);
	// получить случайные данные
	*read = 0;
	if (!RtlGenRandom(buf, (ULONG)count))
		return ERR_BAD_ENTROPY;
	// завершение
	*read = count;
	return ERR_OK;
}

#elif defined OS_UNIX

#include <stdio.h>
#include <dlfcn.h>

err_t rngSysRead(void* buf, size_t* read, size_t count)
{
	file_t file;
	ASSERT(memIsValid(read, O_PER_S));
	ASSERT(memIsValid(buf, count));
	file = fileOpen("/dev/urandom", "rb");
	if (!file)
		return ERR_FILE_OPEN;
	*read = fileRead2(buf, count, file);
	fclose(file);
	return ERR_OK;
}

// http://clang.llvm.org/docs/MemorySanitizer.html#has-feature-memory-sanitizer
#if defined(__has_feature) 
#if __has_feature(memory_sanitizer)
#define MEMORY_SANITIZER
#endif
#endif

#if defined(OS_LINUX) && !defined(MEMORY_SANITIZER) 

err_t rngSys2Read(void* buf, size_t* read, size_t count)
{
	const char* names[] = {
		"libcrypto.so", "libcrypto.so.3", "libcrypto.so.1.1",
		"libcrypto.so.1.1.1" };
	size_t pos;
	void* lib;
	int(*rand_bytes)(octet*, int) = 0;
	// pre
	ASSERT(memIsValid(read, O_PER_S));
	ASSERT(memIsValid(buf, count));
	ASSERT((size_t)(int)count == count);
	// пробежать имена
	for (pos = 0; pos < COUNT_OF(names); ++pos)
		if (lib = dlopen(names[pos], RTLD_NOW))
			break;
	if (pos == COUNT_OF(names))
		return ERR_FILE_NOT_FOUND;
	// прочитать случайные данные
	*read = 0;
	rand_bytes = dlsym(lib, "RAND_bytes");
	if (!rand_bytes || rand_bytes(buf, (int)count) != 1)
	{
		dlclose(lib);
		return ERR_NOT_FOUND;
	}
	// завершение
	dlclose(lib);
	*read = count;
	return ERR_OK;
}

#elif defined(OS_APPLE)

#include <CommonCrypto/CommonRandom.h>

static err_t rngSys2Read(void* buf, size_t* read, size_t count)
{
	ASSERT(memIsValid(read, O_PER_S));
	ASSERT(memIsValid(buf, count));
	*read = 0;
	if (CCRandomGenerateBytes(buf, count) != kCCSuccess)
		return ERR_FILE_NOT_FOUND;
	*read = count;
	return ERR_OK;
}

#else

err_t rngSys2Read(void* buf, size_t* read, size_t count)
{
	ASSERT(memIsValid(read, O_PER_S));
	ASSERT(memIsValid(buf, count));
	return ERR_FILE_NOT_FOUND;
}

#endif

#else

err_t rngSysRead(void* buf, size_t* read, size_t count)
{
	ASSERT(memIsValid(read, O_PER_S));
	ASSERT(memIsValid(buf, count));
	return ERR_FILE_NOT_FOUND;
}

err_t rngSys2Read(void* buf, size_t* read, size_t count)
{
	ASSERT(memIsValid(read, O_PER_S));
	ASSERT(memIsValid(buf, count));
	return ERR_FILE_NOT_FOUND;
}

#endif
