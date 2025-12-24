/*
*******************************************************************************
\file rng_trng.c
\brief Random number generation: physical entropy sources
\project bee2 [cryptographic library]
\created 2014.10.13
\version 2025.12.24
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/core/err.h"
#include "bee2/core/mem.h"
#include "bee2/core/str.h"
#include "bee2/core/util.h"

/*
*******************************************************************************
Физические источники

ГСЧ Intel/AMD

Инструкции для работы с ГСЧ:
-	RDSEED -- выдает данные от источника случайности после их
	криптографической постобработки с помощью AES-CBC-MAC;
-	RDRAND -- выдает данные генератора псевдослучайных чисел AES-CTR-DRBG.
	Затравочное значение генератора (seed) строится по данным от источника
	случайности и периодически обновляется (в соответствии с [1]: не реже
	чем после 1022 обращений к RDRAND).

Инструкция RDSEED используется в основном источнике "trng", инструкция
RDRAND -- во вспомогательном источнике "trng2".

Архитектура ГСЧ / описание инструкций:
[1] Intel Digital Random Number Generator (DRNG) Software Implementation Guide.
	Technical Paper. Revision 2.2, September 2025.
	https://www.intel.com/content/www/us/en/content-details/864722/
	intel-digital-random-number-generator-software-implementation-guide.html.
[2] AMD Random Number Generator, 6/27/17.
    https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/
	white-papers/amd-random-number-generator.pdf.
[3] Intel 64 and IA-32 Architectures Software Developer’s Manual. Volume 1:
	Basic Architecture, September 2016.
	https://www.intel.com/content/dam/www/public/us/en/documents/manuals/
	64-ia-32-architectures-software-developer-vol-1-manual.pdf.

Работа с ГСЧ реализована в соответствии с рекомендациями в [1]. Детали
реализации:
1. Если инструкция RDRAND завершена с ошибкой, т.е. случайное число не было
   сгенерировано, то предпринимаются повторные попытки генерации, вплоть до 10.
2. В случае ошибки при вызове RDSEED число  попыток увеличивается до 100 и между
   попытками вызывается инструкция PAUSE.

\warning RDSEED Failure on AMD “Zen 5” Processors:
https://www.amd.com/en/resources/product-security/bulletin/amd-sb-7055.html
*******************************************************************************
*/

#if (_MSC_VER >= 1600) && (defined(_M_IX86) || defined(_M_X64))

#include <intrin.h>
#include <immintrin.h>

#if defined(_M_IX86) 
typedef u32 trng_val_t;
#else
typedef u64 trng_val_t;
#endif

#define rngCPUID(info, id) __cpuid(info, id)

static int rngRDStep(trng_val_t* val)
{
	size_t retries = 100;
	while (retries--)
	{
#if defined(_M_IX86) 
		if (_rdseed32_step(val))
#else
		if (_rdseed64_step(val))
#endif
			return 1;
		_mm_pause();
	}
	return 0;
}

static int rngRDStep2(trng_val_t* val)
{
	size_t retries = 10;
	while (retries--)
	{
#if defined(_M_IX86) 
		if (_rdrand32_step(val))
#else
		if (_rdrand64_step(val))
#endif
			return 1;
	}
	return 0;
}

#elif defined(_MSC_VER) && defined(_M_IX86)

#include <intrin.h>

typedef u32 trng_val_t;

#define rngCPUID(info, id) __cpuid(info, id)
#define pause __asm _emit 0xF3 __asm _emit 0x90
#define rdseed_eax __asm _emit 0x0F __asm _emit 0xC7 __asm _emit 0xF8
#define rdrand_eax __asm _emit 0x0F __asm _emit 0xC7 __asm _emit 0xF0

static int rngRDStep(trng_val_t* val)
{
	size_t retries = 100;
	while (retries--)
	{
		__asm {
			xor eax, eax
			rdseed_eax
			jnc err
			mov edx, val
			mov[edx], eax
		}
		return 1;
	err:
		_asm pause;
	}
	return 0;
}

static int rngRDStep2(trng_val_t* val)
{
	size_t retries = 10;
	while (retries--)
	{
		__asm {
			xor eax, eax
			rdrand_eax
			jnc err
			mov edx, val
			mov[edx], eax
		}
		return 1;
	err:
		continue;
	}
	return 0;
}

#elif (defined(__GNUC__) || defined(__clang__)) &&\
	(defined(__i386__) || defined(__x86_64__))

#include <cpuid.h>

#if defined(__i386__)
typedef u32 trng_val_t;
#else
typedef u64 trng_val_t;
#endif

#define rngCPUID(info, id)\
	__cpuid_count(id, 0, info[0], info[1], info[2], info[3])

static int rngRDStep(trng_val_t* val)
{
	size_t retries = 100;
	while (retries--)
	{
		octet ok = 0;
		asm("rdseed %0; setc %1" : "=r" (*val), "=qm" (ok));
		if (ok)
			return 1;
		asm("pause");
	}
	return 0;
}

static int rngRDStep2(trng_val_t* val)
{
	size_t retries = 100;
	while (retries--)
	{
		octet ok = 0;
		asm("rdrand %0; setc %1" : "=r" (*val), "=qm" (ok));
		if (ok)
			return 1;
	}
	return 0;
}

#else

typedef u32 trng_val_t;

#define rngCPUID(info, id) memSetZero(info, 16)
#define rngRDStep(val) 0
#define rngRDStep2(val) 0

#endif

static bool_t rngCPUIDIsManufId(const u32 info[4], const char id[12 + 1])
{
	ASSERT(strIsValid(id));
	ASSERT(strLen(id) == 12);
	return memEq(info + 1, id + 0, 4) &&
		memEq(info + 3, id + 4, 4) &&
		memEq(info + 2, id + 8, 4);
}

static bool_t rngTRNGIsAvail()
{
	u32 info[4];
	// Intel or AMD?
	rngCPUID(info, 0);
	if (!rngCPUIDIsManufId(info, "GenuineIntel") &&
		!rngCPUIDIsManufId(info, "AuthenticAMD"))
		return FALSE;
	// rdseed?
	rngCPUID(info, 7);
	return (info[1] & 0x00040000) != 0;
}

static bool_t rngTRNG2IsAvail()
{
	u32 info[4];
	// Intel or AMD?
	rngCPUID(info, 0);
	if (!rngCPUIDIsManufId(info, "GenuineIntel") &&
		!rngCPUIDIsManufId(info, "AuthenticAMD"))
		return FALSE;
	// rdrand?
	rngCPUID(info, 1);
	return (info[2] & 0x40000000) != 0;
}

err_t rngTRNGRead(void* buf, size_t* read, size_t count)
{
	trng_val_t rand;
	// pre
	ASSERT(memIsValid(read, O_PER_S));
	ASSERT(memIsValid(buf, count));
	// есть источник?
	*read = 0;
	if (!rngTRNGIsAvail())
		return ERR_FILE_NOT_FOUND;
	// генерация
	while (*read + sizeof(trng_val_t) <= count)
	{
		if (!rngRDStep(&rand))
		{
			CLEAN(rand);
			return ERR_BAD_ENTROPY;
		}
		memCopy(buf, &rand, sizeof(trng_val_t));
		buf = (octet*)buf + sizeof(trng_val_t);
		*read += sizeof(trng_val_t);
	}
	// неполный блок
	if (*read < count)
	{
		if (!rngRDStep(&rand))
		{
			CLEAN(rand);
			return ERR_BAD_ENTROPY;
		}
		memCopy(buf, &rand, count - *read);
		*read = count;
	}
	CLEAN(rand);
	return ERR_OK;
}

err_t rngTRNG2Read(void* buf, size_t* read, size_t count)
{
	trng_val_t rand;
	// pre
	ASSERT(memIsValid(read, O_PER_S));
	ASSERT(memIsValid(buf, count));
	// есть источник?
	*read = 0;
	if (!rngTRNG2IsAvail())
		return ERR_FILE_NOT_FOUND;
	// генерация
	while (*read + sizeof(trng_val_t) <= count)
	{
		if (!rngRDStep2(&rand))
		{
			CLEAN(rand);
			return ERR_BAD_ENTROPY;
		}
		memCopy(buf, &rand, sizeof(trng_val_t));
		buf = (octet*)buf + sizeof(trng_val_t);
		*read += sizeof(trng_val_t);
	}
	// неполный блок
	if (*read < count)
	{
		if (!rngRDStep2(&rand))
		{
			CLEAN(rand);
			return ERR_BAD_ENTROPY;
		}
		memCopy(buf, &rand, count - *read);
		*read = count;
	}
	CLEAN(rand);
	return ERR_OK;
}
