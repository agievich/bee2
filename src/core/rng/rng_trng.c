/*
*******************************************************************************
\file rng_trng.c
\brief Random number generation: physical entropy sources
\project bee2 [cryptographic library]
\created 2014.10.13
\version 2025.10.08
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

Поддержан ГСЧ Intel

Реализация:
-	по материалам https://software.intel.com/en-us/articles/
	intel-digital-random-number-generator-drng-software-implementation-guide.

Используются инструкции:
-	rdseed -- без криптографической постобработки, т.е. прямая работа с
	источником случайности;
-	rdrand -- с криптографической постобработкой.

Инструкция rdseed напрямую ("честнее") работает с источником случайности,
инструкция rdrand поддержана более широко.

Инструкция rdseed используется в основном источнике "trng",
инструкция rdrand -- во вспомогательном источнике "trng2".
*******************************************************************************
*/

#if (_MSC_VER >= 1600) && (defined(_M_IX86) || defined(_M_X64))

#include <intrin.h>
#include <immintrin.h>

#define rngCPUID(info, id) __cpuidex((int*)info, id, 0)
#define rngRDStep(val) _rdseed32_step(val)
#define rngRDStep2(val) _rdrand32_step(val)

#elif defined(_MSC_VER) && defined(_M_IX86)

#define cpuid		__asm _emit 0x0F __asm _emit 0xA2
#define rdseed_eax	__asm _emit 0x0F __asm _emit 0xC7 __asm _emit 0xF8
#define rdrand_eax	__asm _emit 0x0F __asm _emit 0xC7 __asm _emit 0xF0

static void rngCPUID(u32 info[4], u32 id)
{
	u32 a, b, c, d;
	__asm {
		mov eax, id
		xor ecx, ecx
		cpuid
		mov a, eax
		mov b, ebx
		mov c, ecx
		mov d, edx
	}
	info[0] = a, info[1] = b, info[2] = c, info[3] = d; 
}

static int rngRDStep(u32* val)
{
	__asm {
		xor eax, eax
		xor edx, edx
		rdseed_eax
		jnc err
		mov edx, val
		mov [edx], eax
	}
	return 1;
err:
	return 0;
}

static int rngRDStep2(u32* val)
{
	__asm {
		xor eax, eax
		xor edx, edx
		rdrand_eax
		jnc err
		mov edx, val
		mov [edx], eax
	}
	return 1;
err:
	return 0;
}

#elif (defined(__GNUC__) || defined(__clang__)) && \
	(defined(__i386__) || defined(__x86_64__))

#include <cpuid.h>

#define rngCPUID(info, id) \
	__cpuid_count(id, 0, info[0], info[1], info[2], info[3])

static int rngRDStep(u32* val)
{
	octet ok = 0;
	asm ("rdseed %0; setc %1" : "=r" (*val), "=qm" (ok));
	return ok;
}

static int rngRDStep2(u32* val)
{
	octet ok = 0;
	asm ("rdrand %0; setc %1" : "=r" (*val), "=qm" (ok));
	return ok;
}

#else

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
	u32 rand;
	// pre
	ASSERT(memIsValid(read, O_PER_S));
	ASSERT(memIsValid(buf, count));
	// есть источник?
	*read = 0;
	if (!rngTRNGIsAvail())
		return ERR_FILE_NOT_FOUND;
	// генерация
	while (*read + 4 <= count)
	{
		if (!rngRDStep(&rand))
		{
			CLEAN(rand);
			return ERR_BAD_ENTROPY;
		}
		memCopy(buf, &rand, 4);
		buf = (octet*)buf + 4, *read += 4;		
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
	u32 rand;
	// pre
	ASSERT(memIsValid(read, O_PER_S));
	ASSERT(memIsValid(buf, count));
	// есть источник?
	*read = 0;
	if (!rngTRNG2IsAvail())
		return ERR_FILE_NOT_FOUND;
	// генерация
	while (*read + 4 <= count)
	{
		if (!rngRDStep2(&rand))
		{
			CLEAN(rand);
			return ERR_BAD_ENTROPY;
		}
		memCopy(buf, &rand, 4);
		buf = (octet*)buf + 4, *read += 4;		
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
