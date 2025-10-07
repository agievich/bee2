/*
*******************************************************************************
\file rng.c
\brief Entropy sources and random number generators
\project bee2 [cryptographic library]
\created 2014.10.13
\version 2025.10.07
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/core/blob.h"
#include "bee2/core/err.h"
#include "bee2/core/file.h"
#include "bee2/core/mem.h"
#include "bee2/core/mt.h"
#include "bee2/core/str.h"
#include "bee2/core/tm.h"
#include "bee2/core/rng.h"
#include "bee2/core/u32.h"
#include "bee2/core/util.h"
#include "bee2/core/word.h"
#include "bee2/crypto/belt.h"
#include "bee2/crypto/brng.h"

/*
*******************************************************************************
Статистические тесты

\todo Оценка энтропии.
*******************************************************************************
*/

bool_t rngTestFIPS1(const octet buf[2500])
{
	register size_t s;
	register word w;
	size_t count;
	ASSERT(memIsValid(buf, 2500));
	for (w = 0, count = 2500; !memIsAligned(buf, O_PER_W); ++buf, --count)
		w = (w << 8) | *buf;
	s = wordWeight(w);
	for (; count >= O_PER_W; buf += O_PER_W, count -= O_PER_W)
	{
		ASSERT(memIsAligned(buf, O_PER_W));
		s += wordWeight(*(const word*)buf);
	}
	for (w = 0; count; ++buf, --count)
		w = (w << 8) | *buf;
	s += wordWeight(w);
	CLEAN(w);
	return 9725 < s && s < 10275;
}

bool_t rngTestFIPS2(const octet buf[2500])
{
	u32 s[16];
	size_t i = 2500;
	ASSERT(memIsValid(buf, 2500));
	memSetZero(s, sizeof(s));
	while (i--)
		++s[buf[i] & 15], ++s[buf[i] >> 4];
	s[0] *= s[0];
	for (i = 1; i < 16; ++i)
		s[0] += s[i] * s[i];
	s[0] = 16 * s[0] - 5000 * 5000;
	return 10800 < s[0] && s[0] < 230850;
}

bool_t rngTestFIPS3(const octet buf[2500])
{
	word s[2][7];
	octet b;
	size_t l;
	size_t i;
	ASSERT(memIsValid(buf, 2500));
	memSetZero(s, sizeof(s));
	b = buf[0] & 1;
	l = 1;
	for (i = 1; i < 20000; ++i)
		if ((buf[i / 8] >> i % 8 & 1) == b)
			++l;
		else
			++s[b][MIN2(l, 6)], b = !b, l = 1;
	++s[b][MIN2(l, 6)];
	return 2315 <= s[0][1] && s[0][1] <= 2685 &&
		2315 <= s[1][1] && s[1][1] <= 2685 &&
		1114 <= s[0][2] && s[0][2] <= 1386 &&
		1114 <= s[1][2] && s[1][2] <= 1386 &&
		527 <= s[0][3] && s[0][3] <= 723 &&
		527 <= s[1][3] && s[1][3] <= 723 &&
		240 <= s[0][4] && s[0][4] <= 384 &&
		240 <= s[1][4] && s[1][4] <= 384 &&
		103 <= s[0][5] && s[0][5] <= 209 &&
		103 <= s[1][5] && s[1][5] <= 209 &&
		103 <= s[0][6] && s[0][6] <= 209 &&
		103 <= s[1][6] && s[1][6] <= 209;
}

bool_t rngTestFIPS4(const octet buf[2500])
{
	octet b;
	size_t l;
	size_t i;
	ASSERT(memIsValid(buf, 2500));
	b = buf[0] & 1;
	l = 1;
	for (i = 1; i < 20000; ++i)
		if ((buf[i / 8] >> i % 8 & 1) == b)
			++l;
		else
		{
			if (l >= 26)
				return FALSE;
			b = !b, l = 1;
		}
	return l < 26;
}

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

static err_t rngTRNGRead(void* buf, size_t* read, size_t count)
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

static err_t rngTRNG2Read(void* buf, size_t* read, size_t count)
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

static err_t rngSysRead(void* buf, size_t* read, size_t count)
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

static err_t rngSys2Read(void* buf, size_t* read, size_t count)
{
	// pre
	ASSERT(memIsValid(read, O_PER_S));
	ASSERT(memIsValid(buf, count));
	ASSERT((size_t)(ULONG)count == count);
	// получить случайные данные
	*read = 0;
	if (!RtlGenRandom((octet*)buf, (ULONG)count))
		return ERR_BAD_ENTROPY;
	// завершение
	*read = count;
	return ERR_OK;
}

#elif defined OS_UNIX

#include <stdio.h>
#include <dlfcn.h>

static err_t rngSysRead(void* buf, size_t* read, size_t count)
{
	file_t file;
	ASSERT(memIsValid(read, sizeof(size_t)));
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

static err_t rngSys2Read(void* buf, size_t* read, size_t count)
{
	const char* names[] = {
		"libcrypto.so", "libcrypto.so.3", "libcrypto.so.1.1",
		"libcrypto.so.1.1.1" };
	size_t pos;
	void* lib;
	int(*rand_bytes)(octet*, int) = 0;
	// pre
	ASSERT(memIsValid(read, sizeof(size_t)));
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

#else

static err_t rngSys2Read(void* buf, size_t* read, size_t count)
{
	ASSERT(memIsValid(read, sizeof(size_t)));
	ASSERT(memIsValid(buf, count));
	return ERR_FILE_NOT_FOUND;
}

#endif

#else

static err_t rngSysRead(void* buf, size_t* read, size_t count)
{
	ASSERT(memIsValid(read, sizeof(size_t)));
	ASSERT(memIsValid(buf, count));
	return ERR_FILE_NOT_FOUND;
}

static err_t rngSys2Read(void* buf, size_t* read, size_t count)
{
	ASSERT(memIsValid(read, sizeof(size_t)));
	ASSERT(memIsValid(buf, count));
	return ERR_FILE_NOT_FOUND;
}

#endif

/*
*******************************************************************************
Таймер-счетчик

Таймер-счетчик может использоваться вместо стандартного таймера, если частота
обновления последнего недостаточно высока. Таймер-счетчик -- это отдельный 
поток, в котором выполняется исключительно инкремент счетчика. Частота 
обновления счетчика проверяется при создании таймера. Таймер не создается,
если частота обновления ниже 10^8 раз в секунду (100 МГц).

\remark Синхронизация не нужна, поскольку функции таймера-счетчика вызываются
только в сихнронизированных участках кода.

\thanks Подсмотрено в https://github.com/smuellerDD/jitterentropy-library.
*******************************************************************************
*/

static volatile bool_t _tm_ctr_loop;		/*< счетчик запущен? */
static volatile tm_ticks_t _tm_ctr_ticks;	/*< текущее показание */

#ifdef OS_WIN

static DWORD tmCtrLoop(void* args)
{
	while (_tm_ctr_loop)
		_tm_ctr_ticks++;
	return 0;
}

static HANDLE _tm_ctr_tid;

static bool_t tmCtrCreate()
{
	if (_tm_ctr_loop)
		return TRUE;
	_tm_ctr_loop = TRUE;
	_tm_ctr_tid = CreateThread(0, 0, tmCtrLoop, 0, 0, 0);
	if (!_tm_ctr_tid)
		return _tm_ctr_loop = FALSE;
	return TRUE;
}

static void tmCtrClose()
{
	if (_tm_ctr_loop)
	{
		_tm_ctr_loop = FALSE;
		(void)WaitForSingleObject(_tm_ctr_tid, INFINITE);
		(void)CloseHandle(_tm_ctr_tid);
		_tm_ctr_ticks = 0;
		_tm_ctr_tid = 0;
	}		
}

#elif defined OS_UNIX

static void* tmCtrLoop(void* args)
{
	while (_tm_ctr_loop)
		 _tm_ctr_ticks++;
	return 0;
}

pthread_t _tm_ctr_tid;

static bool_t tmCtrCreate()
{
	if (_tm_ctr_loop)
		return TRUE;
	_tm_ctr_loop = TRUE;
	if (pthread_create(&_tm_ctr_tid, 0, tmCtrLoop, 0) != 0)
	if (!_tm_ctr_tid)
		return _tm_ctr_loop = FALSE;
	return TRUE;
}

static void tmCtrClose()
{
	if (_tm_ctr_loop)
	{
		_tm_ctr_loop = FALSE;
		(void)pthread_join(_tm_ctr_tid, 0);
		_tm_ctr_ticks = 0;
		_tm_ctr_tid = 0;
	}		
}

#else

static bool_t tmCtrCreate()
{
	return FALSE;
}

static void tmCtrClose()
{
}

#endif

static bool_t tmCtrIsValid()
{
	return _tm_ctr_loop;
}

static tm_ticks_t tmCtrTicks()
{
	return _tm_ctr_ticks;
}

static bool_t tmCtrStart()
{
	tm_ticks_t start;
	tm_ticks_t overhead;
	tm_ticks_t freq;
	// таймер уже создан?
	if (tmCtrIsValid())
		return TRUE;
	// создать
	if (!tmCtrCreate())
		return FALSE;
	// оценить частоту
	start = tmCtrTicks();
	overhead = tmCtrTicks() - start;
	start = tmCtrTicks();
	mtSleep(100);
	freq = tmCtrTicks();
	freq = (freq - start - overhead) * 10;
	// проверить частоту
	if (freq < 100000000u)
	{
		tmCtrClose();
		return FALSE;
	}
	// зарегистрировать закрытие
	if (!utilOnExit(tmCtrClose))
	{
		tmCtrClose();
		return FALSE;
	}

	return TRUE;
}

/*
*******************************************************************************
Источник-таймер

Реализовано предложение [Jessie Walker, Seeding Random Number Generator]:
наблюдением является разность между показаниями высокоточного таймера
(регистра RDTSC) при приостановке потока на 0 мс, т.е. при передаче
управления ядру.

Оценка энтропии при использовании RDTSC [Jessie Walker]:
4.9 битов / наблюдение.

Реализация:
-	таймер может быть источником случайности, если он обновляется не реже
	10^9 раз в секунду (1 ГГц);
-	если частота обновления таймера ниже разрешенной, то вместо него может 
	использоваться таймер-счетчик с частотой обновления не ниже 10^8 раз 
	в секунду (100 MГц). Снижение порога частоты мотивируется тем, что 
	таймер-счетчик по принципу своей работы привносит случайные флуктуации 
	промежутков времени между отсчетами; 
-	для формирования одного выходного бита используется сумма битов четности
	8-ми разностей между показаниями таймера.

\warning Качество источника зависит от организации ядра. Эксперименты
показывают, что в Linux качество выше, чем в Windows. Указанное выше число
8 выбрано экспериментальным путем -- проводилась оценка энтропии на выборках
объема 1 Мб. Эксперименты показывают, что для некоторых версий Windows
статистическое качество выборок катастрофически плохое. К источнику следует
относиться с большой осторожностью, использовать его как вспомогательный.

\warning [Jessie Walker]: наблюдения зависимы, модель AR(1).

\todo Остановка на Windows, если параллельно запущено несколько ресурсоемких
процессов.
*******************************************************************************
*/

static bool_t rngTimerIsAvail()
{
	return //tmFreq() >= 1000000000u || 
		tmCtrStart();
}

static err_t rngTimerRead(void* buf, size_t* read, size_t count)
{
	register tm_ticks_t ticks;
	register tm_ticks_t t;
	register word w;
	size_t i, j, reps;
	// pre
	ASSERT(memIsValid(read, sizeof(size_t)));
	ASSERT(memIsValid(buf, count));
	// есть источник?
	if (!rngTimerIsAvail())
		return ERR_FILE_NOT_FOUND;
	// генерация
	for (i = 0; i < count; ++i)
	{
		((octet*)buf)[i] = 0;
		ticks = tmTicks();
		for (j = 0; j < 8; ++j)
		{
			w = 0;
			for (reps = 0; reps < 8; ++reps)
			{
				mtSleep(0);
				t = tmCtrIsValid() ? tmCtrTicks() : tmTicks();
				w ^= (word)(t - ticks);
				ticks = t;
			}
			((octet*)buf)[i] ^= wordParity(w) << j;
		}
	}
	CLEAN3(ticks, t, w);
	*read = count;
	return ERR_OK;
}

/*
*******************************************************************************
Источники случайности (энтропии)
*******************************************************************************
*/

err_t rngESRead(size_t* read, void* buf, size_t count, const char* source)
{
	if (strEq(source, "trng"))
		return rngTRNGRead(buf, read, count);
	else if (strEq(source, "trng2"))
		return rngTRNG2Read(buf, read, count);
	else if (strEq(source, "timer"))
		return rngTimerRead(buf, read, count);
	else if (strEq(source, "sys"))
		return rngSysRead(buf, read, count);
	else if (strEq(source, "sys2"))
		return rngSys2Read(buf, read, count);
	return ERR_FILE_NOT_FOUND;
}

err_t rngESTest(const char* source)
{
	err_t code;
	octet buf[2500];
	size_t read;
	// прочитать данные от источника
	code = rngESRead(&read, buf, 2500, source);
	if (code == ERR_OK && read != 2500)
		code = ERR_FILE_READ;
	ERR_CALL_CHECK(code);
	// статистическое тестирование
	if (!rngTestFIPS1(buf) || !rngTestFIPS2(buf) || !rngTestFIPS3(buf) ||
		!rngTestFIPS4(buf))
		code = ERR_STATTEST;
	// завершение
	memWipe(buf, sizeof(buf));
	return code;
}

err_t rngESHealth2()
{
	const char* sources[] = { "trng", "trng2" };
	size_t pos;
	// проверить физические источники
	for (pos = 0; pos < COUNT_OF(sources); ++pos)
		if (rngESTest(sources[pos]) == ERR_OK)
			return ERR_OK;
	// работоспособные источники не найдены
	return ERR_NOT_ENOUGH_ENTROPY;
}

err_t rngESHealth()
{
	const char* sources[] = { "sys", "sys2", "timer" };
	size_t valid_sources = 0;
	size_t pos;
	// есть работоспособный физический источник?
	if (rngESHealth2() == ERR_OK)
		return ERR_OK;
	// проверить остальные источники
	for (pos = 0; pos < COUNT_OF(sources); ++pos)
	{
		if (rngESTest(sources[pos]) != ERR_OK)
			continue;
		// два работоспособных источника?
		if (++valid_sources == 2)
			return ERR_OK;
	}
	// только один?
	if (valid_sources == 1)
		return ERR_NOT_ENOUGH_ENTROPY;
	// ни одного
	return ERR_BAD_ENTROPY;
}

/*
*******************************************************************************
Создание / закрытие генератора

\warning CoverityScan выдает предупреждение по функции rngCreate(): 
	"Call to rngESRead might sleep while holding lock _mtx".
См. пояснения в комментариях к функции rngStepR().

\warning Функция rngDestroy(), зарегистрированная как деструктор,
не обязательно будет вызвана позже rngClose(). Например, rngClose()
может вызываться в другом зарегистрированном деструкторе, который следует
за rngDestroy().
*******************************************************************************
*/

typedef struct 
{
	octet block[32];			/*< дополнительные данные brngCTR */
	mem_align_t alg_state[];	/*< [MAX(beltHash_keep(), brngCTR_keep())] */
} rng_state_st;

static size_t _once;			/*< триггер однократности */
static mt_mtx_t _mtx[1];		/*< мьютекс */
static bool_t _inited;			/*< мьютекс создан? */
static size_t _ctr;				/*< счетчик обращений */
static rng_state_st* _state;	/*< состояние */

size_t rngCreate_keep()
{
	return sizeof(rng_state_st) + MAX2(beltHash_keep(), brngCTR_keep());
}

static void rngDestroy()
{
	// закрыть состояние (могли забыть)
	mtMtxLock(_mtx);
	blobClose(_state), _state = 0, _ctr = 0;
	mtMtxUnlock(_mtx);
	// закрыть мьютекс
	mtMtxClose(_mtx);
}

static void rngInit()
{
	ASSERT(!_inited);
	// создать мьютекс
	if (!mtMtxCreate(_mtx))
		return;
	// зарегистрировать деструктор
	if (!utilOnExit(rngDestroy))
	{
		mtMtxClose(_mtx);
		return;
	}
	_inited = TRUE;
}

err_t rngCreate(read_i source, void* source_state)
{
	const char* sources[] = { "trng", "trng2", "sys", "timer" };
	size_t read, count, pos;
	// инициализировать однократно
	if (!mtCallOnce(&_once, rngInit) || !_inited)
		return ERR_FILE_CREATE;
	// заблокировать мьютекс
	mtMtxLock(_mtx);
	// состояние уже создано?
	if (_ctr)
	{
		// учесть дополнительный источник
		if (source && source(&read, _state->block, 32, source_state) == ERR_OK)
			brngCTRStepR(_state->block, 32, _state->alg_state);
		// увеличить счетчик обращений и завершить
		++_ctr;
		mtMtxUnlock(_mtx);
		return ERR_OK;
	}
	// создать состояние
	_state = (rng_state_st*)blobCreate(rngCreate_keep());
	if (!_state)
	{
		mtMtxUnlock(_mtx);
		return ERR_OUTOFMEMORY;
	}
	// опрос источников случайности
	count = 0;
	beltHashStart(_state->alg_state);
	for (pos = 0; pos < COUNT_OF(sources); ++pos)
		if (rngESRead(&read, _state->block, 32, sources[pos]) == ERR_OK)
		{
			beltHashStepH(_state->block, read, _state->alg_state);
			count += read;
		}
	if (source && source(&read, _state->block, 32, source_state) == ERR_OK)
	{
		beltHashStepH(_state->block, read, _state->alg_state);
		count += read;
	}
	if (count < 32)
	{
		blobClose(_state), _state = 0;
		mtMtxUnlock(_mtx);
		return ERR_NOT_ENOUGH_ENTROPY;
	}
	// создать brngCTR
	beltHashStepG(_state->block, _state->alg_state);
	memWipe(_state->alg_state, beltHash_keep());
	brngCTRStart(_state->alg_state, _state->block, 0);
	memWipe(_state->block, 32);
	// завершить
	_ctr = 1;
	mtMtxUnlock(_mtx);
	return ERR_OK;
}

static bool_t rngIsValid_internal()
{
	return _ctr && _state && blobIsValid(_state);
}

bool_t rngIsValid()
{
	bool_t b;
	if (!_inited)
		return FALSE;
	mtMtxLock(_mtx);
	b = rngIsValid_internal();
	mtMtxUnlock(_mtx);
	return b;
}

void rngClose()
{
	ASSERT(_inited);
	mtMtxLock(_mtx);
	ASSERT(rngIsValid_internal());
	if (--_ctr == 0)
		blobClose(_state), _state = 0;
	mtMtxUnlock(_mtx);
}

/*
*******************************************************************************
Генерация

\warning CoverityScan выдает предупреждение по функции rngStepR(): 
	"Call to RngESRead might sleep while holding lock _mtx"
с объяснениями: 
	"The lock will prevent other threads from making progress for 
	an indefinite period of time; may be mistaken for deadlock. In rngStepR: 
	A lock is held while waiting for a long running or blocking operation 
	to complete (CWE-667)".
Проблема в том, что в источнике timer многократно вызывается функция
mtSleep(0).
*******************************************************************************
*/

void rngStepR2(void* buf, size_t count, void* state)
{
	ASSERT(_inited);
	mtMtxLock(_mtx);
	ASSERT(rngIsValid_internal());
	brngCTRStepR(buf, count, _state->alg_state);
	mtMtxUnlock(_mtx);
}

void rngStepR(void* buf, size_t count, void* state)
{
	const char* sources[] = {"trng", "trng2", "sys", "sys2", "timer"};
	size_t read, r, pos;
	// блокировать мьютекс
	ASSERT(_inited);
	mtMtxLock(_mtx);
	// опросить источники
	read = pos = 0;
	while (read < count && pos < COUNT_OF(sources))
	{
		if (rngESRead(&r, (octet*)buf + read, count - read,
				sources[pos]) != ERR_OK)
			r = 0;
		read += r, ++pos;
	}
	CLEAN3(read, r, pos);
	// генерация
	ASSERT(rngIsValid_internal());
	brngCTRStepR(buf, count, _state->alg_state);
	// снять блокировку
	mtMtxUnlock(_mtx);
}

void rngRekey()
{
	// блокировать мьютекс
	ASSERT(_inited);
	mtMtxLock(_mtx);
	// сгенерировать новый ключ
	ASSERT(rngIsValid_internal());
	brngCTRStepR(_state->block, 32, _state->alg_state);
	// пересоздать brngCTR
	brngCTRStart(_state->alg_state, _state->block, 0);
	memWipe(_state->block, 32);
	// снять блокировку
	mtMtxUnlock(_mtx);
}
