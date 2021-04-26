/*
*******************************************************************************
\file rng.c
\brief Entropy sources and random number generators
\project bee2 [cryptographic library]
\author Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2014.10.13
\version 2021.04.27
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/blob.h"
#include "bee2/core/err.h"
#include "bee2/core/mem.h"
#include "bee2/core/mt.h"
#include "bee2/core/obj.h"
#include "bee2/core/str.h"
#include "bee2/core/tm.h"
#include "bee2/core/rng.h"
#include "bee2/core/u32.h"
#include "bee2/core/util.h"
#include "bee2/core/word.h"
#include "bee2/crypto/belt.h"
#include "bee2/crypto/brng.h"
#include "bee2/math/ww.h"

/*
*******************************************************************************
Физический источник

Поддержан ГСЧ Intel

Реализация:
-	по материалам https://software.intel.com/en-us/articles/
	intel-digital-random-number-generator-drng-software-implementation-guide.

Используется инструкция rdseed -- без криптографической постобработки, т.е.
прямая работа с источником случайности.

\remark Альтернативная команда: rdrand -- с криптографической постобработкой.
Прошлые версии gcc не поддерживали rdseed и требовалось переходить на rdseed.
С текушими версиями проблем не возникает.

\remark Для переключения на rdrand нужно:
-	_rdseed32_step заменить на _rdrand32_step;
-	rdrand_eax заменить на rdrand_eax;
-	в rngHasTRNG() вместо
	\code
		// rdseed?
		rngCPUID(info, 7);
		return (info[1] & 0x00040000) != 0;
	\encode
	писать
	\code
		// rdrand?
		rngCPUID(info, 1);
		return (info[2] & 0x40000000) != 0;
	\encode
*******************************************************************************
*/

#if	(_MSC_VER >= 1600) && (defined(_M_IX86) || defined(_M_X64))

#include <intrin.h>
#include <immintrin.h>

#define rngCPUID(info, id) __cpuid((int*)info, id)
#define rngRDStep(val) _rdseed32_step(val)

#elif defined(_MSC_VER) && defined(_M_IX86)

#pragma intrinsic(__cpuid)

#define rngCPUID(info, id) __cpuid((int*)info, id)

#define rdrand_eax	__asm _emit 0x0F __asm _emit 0xC7 __asm _emit 0xF0
#define rdseed_eax	__asm _emit 0x0F __asm _emit 0xC7 __asm _emit 0xF8

static int rngRDStep(u32* val)
{
	__asm {
		xor eax, eax
		xor edx, edx
		rdseed_eax
		jnc err
		mov edx, val
		mov[edx], eax
	}
	return 1;
err:
	return 0;
}

#elif defined(__GNUC__) && (defined(__i386__) || defined(__x86_64__))

#include <cpuid.h>

#define rngCPUID(info, id) __cpuid(id, info[0], info[1], info[2], info[3])

static int rngRDStep(u32* val)
{
	octet ok;
	asm volatile("rdrand %0; setc %1" : "=r" (*val), "=qm" (ok));
	return ok;
}

#else

#define rngCPUID(info, id) memSetZero(info, 16)
#define rngRDStep(val) 0

#endif

static bool_t rngHasTRNG()
{
	u32 info[4];
	// Intel?
	rngCPUID(info, 0);
	if (!memEq(info + 1, "Genu", 4) ||
		!memEq(info + 3, "ineI", 4) ||
		!memEq(info + 2, "ntel", 4))
		return FALSE;
	/* rdseed? */
	rngCPUID(info, 7);
	return (info[1] & 0x00040000) != 0;
}

static err_t rngReadTRNG(void* buf, size_t* read, size_t count)
{
	u32* rand = (u32*)buf;
	// pre
	ASSERT(memIsValid(read, O_PER_S));
	ASSERT(memIsValid(buf, count));
	// есть источник?
	if (!rngHasTRNG())
		return ERR_FILE_NOT_FOUND;
	// короткий буфер?
	*read = 0;
	if (count < 4)
		return ERR_OK;
	// генерация
	for (; *read + 4 <= count; *read += 4, ++rand)
		if (!rngRDStep(rand))
			return ERR_OK;
	// неполный блок
	if (*read < count)
	{
		rand = (u32*)((octet*)buf + count - 4);
		if (!rngRDStep(rand))
			return ERR_OK;
		*read = count;
	}
	return ERR_OK;
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
	10^9 раз в секунду (1GHz);
-	для формирования одного выходного бита используется сумма битов четности 
	2-x (Linux) или 8-ми (в остальных случаях) разностей между показаниями 
	таймера.

\warning Качество источника зависит от организации ядра. Эксперименты 
показывают, что в Linux качество выше, чем в Windows. Указанные выше числа 
2 и 8 выбраны экспериментальным путем (проверялось соответствие выходных
последовательностей тестам FIPS). 

\warning [Jessie Walker]: наблюдения зависимы, модель AR(1).

\todo Полноценная оценка энтропии.

\todo Остановка на Windows, если параллельно запущено несколько ресурсоемких
процессов.
*******************************************************************************
*/

static bool_t rngHasTimer()
{
#if (B_PER_W == 16)
	return FALSE;
#else
	return tmFreq() >= 1000000000u;
#endif
}

static err_t rngReadTimer(void* buf, size_t* read, size_t count)
{
	register tm_ticks_t ticks;
	size_t i, j;
	// pre
	ASSERT(memIsValid(read, sizeof(size_t)));
	ASSERT(memIsValid(buf, count));
	// есть источник?
	if (!rngHasTimer())
		return ERR_FILE_NOT_FOUND;
	// генерация
	for (i = 0; i < count; ++i)
	{
		ticks = tmTicks();
		mtSleep(0);
		ticks = tmTicks() - ticks;
		((octet*)buf)[i] = wordParity((word)ticks);
#ifdef OS_LINUX
		for (j = 1; j < 16; ++j)
#else
		for (j = 1; j < 64; ++j)
#endif
		{
			mtSleep(0);
			ticks = tmTicks() - ticks;
			((octet*)buf)[i] ^= wordParity((word)ticks) << j % 8;
		}
	}
	ticks = 0;
	*read = count;
	return ERR_OK;
}

/*
*******************************************************************************
Системный источник

Системный источник Windows -- это функция CryptGenRandom() поверх
стандартного криптопровайдера PROV_RSA_FULL. Системный источник Unix -- 
это файл dev/urandom. 

Обсуждение (и критика) источников:
[1]	http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.124.6557
	&rep=rep1&type=pdf
[2]	http://www.wisdom.weizmann.ac.il/~naor/COURSE/PRIVACY/
	pinkas_prg_insecurity.ppt

\remark Файл dev/random -- это, так называемый, блокирующий источник,
который не выдает данные, пока не будет накоплено достаточно энтропии.
Именно этот источник рекомендуется использовать в криптографических 
приложениях. Однако в наших экспериментах чтение из файла dev/random иногда 
выполнялось экстремально долго (возможно это связано с тем, что программы 
запускались под виртуальной машиной). Поэтому было решено использовать файл 
dev/urandom. Это неблокирующий источник, который всегда выдает данные.

\todo http://www.2uo.de/myths-about-urandom/
*******************************************************************************
*/

#if defined OS_WIN

#include <windows.h>
#include <wincrypt.h>

static err_t rngReadSys(void* buf, size_t* read, size_t count)
{
	HCRYPTPROV hprov = 0;
	// pre
	ASSERT(memIsValid(read, sizeof(size_t)));
	ASSERT(memIsValid(buf, count));
	// открыть провайдер
	if (!CryptAcquireContextW(&hprov, 0, 0, PROV_RSA_FULL, 0))
	{
		*read = 0;
		return ERR_FILE_NOT_FOUND;
	}
	// получить данные
	if (!CryptGenRandom(hprov, (DWORD)count, (octet*)buf))
	{
		*read = 0;
		CryptReleaseContext(hprov, 0);
		return ERR_BAD_RNG;
	}
	// завершение
	CryptReleaseContext(hprov, 0);
	*read = count;
	return ERR_OK;
}

#elif defined OS_UNIX

#include <stdio.h>

static err_t rngReadSys(void* buf, size_t* read, size_t count)
{
	FILE* fp;
	ASSERT(memIsValid(read, sizeof(size_t)));
	ASSERT(memIsValid(buf, count));
	fp = fopen("/dev/urandom", "r");
	if (!fp)
		return ERR_FILE_OPEN;
	*read = fread(buf, 1, count, fp);
	fclose(fp);
	return ERR_OK;
}

#else

static err_t rngReadSys(void* buf, size_t* read, size_t count)
{
	ASSERT(memIsValid(read, sizeof(size_t)));
	ASSERT(memIsValid(buf, count));
	return ERR_FILE_NOT_FOUND;
}

#endif

/*
*******************************************************************************
Статистические тесты

\todo Оценка энтропии.
*******************************************************************************
*/

bool_t rngTestFIPS1(const octet buf[2500])
{
	size_t s = 0;
	size_t count = W_OF_O(2500);
	ASSERT(memIsValid(buf, 2500));
	if (O_OF_W(count) > 2500)
	{
		ASSERT(B_PER_W == 64);
		s = u32Weight(*(const u32*)(buf + 2496));
		--count;
	}
	while (count--)
		s += wordWeight(((const word*)buf)[count]);
	return 9725 < s && s < 10275;
}

bool_t rngTestFIPS2(const octet buf[2500])
{
	u32 s[16];
	size_t i = 2500;
	size_t s1 = 0;
	ASSERT(memIsValid(buf, 2500));
	memSetZero(s, sizeof(s));
	while (i--)
		++s[buf[i] & 15], ++s[buf[i] >> 4];
	for (i = 0; i < 16; ++i)
		s1 += s[i];
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
Сбор энтропии
*******************************************************************************
*/

err_t rngReadSource(void* buf, size_t* read, size_t count,
	const char* source_name)
{
	if (strEq(source_name, "trng"))
		return rngReadTRNG(buf, read, count);
	else if (strEq(source_name, "timer"))
		return rngReadTimer(buf, read, count);
	else if (strEq(source_name, "sys"))
		return rngReadSys(buf, read, count);
	return ERR_FILE_NOT_FOUND;
}

/*
*******************************************************************************
Создание / закрытие генератора

\warning CoverityScan выдает предупреждение по функции rngCreate(): 
	"Call to RngReadSource might sleep while holding lock _mtx".
См. пояснения в комментариях к функции rngStepR().
*******************************************************************************
*/

typedef struct 
{
	octet block[32];			/*< дополнительные данные brngCTR */
	octet alg_state[];			/*< [MAX(beltHash_keep(), brngCTR_keep())] */
} rng_state_st;

static size_t _lock;			/*< счетчик блокировок */
static mt_mtx_t _mtx[1];		/*< мьютекс */
static rng_state_st* _state;	/*< состояние */

size_t rngCreate_keep()
{
	return sizeof(rng_state_st) + MAX2(beltHash_keep(), brngCTR_keep());
}

err_t rngCreate(read_i source, void* source_state)
{
	size_t read;
	size_t count;
	// уже создан?
	if (_lock)
	{
		++_lock;
		return ERR_OK;
	}
	// создать мьютекс и заблокировать его
	if (!mtMtxCreate(_mtx))
		return ERR_FILE_CREATE;
	mtMtxLock(_mtx);
	// создать состояние
	_state = (rng_state_st*)blobCreate(rngCreate_keep());
	if (!_state)
	{
		mtMtxUnlock(_mtx);
		mtMtxClose(_mtx);
		return ERR_OUTOFMEMORY;
	}
	// опрос источников случайности
	count = 0;
	beltHashStart(_state->alg_state);
	if (rngReadSource(_state->block, &read, 32, "trng") == ERR_OK)
	{
		beltHashStepH(_state->block, read, _state->alg_state);
		count += read;
	}
	if (rngReadSource(_state->block, &read, 32, "timer") == ERR_OK)
	{
		beltHashStepH(_state->block, read, _state->alg_state);
		count += read;
	}
	if (rngReadSource(_state->block, &read, 32, "sys") == ERR_OK)
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
		blobClose(_state);
		mtMtxUnlock(_mtx);
		mtMtxClose(_mtx);
		return ERR_BAD_ENTROPY;
	}
	// создать brngCTR
	beltHashStepG(_state->block, _state->alg_state);
	brngCTRStart(_state->alg_state, _state->block, 0);
	memSetZero(_state->block, 32);
	// завершение
	_lock = 1;
	mtMtxUnlock(_mtx);
	return ERR_OK;
}

bool_t rngIsValid()
{
	return _lock > 0 && mtMtxIsValid(_mtx) && blobIsValid(_state);
}

void rngClose()
{
	ASSERT(rngIsValid());
	mtMtxLock(_mtx);
	if (--_lock == 0)
	{
		blobClose(_state);
		mtMtxUnlock(_mtx);
		mtMtxClose(_mtx);
	}
	else
		mtMtxUnlock(_mtx);
}

/*
*******************************************************************************
Генерация

\warning CoverityScan выдает предупреждение по функции rngStepR(): 
	"Call to RngReadSource might sleep while holding lock _mtx"
с объяснениями: 
	"The lock will prevent other threads from making progress for 
	an indefinite period of time; may be mistaken for deadlock. In rngStepR: 
	A lock is held while waiting for a long running or blocking operation 
	to complete (CWE-667)".
Проблема в том, что в источнике timer многократно вызывается 
функция mtSleep(0).
*******************************************************************************
*/

void rngStepR2(void* buf, size_t count, void* state)
{
	ASSERT(rngIsValid());
	mtMtxLock(_mtx);
	brngCTRStepR(buf, count, _state->alg_state);
	mtMtxUnlock(_mtx);
}

void rngStepR(void* buf, size_t count, void* state)
{
	octet* buf1;
	size_t read, t;
	ASSERT(rngIsValid());
	// блокировать генератор
	mtMtxLock(_mtx);
	// опросить trng
	if (rngReadSource(buf, &read, count, "trng") != ERR_OK)
		read = 0;
	// опросить timer
	if (read < count)
	{
		buf1 = (octet*)buf + read;
		if (rngReadSource(buf1, &t, count - read, "timer") != ERR_OK)
			t = 0;
		read += t;
	}
	// опросить sys
	if (read < count)
	{
		buf1 = (octet*)buf + read;
		// проверка возврата снимает претензии сканеров
		if (rngReadSource(buf1, &t, count - read, "sys") != ERR_OK)
			t = 0;
		read += t;
	}
	// генерация
	brngCTRStepR(buf, count, _state->alg_state);
	read = t = 0, buf1 = 0;
	// снять блокировку
	mtMtxUnlock(_mtx);
}
