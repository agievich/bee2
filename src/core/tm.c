/*
*******************************************************************************
\file tm.c
\brief Time and timers
\project bee2 [cryptographic library]
\created 2012.05.10
\version 2023.04.13
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/core/mem.h"
#include "bee2/core/mt.h"
#include "bee2/core/tm.h"
#include "bee2/core/util.h"

/*
*******************************************************************************
Таймер

\remark Функция mach_timebase_info() "returns fraction to multiply a value
in mach tick units with to convert it to nanoseconds". Можно понять, что
1 tick * fraction = 1 ns. На самом деле, 1 tick = fraction * 1 ns.

\todo Протестировать все возможности.
\todo Определять частоту без временной задержки.
*******************************************************************************
*/

#if defined(_M_IX86) || defined (_M_IA64) || defined (_M_X64) || \
	defined(__i386__) || defined(__x86_64__)

#if defined(_MSC_VER)

#pragma intrinsic(__rdtsc)

tm_ticks_t tmTicks()
{
	return (tm_ticks_t)__rdtsc();
}

#elif defined(__GNUC__) || defined(__clang__)

#include <x86intrin.h>

tm_ticks_t tmTicks()
{
	return (tm_ticks_t)_rdtsc();
}

#endif

static tm_ticks_t _freq;

static void tmCalcFreq()
{
	tm_ticks_t start;
	tm_ticks_t overhead;
	start = tmTicks();
	overhead = tmTicks() - start;
	start = tmTicks();
	mtSleep(100);
	_freq = tmTicks();
	_freq = (_freq - start - overhead) * 10;
}

static size_t _once;

tm_ticks_t tmFreq()
{
	return mtCallOnce(&_once, tmCalcFreq) ? _freq : 0;
}

#elif defined(OS_WIN)

#include <windows.h>

tm_ticks_t tmTicks()
{
	LARGE_INTEGER ctr;
	if (QueryPerformanceCounter(&ctr))
		return (tm_ticks_t)ctr.QuadPart;
	return (tm_ticks_t)clock();
}

tm_ticks_t tmFreq()
{
	LARGE_INTEGER freq;
	if (QueryPerformanceFrequency(&freq))
		return (tm_ticks_t)freq.QuadPart;
	return (tm_ticks_t)CLOCKS_PER_SEC;
}

#elif defined(OS_APPLE) && defined(U64_SUPPORT)

#include <mach/mach_time.h>

tm_ticks_t tmTicks()
{
    return mach_absolute_time();
}

tm_ticks_t tmFreq()
{
    mach_timebase_info_data_t tb_info;
    tm_ticks_t freq = 1000000000u;
	// tb_info <- {numer, denom}: 1 tick = numer / denom * 1 ns
	VERIFY(mach_timebase_info(&tb_info) == KERN_SUCCESS);
	// 1 s = 10^9 * denom / numer ticks
	freq *= tb_info.denom, freq /= tb_info.numer;
    return freq;
}

#elif defined(U64_SUPPORT)

tm_ticks_t tmTicks()
{
	struct timespec ts;
	tm_ticks_t ticks;
	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		return 0;
	ticks = (tm_ticks_t)ts.tv_sec;
	ticks *= 1000000000u;
	ticks += (tm_ticks_t)ts.tv_nsec;
	return ticks;
}

tm_ticks_t tmFreq()
{
	struct timespec ts;
	tm_ticks_t freq;
	if (clock_getres(CLOCK_MONOTONIC, &ts) || ts.tv_sec || !ts.tv_nsec)
		return 0;
	freq = 1000000000u;
	freq /= (tm_ticks_t)ts.tv_nsec;
	return freq;
}

#else

tm_ticks_t tmTicks()
{
	return (tm_ticks_t)clock();
}

tm_ticks_t tmFreq()
{
	return (tm_ticks_t)CLOCKS_PER_SEC;
}

#endif

size_t tmSpeed(size_t reps, tm_ticks_t ticks)
{
	return ticks ? (size_t)((dword)reps * tmFreq() / ticks) : SIZE_MAX;
}

/*
*******************************************************************************
Время

\todo Гарантировать 64-битовый счетчик.
\todo Поддержать представление времени в формате ISO 8601.
*******************************************************************************
*/

tm_time_t tmTime()
{
	return time(0);
}

tm_time_t tmTimeRound(tm_time_t t0, tm_time_t ts)
{
	register tm_time_t t = tmTime();
	if (ts == 0 || t < t0)
		return TIME_ERR;
	t = (t - t0) / ts;
	return t;
}

/*
*******************************************************************************
Дата
*******************************************************************************
*/

#if defined(OS_WIN)

static struct tm* localtime_r(const time_t* timep, struct tm* result)
{
	return localtime_s(result, timep) ? 0 : result;
}

#endif

bool_t tmDate(size_t* y, size_t* m, size_t* d)
{
	struct tm lt;
	time_t et;
	// входной контроль
	ASSERT(memIsNullOrValid(y, O_PER_S));
	ASSERT(memIsNullOrValid(m, O_PER_S));
	ASSERT(memIsNullOrValid(d, O_PER_S));
	// получить отметку времени
	if (time(&et) == -1 || !localtime_r(&et, &lt))
		return FALSE;
	// возвратить данные
	if (y)
		*y = (size_t)lt.tm_year, *y += 1900;
	if (m)
		*m = (size_t)lt.tm_mon + 1;
	if (d)
		*d = (size_t)lt.tm_mday;
	return TRUE;
}

bool_t tmDate2(octet date[6])
{
	size_t y;
	size_t m;
	size_t d;
	ASSERT(memIsValid(date, 6));
	// получить дату
	if (!tmDate(&y, &m, &d))
		return FALSE;
	// преобразовать дату
	if (y < 2000 || y > 2099)
		return FALSE;
	y -= 2000;
	date[0] = (octet)(y / 10), date[1] = (octet)(y % 10);
	date[2] = (octet)(m / 10), date[3] = (octet)(m % 10);
	date[4] = (octet)(d / 10), date[5] = (octet)(d % 10);
	return TRUE;
}

#define yearIsSlope(y) ((y) % 400 == 0 || (y) % 4 == 0 && (y) % 100)

bool_t tmDateIsValid(size_t y, size_t m, size_t d)
{
	return 1583 <= y &&
		1 <= m && m <= 12 &&
		1 <= d && d <= 31 &&
		!(d == 31 && (m == 4 || m == 6 || m == 9 || m == 11)) &&
		!(m == 2 && (d > 29 || d == 29 && !yearIsSlope(y)));
}

bool_t tmDateIsValid2(const octet date[6])
{
	return memIsValid(date, 6) && 
		tmDateIsValid(
			(size_t)10 * date[0] + date[1] + 2000,
			(size_t)10 * date[2] + date[3],
			(size_t)10 * date[4] + date[5]);
}
