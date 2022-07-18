/*
*******************************************************************************
\file tm.c
\brief Time and timers
\project bee2 [cryptographic library]
\created 2012.05.10
\version 2022.07.18
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/mem.h"
#include "bee2/core/mt.h"
#include "bee2/core/tm.h"
#include "bee2/core/util.h"

/*
*******************************************************************************
Таймер

\todo Протестировать все возможности.

\todo Определять частоту без временной задержки.
*******************************************************************************
*/

#if defined(_MSC_VER)

#if defined(_M_IX86) || defined (_M_IA64) || defined (_M_X64)

#pragma intrinsic(__rdtsc)
tm_ticks_t tmTicks()
{
	return (tm_ticks_t)__rdtsc();
}

tm_ticks_t tmFreq()
{
	static tm_ticks_t freq = 0;
	if (freq == 0)
	{
		tm_ticks_t start = tmTicks();
		tm_ticks_t overhead = tmTicks() - start;
		start = tmTicks();
		Sleep(100);
		freq = tmTicks() - start - overhead;
		freq *= 10;
	}
	return freq;
}

#else

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

#endif

#elif defined(__GNUC__)

#if defined(__i386__) || defined(__x86_64__)

#if defined(__i386__) || (B_PER_W == 16)

tm_ticks_t tmTicks()
{
	register tm_ticks_t x;
	__asm__ volatile (".byte 0x0f, 0x31" : "=A" (x));
	return x;
}

#else

tm_ticks_t tmTicks()
{
	register u32 hi;
	register u32 lo;
	__asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
	return (tm_ticks_t)lo | (tm_ticks_t)hi << 32;
}

#endif

tm_ticks_t tmFreq()
{
	static tm_ticks_t freq = 0;
	if (freq == 0)
	{
		struct timespec ts;
		tm_ticks_t start;
		tm_ticks_t overhead;
		ts.tv_sec = 0, ts.tv_nsec = 100000000;
		start = tmTicks();
		overhead = tmTicks() - start;
		nanosleep(&ts, 0);
		freq = tmTicks() - start - overhead;
		freq *= 10;
	}
	return freq;
}

#elif (B_PER_W > 16)

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

#if defined(_MSC_VER)
#define localtime_r(et, lt) (localtime_s(lt, et) ? 0 : lt)
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
