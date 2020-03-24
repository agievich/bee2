/*
*******************************************************************************
\file tm.c
\brief Time and timers
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2012.05.10
\version 2015.11.25
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/mem.h"
#include "bee2/core/mt.h"
#include "bee2/core/tm.h"

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
