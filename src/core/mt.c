/*
*******************************************************************************
\file mt.c
\brief Multithreading
\project bee2 [cryptographic library]
\created 2014.10.10
\version 2023.04.13
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/core/mem.h"
#include "bee2/core/mt.h"
#include "bee2/core/blob.h"
#include "bee2/core/str.h"
#include "bee2/core/util.h"

/*
*******************************************************************************
Мьютексы
*******************************************************************************
*/

#ifdef OS_WIN

bool_t mtMtxCreate(mt_mtx_t* mtx)
{
	ASSERT(memIsValid(mtx, sizeof(mt_mtx_t)));
	return InitializeCriticalSectionAndSpinCount(mtx, 0x400);
}

bool_t mtMtxIsValid(const mt_mtx_t* mtx)
{
	return memIsValid(mtx, sizeof(mt_mtx_t));
}

void mtMtxLock(mt_mtx_t* mtx)
{
	ASSERT(mtMtxIsValid(mtx));
	EnterCriticalSection(mtx);
}

void mtMtxUnlock(mt_mtx_t* mtx)
{
	ASSERT(mtMtxIsValid(mtx));
	LeaveCriticalSection(mtx);
}

void mtMtxClose(mt_mtx_t* mtx)
{
	ASSERT(mtMtxIsValid(mtx));
	DeleteCriticalSection(mtx);
}

#elif defined OS_UNIX

bool_t mtMtxCreate(mt_mtx_t* mtx)
{
	ASSERT(memIsValid(mtx, sizeof(mt_mtx_t)));
	return pthread_mutex_init(mtx, 0) == 0;
}

bool_t mtMtxIsValid(const mt_mtx_t* mtx)
{
	return memIsValid(mtx, sizeof(mt_mtx_t));
}

void mtMtxLock(mt_mtx_t* mtx)
{
	ASSERT(mtMtxIsValid(mtx));
	pthread_mutex_lock(mtx);
}

void mtMtxUnlock(mt_mtx_t* mtx)
{
	ASSERT(mtMtxIsValid(mtx));
	pthread_mutex_unlock(mtx);
}

void mtMtxClose(mt_mtx_t* mtx)
{
	ASSERT(mtMtxIsValid(mtx));
	pthread_mutex_destroy(mtx);
}

#else

bool_t mtMtxCreate(mt_mtx_t* mtx)
{
	return TRUE;
}

bool_t mtMtxIsValid(const mt_mtx_t* mtx)
{
	return TRUE;
}

void mtMtxLock(mt_mtx_t* mtx)
{
	ASSERT(mtMtxIsValid(mtx));
}

void mtMtxUnlock(mt_mtx_t* mtx)
{
	ASSERT(mtMtxIsValid(mtx));
}

void mtMtxClose(mt_mtx_t* mtx)
{
	ASSERT(mtMtxIsValid(mtx));
}

#endif // OS

/*
*******************************************************************************
Потоки

\remark Реализация mtCallOnce() выполнена по мотивам Windows-редакции
функции CRYPTO_THREAD_run_once() из OpenSSL 1.1.1. Другие варианты реализации
могут быть основаны на функциях InitOnceExecuteOnce() (WinAPI) и pthread_once()
(<pthread.h>).
*******************************************************************************
*/

#ifdef OS_WIN

void mtSleep(u32 ms)
{
	Sleep(ms);
}

#elif defined OS_UNIX

#include <time.h>

void mtSleep(u32 ms)
{
	struct timespec ts;
	ts.tv_sec = (time_t)ms, ts.tv_sec /= 1000;
	ts.tv_nsec = (long)ms, ts.tv_nsec *= 1000, ts.tv_nsec *= 1000;
	ts.tv_nsec %= 1000000000l;
	nanosleep(&ts, 0);
}

#else

void mtSleep(u32 ms)
{
}

#endif // OS

bool_t mtCallOnce(size_t* once, void (*fn)())
{
	size_t t;
	// попытки вызова
	do
		// удается захватить триггер?...
		if ((t = mtAtomicCmpSwap(once, 0, SIZE_MAX)) == 0)
		{
			// ... да, обработать захват
			fn(), *once = 1;
			break;
		}
	// ... нет, ожидаем обработки захвата в другом потоке
	while (t == SIZE_MAX);
	// завершить
	ASSERT(*once == 1);
	return TRUE;
}

/*
*******************************************************************************
Атомарные операции

Пока не потребовалась функция mtMtxTryLock(). Она отличается от mtMtxLock()
тем, что немедленно блокирует разблокированный мьютекс и не ожидает
разблокировки заблокированного.

Примерный интерфейс:
	\brief Блокировка мьютекса без ожидания

	Мьютекс mtx блокируется, если в момент вызова он не был заблокирован
	в другом потоке.
	\pre Мьютекс корректен.
	\return TRUE, если мьютекс не был заблокирован в другом потоке
	(и стал заблокирован) или уже был заблокирован в текущем потоке,
	и FALSE в противном случае.
	\remark Снятие блокировки мьютекса (в другом потоке) не ожидается.
	bool_t mtMtxTryLock(
		mt_mtx_t* mtx
	);

Реализация mtMtxTryLock() может быть основана на функциях
pthread_mutex_trylock() (<pthread.h>) и TryEnterCriticalSection() (WinAPI).
*******************************************************************************
*/

#ifdef OS_WIN

#if (O_PER_S == 8)

size_t mtAtomicIncr(size_t* ctr)
{
	ASSERT(memIsAligned(ctr, O_PER_S));
	return InterlockedIncrement64((i64 volatile*)ctr);
}

size_t mtAtomicDecr(size_t* ctr)
{
	ASSERT(memIsAligned(ctr, O_PER_S));
	return InterlockedDecrement64((i64 volatile*)ctr);
}

size_t mtAtomicCmpSwap(size_t* ctr, size_t cmp, size_t swap)
{
	ASSERT(memIsAligned(ctr, O_PER_S));
	return InterlockedCompareExchange64((i64 volatile*)ctr,
		(i64)swap, (i64)cmp);
}

#elif (O_PER_S == 4)

size_t mtAtomicIncr(size_t* ctr)
{
	ASSERT(memIsAligned(ctr, O_PER_S));
	return InterlockedIncrement((i32 volatile*)ctr);
}

size_t mtAtomicDecr(size_t* ctr)
{
	ASSERT(memIsAligned(ctr, O_PER_S));
	return InterlockedDecrement((i32 volatile*)ctr);
}

size_t mtAtomicCmpSwap(size_t* ctr, size_t cmp, size_t swap)
{
	ASSERT(memIsAligned(ctr, O_PER_S));
	return InterlockedCompareExchange((i32 volatile*)ctr,
		(i32)swap, (i32)cmp);
}

#elif (O_PER_S == 2)

size_t mtAtomicIncr(size_t* ctr)
{
	ASSERT(memIsAligned(ctr, O_PER_S));
	return InterlockedIncrement16((i16 volatile*)ctr);
}

size_t mtAtomicDecr(size_t* ctr)
{
	ASSERT(memIsAligned(ctr, O_PER_S));
	return InterlockedDecrement16((i16 volatile*)ctr);
}

size_t mtAtomicCmpSwap(size_t* ctr, size_t cmp, size_t swap)
{
	ASSERT(memIsAligned(ctr, O_PER_S));
	return InterlockedCompareExchange16((i16 volatile*)ctr,
		(i16)swap, (i16)cmp);
}

#else

#error "Unsupported size_t"

#endif // O_PER_S

#elif defined OS_UNIX

size_t mtAtomicIncr(size_t* ctr)
{
	return __sync_add_and_fetch(ctr, SIZE_1);
}

size_t mtAtomicDecr(size_t* ctr)
{
	return __sync_sub_and_fetch(ctr, SIZE_1);
}

size_t mtAtomicCmpSwap(size_t* ctr, size_t cmp, size_t swap)
{
	return __sync_val_compare_and_swap(ctr, cmp, swap);
}

#else

size_t mtAtomicIncr(size_t* ctr)
{
	ASSERT(memIsValid(ctr, O_PER_S));
	return ++*ctr;
}

size_t mtAtomicDecr(size_t* ctr)
{
	ASSERT(memIsValid(ctr, O_PER_S));
	return --*ctr;
}

size_t mtAtomicCmpSwap(size_t* ctr, size_t cmp, size_t swap)
{
	register size_t t;
	ASSERT(memIsValid(ctr, O_PER_S));
	*ctr = ((t = *ctr) == cmp) ? swap : t;
	return t;
}

#endif // OS
