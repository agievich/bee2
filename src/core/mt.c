/*
*******************************************************************************
\file mt.c
\brief Multithreading
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2014.10.10
\version 2015.08.27
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/mem.h"
#include "bee2/core/mt.h"
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
	*mtx = CreateMutex(0, FALSE, 0);
	return *mtx != NULL;
}

bool_t mtMtxIsValid(const mt_mtx_t* mtx)
{
	return memIsValid(mtx, sizeof(mt_mtx_t)) && *mtx != NULL;
}

void mtMtxLock(mt_mtx_t* mtx)
{
	ASSERT(mtMtxIsValid(mtx));
	WaitForSingleObject(*mtx, INFINITE);
}

void mtMtxUnlock(mt_mtx_t* mtx)
{
	ASSERT(mtMtxIsValid(mtx));
	ReleaseMutex(*mtx);
}

void mtMtxClose(mt_mtx_t* mtx)
{
	ASSERT(mtMtxIsValid(mtx));
	CloseHandle(*mtx);
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

