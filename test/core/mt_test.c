/*
*******************************************************************************
\file mt_test.c
\brief Tests for multithreading
\project bee2/test
\created 2021.05.15
\version 2021.05.18
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include <bee2/core/mt.h>

/*
*******************************************************************************
Тестирование
*******************************************************************************
*/

static size_t _once;
static bool_t _inited;
void init()
{
	_inited = TRUE;
}

bool_t mtTest()
{
	mt_mtx_t mtx[1];
	size_t ctr[1] = { SIZE_0 };
	// мьютексы
	if (!mtMtxCreate(mtx))
		return FALSE;
	mtMtxLock(mtx);
	mtMtxUnlock(mtx);
	mtMtxClose(mtx);
	// атомарные операции
	mtAtomicIncr(ctr);
	mtAtomicIncr(ctr);
	mtAtomicDecr(ctr);
	if (mtAtomicCmpSwap(ctr, 1, 0) != 1 || *ctr != SIZE_0)
		return FALSE;
	// однократный вызов
	if (!mtCallOnce(&_once, init) || !_inited)
		return FALSE;
	if (!mtCallOnce(&_once, init) || !_inited)
		return FALSE;
	// все нормально
	return TRUE;
}
