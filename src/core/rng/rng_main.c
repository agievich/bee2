/*
*******************************************************************************
\file rng_main.c
\brief Random number generation: collecting entropy and post-processing
\project bee2 [cryptographic library]
\created 2014.10.13
\version 2025.10.08
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/core/blob.h"
#include "bee2/core/err.h"
#include "bee2/core/mem.h"
#include "bee2/core/mt.h"
#include "bee2/core/str.h"
#include "bee2/core/rng.h"
#include "bee2/core/util.h"
#include "bee2/crypto/belt.h"
#include "bee2/crypto/brng.h"

/*
*******************************************************************************
Источники случайности (энтропии)
*******************************************************************************
*/

extern err_t rngTRNGRead(void* buf, size_t* read, size_t count);
extern err_t rngTRNG2Read(void* buf, size_t* read, size_t count);
extern err_t rngTimerRead(void* buf, size_t* read, size_t count);
extern err_t rngJitterRead(void* buf, size_t* read, size_t count);
extern err_t rngSysRead(void* buf, size_t* read, size_t count);
extern err_t rngSys2Read(void* buf, size_t* read, size_t count);

err_t rngESRead(size_t* read, void* buf, size_t count, const char* source)
{
	if (strEq(source, "trng"))
		return rngTRNGRead(buf, read, count);
	else if (strEq(source, "trng2"))
		return rngTRNG2Read(buf, read, count);
	else if (strEq(source, "timer"))
		return rngTimerRead(buf, read, count);
	else if (strEq(source, "jitter"))
		return rngJitterRead(buf, read, count);
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
	const char* sources[] = { "sys", "sys2", "timer", "jitter" };
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
	const char* sources[] = { "trng", "trng2", "sys", "sys2", "timer", "jitter" };
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
	const char* sources[] = {"trng", "trng2", "sys", "sys2", "timer", "jitter"};
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
