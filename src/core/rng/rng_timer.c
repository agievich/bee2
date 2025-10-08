/*
*******************************************************************************
\file rng_timer.c
\brief Random number generation: entropy sources based on timers
\project bee2 [cryptographic library]
\created 2014.10.13
\version 2025.10.08
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/core/err.h"
#include "bee2/core/mem.h"
#include "bee2/core/mt.h"
#include "bee2/core/tm.h"
#include "bee2/core/util.h"
#include "bee2/core/word.h"

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
	return tmFreq() >= 1000000000u;
}

err_t rngTimerRead(void* buf, size_t* read, size_t count)
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
				t = tmTicks();
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
static volatile tm_ticks_t _tm_ctr_ticks2;	/*< предыдущее показание */

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
		_tm_ctr_ticks = _tm_ctr_ticks2 = 0;
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
		_tm_ctr_ticks = _tm_ctr_ticks2 = 0;
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
	ASSERT(tmCtrIsValid());
	while (_tm_ctr_ticks == _tm_ctr_ticks2);
	return _tm_ctr_ticks2 = _tm_ctr_ticks;
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

static bool_t rngJitterIsAvail()
{
	return tmCtrStart();
}

static void rngJitterSleep()
{
}

err_t rngJitterRead(void* buf, size_t* read, size_t count)
{
	register tm_ticks_t ticks;
	register tm_ticks_t t;
	register word w;
	size_t i, j, reps;
	// pre
	ASSERT(memIsValid(read, sizeof(size_t)));
	ASSERT(memIsValid(buf, count));
	// есть источник?
	if (!rngJitterIsAvail())
		return ERR_FILE_NOT_FOUND;
	// генерация
	ticks = tmCtrTicks();
	for (i = 0; i < count; ++i)
	{
		((octet*)buf)[i] = 0;
		for (j = 0; j < 8; ++j)
		{
			w = 0;
			for (reps = 0; reps < 8; ++reps)
			{
				rngJitterSleep();
				t = tmCtrTicks();
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
