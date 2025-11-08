/*
*******************************************************************************
\file rng_timer.c
\brief Random number generation: entropy sources based on timers
\project bee2 [cryptographic library]
\created 2014.10.13
\version 2025.11.08
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/core/err.h"
#include "bee2/core/mem.h"
#include "bee2/core/mt.h"
#include "bee2/core/tm.h"
#include "bee2/core/util.h"
#include "bee2/core/u32.h"
#include "bee2/core/u64.h"
#include "bee2/core/word.h"

/*
*******************************************************************************
Источник-таймер

Реализовано предложение [Jessie Walker, Seeding Random Number Generator]:
наблюдением является разность между показаниями высокоточного таймера
(например, регистра RDTSC) при приостановке потока на 0 мс, т.е. при передаче
управления ядру.

Оценка энтропии при использовании RDTSC [Jessie Walker]:
4.9 битов / наблюдение.

Реализация:
-	таймер может быть источником случайности, если он обновляется не реже
	10^9 раз в секунду (1 ГГц);
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
Таймер-счетчик (экспериментальный)

Таймер-счетчик -- это отдельный поток, в котором выполняется исключительно 
инкремент счетчика. Таймер-счетчик может использоваться вместо стандартного 
в тех случаях, когда разрешающая способность последнего недостаточно высока.

В tmCtrTicks() контролируется несовпадение соседних значений счетчика: текущее 
значение сравнивается с предыдущим, в случае сопадения формируется новое 
значение и сравнение повторяется. Если несовпадение соблюсти не удалось после 
1024 попыток, то счетчик выдает значение 0.

\expect Функции таймера-счетчика вызываются только в сихнронизированных 
участках кода модуля rng_main.c. Дополнительная синхронизация не нужна.
*******************************************************************************
*/

static volatile bool_t _tm_ctr_loop;		/*< счетчик запущен? */
static volatile tm_ticks_t _tm_ctr_ticks;	/*< текущее показание */
static volatile tm_ticks_t _tm_ctr_ticks2;	/*< предыдущее показание */

#ifdef OS_WIN

static DWORD WINAPI tmCtrLoop(void* args)
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
	register size_t reps = SIZE_1 << 20;
	ASSERT(tmCtrIsValid());
	while (reps--)
		if (_tm_ctr_ticks != _tm_ctr_ticks2)
		{
			CLEAN(reps);
			return _tm_ctr_ticks2 = _tm_ctr_ticks;
		}
	return 0;
}

static bool_t tmCtrStart()
{
	// таймер уже создан?
	if (tmCtrIsValid())
		return TRUE;
	// создать
	if (!tmCtrCreate())
		return FALSE;
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
Источник-джиттер (экспериментальный)

Реализована идея работ [1, 2]: наблюдением является разность между показаниями  
таймера-счетчика до и после выполнения определенного набора инструкций 
процессора. Время выполнения набора предположительно флуктуирует.

Реализация:
-	целевой набор инструкций оформлен в виде функции rngJitterSleep();
-	отсчеты времени обрабатываются LFSR с характеристическим многочленом
		f(x) = x^n + x^8 + x^6 + x^5 + x^4 + x^2 + 1,
	где n = 8 * sizeof(tm_ticks_t). Многочлен f(x) является примитивным для
	n in {16, 32, 64, 128}. Преобразование LFSR -- регистра t -- выполняется
	по формуле
		t = (t >> 1) ^ (~((t & 1) - 1) & 0x0175) ^ (t << (n - 1))
	(в соответствии с [1, стр. 155]);
-	LFSR накапливает разности между показаниями таймера: разность складывается 
	с регистром по правилу XOR, после этого выполняется преобразование LFSR;
-	для формирования одного выходного бита используется сумма битов четности
	LFSR после обработки 128-и разностей;
-	после формирования выходного бита LFSR не обнуляется.

[1]	Харин Ю.С., Агиевич С.В. Компьютерный практикум по математическим методам
	защиты информации. Мн.: БГУ, 2001.

\warning Пока функция rngJitterSleep() и способ постобработки разностей носят 
экспериментальный характер.

[1] https://www.chronox.de/jent/CPU-Jitter-NPTRNG-v2.2.0.pdf;
[2] https://www.irisa.fr/caps/projects/hipsor/publications/havege-tomacs.pdf.

\remark Дополнительная информация / реализации:
* https://static.lwn.net/images/conf/rtlws11/random-hardware.pdf
* https://www.issihosts.com/haveged/;
* https://github.com/smuellerDD/jitterentropy-library;
* https://github.com/jirka-h/haveged.

\todo Уточнить rngJitterSleep() и способ постобработки.
*******************************************************************************
*/

static bool_t rngJitterIsAvail()
{
	return tmCtrStart();
}

static size_t _jitter_pos;
static octet _jitter_table[4096];

static void rngJitterSleep()
{
	register size_t pos = _jitter_pos;
	register octet o = _jitter_table[pos];
	switch (pos & 3)
	{
		case 0:
			pos += 12;
			break;
		case 1:
			pos += 189;
			break;
		case 2:
			pos += 3017;
			break;
		case 3:
			pos += 127;
			break;
	}
	pos %= sizeof(_jitter_table);
	_jitter_table[_jitter_pos] = _jitter_table[pos];
	_jitter_table[_jitter_pos = pos] = o; 
}

err_t rngJitterRead(void* buf, size_t* read, size_t count)
{
	static const tm_ticks_t mask = 
		((tm_ticks_t)1 << (8 * sizeof(tm_ticks_t) - 1)) | 0x0175;
	register tm_ticks_t ticks;
	register tm_ticks_t t;
	register tm_ticks_t w;
	size_t i, j, reps;
	// pre
	ASSERT(memIsValid(read, sizeof(size_t)));
	ASSERT(memIsValid(buf, count));
	// есть источник?
	if (!rngJitterIsAvail())
		return ERR_FILE_NOT_FOUND;
	// генерация
	for (i = 0, w = 0; i < count; ++i)
	{
		((octet*)buf)[i] = 0;
		ticks = tmCtrTicks();
		for (j = 0; j < 8; ++j)
		{
			for (reps = 0; reps < 128; ++reps)
			{
				rngJitterSleep();
				t = tmCtrTicks();
				w ^= (word)(t - ticks);
				w = (w >> 1) ^ (~((w & 1) - 1) & mask);
				ticks = t;
			}
			if (sizeof(tm_ticks_t) <= 4)
				((octet*)buf)[i] ^= u32Parity((u32)w) << j;
			else
				((octet*)buf)[i] ^= u64Parity((u64)w) << j;
		}
	}
	CLEAN3(ticks, t, w);
	*read = count;
	return ERR_OK;
}
