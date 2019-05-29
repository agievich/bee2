/*
*******************************************************************************
\file tm_test.c
\brief Tests for time management
\project bee2/test
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2014.10.13
\version 2017.01.17
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include <stdio.h>
#include <bee2/core/mt.h>
#include <bee2/core/tm.h>

/*
*******************************************************************************
Тестирование
*******************************************************************************
*/

bool_t tmTest()
{
	tm_ticks_t freq = tmFreq();
	tm_ticks_t ticks = tmTicks();
	mtSleep(1000);
	ticks = tmTicks() - ticks;
	printf("tm::timer: freq = %u vs ticks_per_sec = %u\n", 
		(u32)freq, (u32)ticks);
	printf("tm::timer: test_speed = %u vs freq = %u\n", 
		(u32)tmSpeed(10, 10), (u32)freq);
	printf("tm::timer: time = %u vs test_time_round = %u\n", 
		(u32)tmTime(), (u32)tmTimeRound(0, 1));
	// все нормально
	return TRUE;
}
