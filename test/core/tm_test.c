/*
*******************************************************************************
\file tm_test.c
\brief Tests for time management
\project bee2/test
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2014.10.13
\version 2022.07.12
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
	// время
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
	}
	// дата
	{
		size_t year;
		size_t mon;
		size_t day;
		octet date[6];
		if (tmDate(&year, &mon, &day) != ERR_OK || tmDate2(date) != ERR_OK)
			return FALSE;
		printf("tm::date: %04u-%02u-%02u\n",
			(unsigned)year, (unsigned)mon, (unsigned)day);
	}
	// все нормально
	return TRUE;
}
