/*
*******************************************************************************
\file tm_test.c
\brief Tests for time management
\project bee2/test
\created 2014.10.13
\version 2022.07.12
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
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
		size_t y;
		size_t m;
		size_t d;
		octet date[6];
		if (!tmDate(&y, &m, &d) || !tmDate2(date) ||
			!tmDateIsValid(y, m, d) || !tmDateIsValid2(date) ||
			tmDateIsValid(1582, 12, 31) || tmDateIsValid(1583, 9, 31) ||
			!tmDateIsValid(1600, 2, 29) || tmDateIsValid(1900, 2, 29))
			return FALSE;
		printf("tm::date: %04u-%02u-%02u\n",
			(unsigned)y, (unsigned)m, (unsigned)d);
	}
	// все нормально
	return TRUE;
}
