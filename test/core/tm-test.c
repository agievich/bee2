/*
*******************************************************************************
\file tm-test.c
\brief Tests for time management
\project bee2/test
\author (С) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2014.10.13
\version 2014.10.13
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
		(uint32)freq, (uint32)ticks);
	// все нормально
	return TRUE;
}
