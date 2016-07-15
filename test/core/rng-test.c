/*
*******************************************************************************
\file rng-test.c
\brief Tests for random number generators
\project bee2/test
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2014.10.10
\version 2016.07.15
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include <stdio.h>
#include <bee2/core/mem.h>
#include <bee2/core/hex.h>
#include <bee2/core/prng.h>
#include <bee2/core/rng.h>
#include <bee2/core/util.h>

/*
*******************************************************************************
Тестирование
*******************************************************************************
*/

bool_t rngTest()
{
	octet buf[2500];
	char hex[33];
	size_t read;
	// источник-таймер
	if (rngReadSource(&read, buf, 2500, "timer") == ERR_OK)
	{
		if (read == 2500)
			hexFrom(hex, buf, 16),
			printf("rngSourceTimer: %s... [FIPS: 1%c 2%c 3%c 4%c]\n",
				hex,
				rngTestFIPS1(buf) ? '+' : '-',
				rngTestFIPS2(buf) ? '+' : '-',
				rngTestFIPS3(buf) ? '+' : '-',
				rngTestFIPS4(buf) ? '+' : '-');
		else if (read > 16)
			hexFrom(hex, buf, 16),
			printf("rngSourceTimer: %s... (%u bytes)\n", hex, (unsigned)read);
		else
			hexFrom(hex, buf, read),
			printf("rngSourceTimer: %s\n", hex);
	}
	// физический источник
	if (rngReadSource(&read, buf, 2500, "trng") == ERR_OK)
	{
		if (read == 2500)
			hexFrom(hex, buf, 16),
			printf("rngSourceTRNG:  %s... [FIPS: 1%c 2%c 3%c 4%c]\n",
				hex,
				rngTestFIPS1(buf) ? '+' : '-',
				rngTestFIPS2(buf) ? '+' : '-',
				rngTestFIPS3(buf) ? '+' : '-',
				rngTestFIPS4(buf) ? '+' : '-');
		else if (read > 16)
			hexFrom(hex, buf, 16),
			printf("rngSourceTRNG:  %s... (%u bytes)\n", hex, (unsigned)read);
		else
			hexFrom(hex, buf, read),
			printf("rngSourceTRNG:  %s\n", hex);
	}
	// системный источник
	if (rngReadSource(&read, buf, 2500, "sys") == ERR_OK)
	{
		if (read == 2500)
			hexFrom(hex, buf, 16),
			printf("rngSourceSys:   %s... [FIPS: 1%c 2%c 3%c 4%c]\n",
				hex,
				rngTestFIPS1(buf) ? '+' : '-',
				rngTestFIPS2(buf) ? '+' : '-',
				rngTestFIPS3(buf) ? '+' : '-',
				rngTestFIPS4(buf) ? '+' : '-');
		else if (read > 16)
			hexFrom(hex, buf, 16),
			printf("rngSourceSys:   %s... (%u bytes)\n", hex, (unsigned)read);
		else
			hexFrom(hex, buf, read),
			printf("rngSourceSys:   %s\n", hex);
	}
	// работа с ГСЧ
	if (rngCreate(0, 0) != ERR_OK)
		return FALSE;
	rngStepR(buf, 2500, 0);
	hexFrom(hex, buf, 16);
	printf("rngStepR:       %s... [FIPS: 1%c 2%c 3%c 4%c]\n",
		hex,
		rngTestFIPS1(buf) ? '+' : '-',
		rngTestFIPS2(buf) ? '+' : '-',
		rngTestFIPS3(buf) ? '+' : '-',
		rngTestFIPS4(buf) ? '+' : '-');
	rngStepR2(buf, 2500, 0);
	hexFrom(hex, buf, 16);
	printf("rngStepR2:      %s... [FIPS: 1%c 2%c 3%c 4%c]\n",
		hex,
		rngTestFIPS1(buf) ? '+' : '-',
		rngTestFIPS2(buf) ? '+' : '-',
		rngTestFIPS3(buf) ? '+' : '-',
		rngTestFIPS4(buf) ? '+' : '-');
	rngClose();
	// все нормально
	return TRUE;
}
