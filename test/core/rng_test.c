/*
*******************************************************************************
\file rng_test.c
\brief Tests for random number generators
\project bee2/test
\author Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2014.10.10
\version 2021.05.18
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
	const char* sources[] = { "trng", "trng2", "sys", "timer" };
	octet buf[2500];
	char hex[33];
	size_t read;
	size_t pos;
	// пробежать источники
	for (pos = 0; pos < COUNT_OF(sources); ++pos)
	{
		if (rngReadSource(&read, buf, 2500, sources[pos]) == ERR_OK)
		{
			if (read == 2500)
				hexFrom(hex, buf, 16),
				printf("rngSource[%5s]: %s... [FIPS: 1%c 2%c 3%c 4%c]\n",
					sources[pos],
					hex,
					rngTestFIPS1(buf) ? '+' : '-',
					rngTestFIPS2(buf) ? '+' : '-',
					rngTestFIPS3(buf) ? '+' : '-',
					rngTestFIPS4(buf) ? '+' : '-');
			else if (read > 16)
				hexFrom(hex, buf, 16),
				printf("rngSource[%5s]: %s... (%u bytes)\n",
					sources[pos], hex, (unsigned)read);
			else
				hexFrom(hex, buf, read),
				printf("rngSource[%5s]: %s\n", sources[pos], hex);
		}
	}
	// работа с ГСЧ
	if (rngCreate(0, 0) != ERR_OK)
		return FALSE;
	if (!rngIsValid())
		return FALSE;
	rngStepR(buf, 2500, 0);
	hexFrom(hex, buf, 16);
	printf("rngStepR:         %s... [FIPS: 1%c 2%c 3%c 4%c]\n",
		hex,
		rngTestFIPS1(buf) ? '+' : '-',
		rngTestFIPS2(buf) ? '+' : '-',
		rngTestFIPS3(buf) ? '+' : '-',
		rngTestFIPS4(buf) ? '+' : '-');
	rngStepR2(buf, 2500, 0);
	hexFrom(hex, buf, 16);
	printf("rngStepR2:        %s... [FIPS: 1%c 2%c 3%c 4%c]\n",
		hex,
		rngTestFIPS1(buf) ? '+' : '-',
		rngTestFIPS2(buf) ? '+' : '-',
		rngTestFIPS3(buf) ? '+' : '-',
		rngTestFIPS4(buf) ? '+' : '-');
	if (rngCreate(0, 0) != ERR_OK)
		return FALSE;
	rngClose();
	if (!rngIsValid())
		return FALSE;
	rngClose();
	if (rngIsValid())
		return FALSE;
	// все нормально
	return TRUE;
}
