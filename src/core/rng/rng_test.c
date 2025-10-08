/*
*******************************************************************************
\file rng_test.c
\brief Random number generation: statistical tests
\project bee2 [cryptographic library]
\created 2014.10.13
\version 2025.10.08
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/core/err.h"
#include "bee2/core/mem.h"
#include "bee2/core/rng.h"
#include "bee2/core/util.h"
#include "bee2/core/word.h"

/*
*******************************************************************************
Статистические тесты

\todo Оценка энтропии.
*******************************************************************************
*/

bool_t rngTestFIPS1(const octet buf[2500])
{
	register size_t s;
	register word w;
	size_t count;
	ASSERT(memIsValid(buf, 2500));
	for (w = 0, count = 2500; !memIsAligned(buf, O_PER_W); ++buf, --count)
		w = (w << 8) | *buf;
	s = wordWeight(w);
	for (; count >= O_PER_W; buf += O_PER_W, count -= O_PER_W)
	{
		ASSERT(memIsAligned(buf, O_PER_W));
		s += wordWeight(*(const word*)buf);
	}
	for (w = 0; count; ++buf, --count)
		w = (w << 8) | *buf;
	s += wordWeight(w);
	CLEAN(w);
	return 9725 < s && s < 10275;
}

bool_t rngTestFIPS2(const octet buf[2500])
{
	u32 s[16];
	size_t i = 2500;
	ASSERT(memIsValid(buf, 2500));
	memSetZero(s, sizeof(s));
	while (i--)
		++s[buf[i] & 15], ++s[buf[i] >> 4];
	s[0] *= s[0];
	for (i = 1; i < 16; ++i)
		s[0] += s[i] * s[i];
	s[0] = 16 * s[0] - 5000 * 5000;
	return 10800 < s[0] && s[0] < 230850;
}

bool_t rngTestFIPS3(const octet buf[2500])
{
	word s[2][7];
	octet b;
	size_t l;
	size_t i;
	ASSERT(memIsValid(buf, 2500));
	memSetZero(s, sizeof(s));
	b = buf[0] & 1;
	l = 1;
	for (i = 1; i < 20000; ++i)
		if ((buf[i / 8] >> i % 8 & 1) == b)
			++l;
		else
			++s[b][MIN2(l, 6)], b = !b, l = 1;
	++s[b][MIN2(l, 6)];
	return 2315 <= s[0][1] && s[0][1] <= 2685 &&
		2315 <= s[1][1] && s[1][1] <= 2685 &&
		1114 <= s[0][2] && s[0][2] <= 1386 &&
		1114 <= s[1][2] && s[1][2] <= 1386 &&
		527 <= s[0][3] && s[0][3] <= 723 &&
		527 <= s[1][3] && s[1][3] <= 723 &&
		240 <= s[0][4] && s[0][4] <= 384 &&
		240 <= s[1][4] && s[1][4] <= 384 &&
		103 <= s[0][5] && s[0][5] <= 209 &&
		103 <= s[1][5] && s[1][5] <= 209 &&
		103 <= s[0][6] && s[0][6] <= 209 &&
		103 <= s[1][6] && s[1][6] <= 209;
}

bool_t rngTestFIPS4(const octet buf[2500])
{
	octet b;
	size_t l;
	size_t i;
	ASSERT(memIsValid(buf, 2500));
	b = buf[0] & 1;
	l = 1;
	for (i = 1; i < 20000; ++i)
		if ((buf[i / 8] >> i % 8 & 1) == b)
			++l;
		else
		{
			if (l >= 26)
				return FALSE;
			b = !b, l = 1;
		}
	return l < 26;
}

