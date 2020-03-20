/*
*******************************************************************************
\file prng.c
\brief Pseudorandom number generators
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2014.05.02
\version 2016.07.15
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/mem.h"
#include "bee2/core/prng.h"
#include "bee2/core/u32.h"
#include "bee2/core/util.h"

/*
*******************************************************************************
\todo Генератор-счетчик.
*******************************************************************************
*/


/*
*******************************************************************************
Генератор COMBO
*******************************************************************************
*/

typedef struct {
	u32 x;			/*< параметр x */
	u32 y;			/*< параметр y */
	u32 z;			/*< параметр z */
	union {
		u32 u32;
		octet block[4];
	} r;				/*< псевдослучайное данные */
	size_t reserved;	/*< резерв октетов в r.block */
} prng_combo_st;

static void prngCOMBOStep(prng_combo_st* s)
{
	s->r.u32 = s->x * s->x;
	s->x = s->y;
	s->y = s->r.u32;
	s->z = (s->z & 0xFFFF) * 30903 + (s->z >> 16);
	s->r.u32 += s->z;
#if (OCTET_ORDER == BIG_ENDIAN)
	s->r.u32 = u32Rev(s->r.u32);
#endif
}

size_t prngCOMBO_keep()
{
	return sizeof(prng_combo_st);
}

void prngCOMBOStart(void* state, u32 seed)
{
	prng_combo_st* s = (prng_combo_st*)state;
	ASSERT(memIsValid(s, sizeof(*s)));
	s->x = 0xF8B7BB93;
	s->y = 0xBEE3B54B;
	s->z = 0x1F6B7FBD + seed;
	if (s->z)
		++s->z;
	s->reserved = 0;
}

void prngCOMBOStepR(void* buf, size_t count, void* state)
{
	prng_combo_st* s = (prng_combo_st*)state;
	ASSERT(memIsValid(buf, count));
	ASSERT(memIsValid(s, sizeof(*s)));
	// есть резерв?
	if (s->reserved)
	{
		if (s->reserved >= count)
		{
			memCopy(buf, s->r.block + 4 - s->reserved, count);
			s->reserved -= count;
			return;
		}
		memCopy(buf, s->r.block + 4 - s->reserved, s->reserved);
		count -= s->reserved;
		buf = (octet*)buf + s->reserved;
		s->reserved = 0;
	}
	// цикл по полным блокам
	while (count >= 4)
	{
		prngCOMBOStep(s);
		memCopy(buf, s->r.block, 4);
		buf = (octet*)buf + 4;
		count -= 4;
	}
	// неполный блок?
	if (count)
	{
		prngCOMBOStep(s);
		memCopy(buf, s->r.block, count);
		s->reserved = 4 - count;
	}
}

/*
*******************************************************************************
Эхо-генератор
*******************************************************************************
*/

typedef struct
{
	const octet* seed;	/*< буфер */
	size_t seed_len;	/*< длина буфера */
	size_t pos;			/*< позиция в буфере */
} prng_echo_st;

size_t prngEcho_keep()
{
	return sizeof(prng_echo_st);
}

void prngEchoStart(void* state, const void* seed, size_t seed_len)
{
	prng_echo_st* s = (prng_echo_st*)state;
	ASSERT(memIsValid(s, sizeof(prng_echo_st)));
	ASSERT(seed_len > 0);
	ASSERT(memIsValid(seed, seed_len));
	// инициализировать
	s->seed = (const octet*)seed;
	s->seed_len = seed_len;
	s->pos = 0;
}

void prngEchoStepR(void* buf, size_t count, void* state)
{
	prng_echo_st* s = (prng_echo_st*)state;
	ASSERT(memIsValid(s, sizeof(prng_echo_st)));
	ASSERT(memIsValid(s->seed, s->seed_len));
	ASSERT(memIsValid(buf, count));
	// генерировать
	while (count--)
	{
		*((octet*)buf) = s->seed[s->pos];
		buf = (octet*)buf + 1;
		++s->pos;
		if (s->pos == s->seed_len)
			s->pos = 0;
	}
}

/*
*******************************************************************************
Генератор СТБ
*******************************************************************************
*/

typedef struct
{
	size_t i;		/*< счетчик */
	u16 z[31];		/*< числа z_i */
	u16 v;			/*< числа v_i */
	u16 w;			/*< числа w_i */
	u16 u;			/*< числа u_i */
} prng_stb_st;

size_t prngSTB_keep()
{
	return sizeof(prng_stb_st);
}

static void _prngSTBClock(prng_stb_st* s)
{
	size_t j = (s->i + 10) % 31;
	// v <- v + z[i]
	s->v += s->z[s->i];
	// w <- z[i + 20] + rotHi(w, 1)
	s->w = (s->w >> 1) | (s->w << 15);
	s->w += s->z[(s->i + 20) % 31];
	// u <- v ^ w
	s->u = s->v ^ s->w;
	// z[i] <- (z[i - 31] - z[i - 21]) \mod 65257
	ASSERT(s->z[s->i] < 65257 && s->z[j] < 65257);
	if (s->z[s->i] >= s->z[j])
		s->z[s->i] -= s->z[j];
	else
		s->z[s->i] = 65257 - (s->z[j] - s->z[s->i]);
	// i <- i + 1
	s->i = (s->i + 1) % 31;
}

void prngSTBStart(void* state, const u16 z[31])
{
	prng_stb_st* s = (prng_stb_st*)state;
	size_t i;
	// pre
	ASSERT(memIsValid(s, sizeof(prng_stb_st)));
	ASSERT(memIsNullOrValid(z, 2 * 31));
	// загрузить z
	for (i = 0; i < 31; ++i)
	{
		s->z[i] = z ? z[i] : (u16)(i + 1);
		ASSERT(s->z[i] > 0 && s->z[i] < 65257);
	}
	// настроить состояние
	s->v = s->w = 0;
	s->i = 0;
	// холостой ход
	for (i = 0; i < 256; ++i)
		_prngSTBClock(s);
}

void prngSTBStepR(void* buf, size_t count, void* state)
{
	register u16 u;
	prng_stb_st* s = (prng_stb_st*)state;
	// pre
	ASSERT(memIsValid(s, sizeof(prng_stb_st)));
	ASSERT(memIsValid(buf, count));
	// генерировать
	while (count--)
	{
		u = s->u;
		_prngSTBClock(s);
		*((octet*)buf) = (s->u) + u / 255;
		buf = (octet*)buf + 1;
	}
	u = 0;
}
