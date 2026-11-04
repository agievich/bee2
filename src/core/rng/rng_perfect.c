#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <string.h>


#if defined(_WIN32)
    #ifndef _CRT_RAND_S
        #define _CRT_RAND_S
    #endif
    #include <stdlib.h>          /* rand_s */
#else
    #include <unistd.h>          /* getpid */
#endif


#include "bee2/core/err.h"
#include "bee2/core/mem.h"
#include "bee2/core/rng.h"
#include "bee2/core/util.h"
#include "../../../external/perfect-random/1F4B~1/perfect_random_c.h"  

#define PRNG_N_DEFAULT 49        /* каскадный параметр N */
#define PRNG_BB_CAP    16        /* буфер битов: до 68 бит + запас */

static cascade_prng prng_state;
static int prng_inited = 0;

static octet prng_bb[PRNG_BB_CAP];   /* битовый буфер */
static int prng_bb_bits = 0;

/* --- сидирование: /dev/urandom или rand_s + подмес таймера/pid --- */
static uint64_t prngOsEntropy64(void)
{
    uint64_t seed = 0;
    uint64_t t;
#if defined(_WIN32)
    unsigned int v = 0;
    if (rand_s(&v) == 0)
        seed = (uint64_t)v;
#else
    FILE* f = fopen("/dev/urandom", "rb");
    if (f != 0)
    {
        octet buf[8];
        size_t i;
        if (fread(buf, 1, 8, f) == 8)
            for (i = 0; i < 8; ++i)
                seed = (seed << 8) | buf[i];
        fclose(f);
    }
#endif
    t = (uint64_t)time(0) ^ ((uint64_t)clock() << 32);
    t ^= (uint64_t)(uintptr_t)&seed;
#if !defined(_WIN32)
    t ^= (uint64_t)getpid() << 17;
#endif
    seed ^= (t << 31) | (t >> 33);   /* rol-смешение */
    return seed;
}

static err_t prngStart(void)
{
    if (prng_inited)
        return ERR_OK;
    cascade_prng_init(&prng_state, prngOsEntropy64(), PRNG_N_DEFAULT);
    prng_bb_bits = 0;
    prng_inited = 1;
    return ERR_OK;
}

/* --- битовый буфер: положить nbits (<= 61) младших бит v --- */
static void prngPutBits(uint32_t v, int nbits)
{
    int i;
    for (i = nbits - 1; i >= 0; --i)
    {
        size_t byte = prng_bb_bits >> 3;
        int off = prng_bb_bits & 7;
        if (off == 0)
            prng_bb[byte] = 0;       /* очистка от протухших битов */
        prng_bb[byte] = (octet)((prng_bb[byte] << 1) | (int)((v >> i) & 1));
        ++prng_bb_bits;
    }
}

err_t rngPerfectRead(void* buf, size_t* read, size_t count)
{
	octet* out = (octet*)buf;
	size_t done = 0;
	int i;
	// pre
	ASSERT(memIsValid(read, O_PER_S));
	ASSERT(memIsValid(buf, count));
	*read = 0;
	if (count == 0)
		return ERR_OK;
	// инициализация по первому обращению
	if (!prng_inited && prngStart() != ERR_OK)
		return ERR_BAD_ENTROPY;
	// выдача: битовый буфер не имеет блочных ограничений,
	// поэтому заполняем ровно count октетов без хвостовых хитростей
	while (done < count)
	{
		while (prng_bb_bits < 8)
			prngPutBits(cascade_prng_generate_raw(&prng_state), 31);
		out[done++] = prng_bb[0];
		for (i = 0; i < PRNG_BB_CAP - 1; ++i)
			prng_bb[i] = prng_bb[i + 1];
		prng_bb_bits -= 8;
	}
	*read = done;
	return ERR_OK;
}
