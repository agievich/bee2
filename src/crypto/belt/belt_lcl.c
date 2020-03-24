/*
*******************************************************************************
\file belt_lcl.c
\brief STB 34.101.31 (belt): local functions
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2012.12.18
\version 2020.03.20
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/mem.h"
#include "bee2/core/u32.h"
#include "bee2/core/util.h"
#include "bee2/crypto/belt.h"
#include "bee2/math/pp.h"
#include "bee2/math/ww.h"
#include "belt_lcl.h"

/*
*******************************************************************************
Арифметика чисел
*******************************************************************************
*/

void beltBlockAddBitSizeU32(u32 block[4], size_t count)
{
	// block <- block + 8 * count
	register u32 carry = (u32)count << 3;
#if (B_PER_S < 32)
	carry = (block[0] += carry) < carry;
	carry = (block[1] += carry) < carry;
	carry = (block[2] += carry) < carry;
	block[3] += carry;
#else
	register size_t t = count >> 29;
	carry = (block[0] += carry) < carry;
	if ((block[1] += carry) < carry)
		block[1] = (u32)t;
	else
		carry = (block[1] += (u32)t) < (u32)t;
	t >>= 16, t >>= 16;
	if ((block[2] += carry) < carry)
		block[2] = (u32)t;
	else
		carry = (block[2] += (u32)t) < (u32)t;
	t >>= 16, t >>= 16;
	block[3] += carry;
	block[3] += (u32)t;
	t = 0;
#endif
	carry = 0;
}

void beltHalfBlockAddBitSizeW(word block[W_OF_B(64)], size_t count)
{
	// block <- block + 8 * count
	register word carry = (word)count << 3;
#if (B_PER_W == 16)
	register size_t t = count >> 13;
	carry = (block[0] += carry) < carry;
	if ((block[1] += carry) < carry)
		block[1] = (word)t;
	else
		carry = (block[1] += (word)t) < (word)t;
	t >>= 8, t >>= 8;
	if ((block[2] += carry) < carry)
		block[2] = (word)t;
	else
		carry = (block[2] += (word)t) < (word)t;
	t >>= 8, t >>= 8;
	block[3] += carry;
	block[3] += (word)t;
#elif (B_PER_W == 32)
	register size_t t = count;
	carry = (block[0] += carry) < carry;
	t >>= 15, t >>= 14;
	block[1] += carry;
	block[1] += (u32)t;
	t = 0;
#elif (B_PER_W == 64)
	block[0] += carry;
#else
	#error "Unsupported word size"
#endif // B_PER_W
	carry = 0;
}

/*
*******************************************************************************
Арифметика многочленов
*******************************************************************************
*/

void beltPolyMul(word c[], const word a[], const word b[], void* stack)
{
	const size_t n = W_OF_B(128);
	word* prod = (word*)stack;
	stack = prod + 2 * n;
	// умножить
	ppMul(prod, a, n, b, n, stack);
	// привести по модулю
	ppRedBelt(prod);
	wwCopy(c, prod, n);
}

size_t beltPolyMul_deep()
{
	const size_t n = W_OF_B(128);
	return O_OF_W(2 * n) + ppMul_deep(n, n);
}

/*
*******************************************************************************
Умножение на многочлен C(x) = x mod (x^128 + x^7 + x^2 + x + 1)

\remark t = (старший бит block ненулевой) ? x^7 + x^2 + x + 1 : 0 [регулярно].
*******************************************************************************
*/

void beltBlockMulC(u32 block[4])
{
	register u32 t = ~((block[3] >> 31) - U32_1) & 0x00000087;
	block[3] = (block[3] << 1) ^ (block[2] >> 31);
	block[2] = (block[2] << 1) ^ (block[1] >> 31);
	block[1] = (block[1] << 1) ^ (block[0] >> 31);
	block[0] = (block[0] << 1) ^ t;
	t = 0;
}
