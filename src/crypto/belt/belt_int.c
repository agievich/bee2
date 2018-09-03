/*
*******************************************************************************
\file belt_int.c
\brief STB 34.101.31 (belt): internal functions
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2012.12.18
\version 2018.09.03
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/mem.h"
#include "bee2/core/u32.h"
#include "bee2/core/util.h"
#include "bee2/crypto/belt.h"
#include "belt_int.h"

/*
*******************************************************************************
Арифметика
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
Алгоритмы belt-compr, sigma2

Функция beltCompr() возвращает оба выхода belt-compr:
	s <- s + sigma1(X || h), h <- sigma2(X || h).
Функция beltCompr2() возвращает только второй выход.

h и X разбиваются на половинки:
	[8]h = [4]h0 || [4]h1, [8]X = [4]X0 || [4]X1.

\pre Буферы s и h, s и X, h и X не пересекаются.

\warning Для получения точного первого выхода в beltCompr() следует обнулить
буфер s перед обращением.

Схема расчета глубины стека:
		beltCompr_deep().
*******************************************************************************
*/

void beltCompr(u32 s[4], u32 h[8], const u32 X[8], void* stack)
{
	// [12]buf = [4]buf0 || [4]buf1 || [4]buf2
	u32* buf = (u32*)stack;
	// буферы не пересекаются?
	ASSERT(memIsDisjoint4(s, 16, h, 32, X, 32, buf, 48));
	// buf0, buf1 <- h0 + h1
	beltBlockXor(buf, h, h + 4);
	beltBlockCopy(buf + 4, buf);
	// buf0 <- beltBlock(buf0, X) + buf1
	beltBlockEncr2(buf, X);
	beltBlockXor2(buf, buf + 4);
	// s <- s ^ buf0
	beltBlockXor2(s, buf);
	// buf2 <- h0
	beltBlockCopy(buf + 8, h);
	// buf1 <- h1 [buf01 == K1]
	beltBlockCopy(buf + 4, h + 4);
	// h0 <- beltBlock(X0, buf01) + X0
	beltBlockCopy(h, X);
	beltBlockEncr2(h, buf);
	beltBlockXor2(h, X);
	// buf1 <- ~buf0 [buf12 == K2]
	beltBlockNeg(buf + 4, buf);
	// h1 <- beltBlock(X1, buf12) + X1
	beltBlockCopy(h + 4, X + 4);
	beltBlockEncr2(h + 4, buf + 4);
	beltBlockXor2(h + 4, X + 4);
}

void beltCompr2(u32 h[8], const u32 X[8], void* stack)
{
	// [12]buf = [4]buf0 || [4]buf1 || [4]buf2
	u32* buf = (u32*)stack;
	// буферы не пересекаются?
	ASSERT(memIsDisjoint3(h, 32, X, 32, buf, 48));
	// buf0, buf1 <- h0 + h1
	beltBlockXor(buf, h, h + 4);
	beltBlockCopy(buf + 4, buf);
	// buf0 <- beltBlock(buf0, X) + buf1
	beltBlockEncr2(buf, X);
	beltBlockXor2(buf, buf + 4);
	// buf2 <- h0
	beltBlockCopy(buf + 8, h);
	// buf1 <- h1 [buf01 == K1]
	beltBlockCopy(buf + 4, h + 4);
	// h0 <- beltBlock(X0, buf01) + X0
	beltBlockCopy(h, X);
	beltBlockEncr2(h, buf);
	beltBlockXor2(h, X);
	// buf1 <- ~buf0 [buf12 == K2]
	beltBlockNeg(buf + 4, buf);
	// h1 <- beltBlock(X1, buf12) + X1
	beltBlockCopy(h + 4, X + 4);
	beltBlockEncr2(h + 4, buf + 4);
	beltBlockXor2(h + 4, X + 4);
}

size_t beltCompr_deep()
{
	return 12 * 4;
}

