/*
*******************************************************************************
\file belt_compr.c
\brief STB 34.101.31 (belt): compression
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2012.12.18
\version 2019.06.26
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/mem.h"
#include "bee2/core/u32.h"
#include "bee2/core/util.h"
#include "bee2/crypto/belt.h"
#include "belt_lcl.h"

/*
*******************************************************************************
Сжатие (belt-compress) форматированных данных

h и X разбиваются на половинки:
	[8]h = [4]h0 || [4]h1, [8]X = [4]X0 || [4]X1.
*******************************************************************************
*/

void beltCompr(u32 h[8], const u32 X[8], void* stack)
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

void beltCompr2(u32 s[4], u32 h[8], const u32 X[8], void* stack)
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

size_t beltCompr_deep()
{
	return 12 * 4;
}
