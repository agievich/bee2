/*
*******************************************************************************
\file gfp.c
\brief Prime fields
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2012.07.11
\version 2014.04.17
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/mem.h"
#include "bee2/core/util.h"
#include "bee2/math/gfp.h"
#include "bee2/math/pri.h"
#include "bee2/math/ww.h"

/*
*******************************************************************************
Управление описанием поля

\todo Поддержать функции редукции для простых Солинаса из NIST:
P192, P224, P256, P384, P521.

\todo Реализовать алгоритм обращения a^{-1} mod p, p -- простое, предложенный в
[J.J. Thomas, J.M.Keller, G.N.Larsen. The calculation of multiplicative 
inverses over GF(p) efficiently where p is a Mersenne prime, 
IEEE Trans. on Computers 35 No5 (1986), 478–482] и цитируемый в соответствии
с [Algorithm 11.9 Prime field inversion, CohenFrey, p. 207]:
	t <- a mod p, b <- 1
	while t != 1
	  q <- - (p div t)
	  t <- p + q t
	  b <- (q b) mod p
	return b
*******************************************************************************
*/

bool_t gfpCreate(qr_o* r, const octet p[], size_t no, void* stack)
{
	ASSERT(memIsValid(r, sizeof(*r)));
	ASSERT(memIsValid(p, no));
	ASSERT(no > 0 && p[no - 1] > 0);
	// p -- четное или p == 1?
	if (no == 0 || p[0] % 2 == 0 || no == 1 && p[0] == 1)
		return FALSE;
	// создать GF(p) как ZZ / (p)
	zmCreate(r, p, no, stack);
	return TRUE;
}

size_t gfpCreate_keep(size_t no)
{
	return zmCreate_keep(no);
}

size_t gfpCreate_deep(size_t no)
{
	return zmCreate_deep(no);
}

bool_t gfpIsOperable(const qr_o* f)
{
	return zmIsValid(f) && 
		f->mod[0] % 2 &&
		(f->n > 1 || f->mod[0] > 1);
}

bool_t gfpIsValid(const qr_o* f, void* stack)
{
	return gfpIsOperable(f) &&
		priIsPrime(f->mod, f->n, stack);
}

size_t gfpIsValid_deep(size_t n)
{
	return priIsPrime_deep(n);
}
