/*
*******************************************************************************
\file ecp_j.c
\brief Elliptic curves over prime fields: Jacobian coordinates
\project bee2 [cryptographic library]
\created 2012.06.26
\version 2021.07.29
\license This program is released under the GNU General Public License
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/mem.h"
#include "bee2/core/util.h"
#include "bee2/math/ecp.h"
#include "bee2/math/gfp.h"
#include "bee2/math/ww.h"
#include "ecp_lcl.h"

/*
*******************************************************************************
Якобиевы координаты:
	x = X / Z^2, y = Y / Z^3,
	-(X : Y : Z) = (X : -Y : Z).

В функции ecpDblJ() выполняется удвоение P <- 2P. Реализован
алгоритм dbl-1998-hnm [Hasegawa T., Nakajima J., Matsui M. A Practical
Implementation of Elliptic Curve Cryptosystems over GF(p) on a
16-bit Microcomputer. Public Key Cryptography, 1998].
Сложность алгоритма:
	3M + 6S + 1*A + 1half + 6add + 3*2 \approx 9M.

\todo Сравнить dbl-1998-hnm с dbl-2007-bl, сложность которого
	1M + 8S + 1A + 10add + 1*8 + 2*2 + 1*3.

В функции ecpDblJA3() выполняется удвоение P <- 2P для случая A = -3.
Реализован алгоритм dbl-1998-hnm2 [Hasegawa T., Nakajima J., Matsui M.
A Practical Implementation of Elliptic Curve Cryptosystems over GF(p)
on a 16-bit Microcomputer. Public Key Cryptography, 1998].
Сложность алгоритма:
	4M + 4S + 1*half + 7add + 3*2 \approx 8M.

\todo Сравнить dbl-1998-hnm2 с dbl-2001-b, сложность которого
	3M +5S + 8add + 1*4 + 2*8 + 1*3.

В функции ecpDblAJ() выполняется удвоение P <- 2A. Реализован алгоритм
mdbl-2007-bl [Bernstein-Lange, 2007]. Сложность алгоритма:
	1M + 5S + 7add + 1*8 + 3*2 + 1*3 \approx 6M.

В функции ecpAddJ() выполняется сложение P <- P + P. Реализован алгоритм
add-2007-bl [Bernstein-Lange, 2007]. Сложность алгоритма:
	11M + 5S + 9add + 4*2 \approx 16M.

\todo Сравнить add-2007-bl с add-1998-cmo-2, сложность которого
	12M + 4S + 6add + 1*2.

В функции ecpAddAJ() выполняется сложение P <- P + A.
Реализован алгоритм madd-2004-hmv [Hankerson D., Menezes A., Vanstone S.
Guide to Elliptic Curve Cryptography, Springer, 2004].
Сложность алгоритма:
	8M + 3S + 6add + 1*2 \approx 11M.

В функции ecpTplJ() выполняется утроение P <- 3P. Реализован алгоритм
tpl-2007-bl [Bernstein-Lange, 2007]. Сложность алгоритма
	5M + 10S + 1*A + 15add + 2*4 + 1*6 + 1*8 + 1*16 + 1*3 \approx 15M.

В функции ecpTplJA3() выполняется утроение P <- 3P для случая A = -3.
Реализован алгоритм tpl-2007-bl-2 [Bernstein-Lange, 2007].
Сложность алгоритма
	7M + 7S + 13add + 2*4 + 1*8 + 1*12 + 1*16 + 1*3 \approx 14M.

Целевые функции ci(l), определенные в описании реализации ecMul() в ec.c,
принимают следующий вид:
	c1(l) = l/3 11;
	c2(l, w) = 103 + (2^{w-2} - 2)102 + l/(w + 1) 11;
	c3(l, w) = 6 + (2^{w-2} - 2)16 + l/(w + 1) 16.

Расчеты показывают, что
	с1(l) <= min_w c3(l), l <= 81,
	min_w c3(l, w) <= m	in_w c2(l, w), l <= 899.
Поэтому для практически используемых размерностей l (192 <= l <= 571)
первые две стратегии являются проигрышными. Реализована только стратегия 3.

\todo Сравнить madd-2004-hmv с madd-2007-bl, сложность которого
	7M + 4S + 9add + 1*4 + 3*2.

\todo При выполнении функции ecpAddAJ() может выясниться, что
складываются одинаковые точки. В этом случае вызывается функция
ecpDblAJ(). Подумать, как "помочь" этой функции, передав уже
рассчитанные значения, например, za^2. Аналогичное замечание касается
функции ecpAddJ().

В функции eclDblAddJ() выполняется удвоение якобиевой точки с одновременным 
сложением с афинной точкой:
	P <- 2P + A
Использован алгоритм, предложенный в приложении А.3 работы
[*]	P. Longa and A. Miri. New Multibase Non-Adjacent Form Scalar 
	Multiplication and its Application to Elliptic Curve Cryptosystems 
	(extended version). Cryptology ePrint Archive, Report 2008/052. 
	https://eprint.iacr.org/2008/052. 2008.
Время работы алгоритма:
	11M + 7S + 27A.

\warning В [*] имеется неточность: шаг 36 необходимо выполнять после шага 38, 
так как на шаге 38 значение переменной T5 предполагается равным theta^3.
Это значение устанавливается на шаге 33 и перезаписывается на шаге 36.
*******************************************************************************
*/

// [3n]b <- [2n]a (P <- A)
static bool_t ecpFromAJ(word b[], const word a[], const ec_o* ec, void* stack)
{
	const size_t n = ec->f->n;
	// pre
	ASSERT(ecIsOperable(ec) && ec->d == 3);
	ASSERT(ecpSeemsOnA(a, ec));
	ASSERT(a == b || wwIsDisjoint2(a, 2 * n, b, 3 * n));
	// xb <- xa
	qrCopy(ecX(b), ecX(a), ec->f);
	// yb <- ya
	qrCopy(ecY(b, n), ecY(a, n), ec->f);
	// zb <- unity
	qrSetUnity(ecZ(b, n), ec->f);
	return TRUE;
}

// [2n]b <- [3n]a (A <- P)
//todo регуляризовать, так как используется в SAFE(ecMulA)
static bool_t ecpToAJ(word b[], const word a[], const ec_o* ec, void* stack)
{
	const size_t n = ec->f->n;
	// переменные в stack
	word* t1 = (word*)stack;
	word* t2 = t1 + n;
	stack = t2 + n;
	// pre
	ASSERT(ecIsOperable(ec) && ec->d == 3);
	ASSERT(ecpSeemsOn3(a, ec));
	ASSERT(a == b || wwIsDisjoint2(a, 3 * n, b, 2 * n));
	// a == O => b <- O
	if (qrIsZero(ecZ(a, n), ec->f))
		return FALSE;
	// t1 <- za^{-1}
	qrInv(t1, ecZ(a, n), ec->f, stack);
	// t2 <- t1^2
	qrSqr(t2, t1, ec->f, stack);
	// xb <- xa t2
	qrMul(ecX(b), ecX(a), t2, ec->f, stack);
	// t2 <- t1 t2
	qrMul(t2, t1, t2, ec->f, stack);
	// yb <- ya t2
	qrMul(ecY(b, n), ecY(a, n), t2, ec->f, stack);
	// b != O
	return TRUE;
}

static size_t ecpToAJ_deep(size_t n, size_t f_deep)
{
	return O_OF_W(2 * n) + f_deep;
}

// [3n]b <- -[3n]a (P <- -P)
static void ecpNegJ(word b[], const word a[], const ec_o* ec, void* stack)
{
	const size_t n = ec->f->n;
	// pre
	ASSERT(ecIsOperable(ec) && ec->d == 3);
	ASSERT(ecpSeemsOn3(a, ec));
	ASSERT(wwIsSameOrDisjoint(a, b, 3 * n));
	// xb <- xa
	qrCopy(ecX(b), ecX(a), ec->f);
	// yb <- -ya
	zmNeg(ecY(b, n), ecY(a, n), ec->f);
	// zb <- za
	qrCopy(ecZ(b, n), ecZ(a, n), ec->f);
}

// [3n]b <- 2[3n]a (P <- 2P)
static void ecpDblJ(word b[], const word a[], const ec_o* ec, void* stack)
{
	const size_t n = ec->f->n;
	// переменные в stack
	word* t1 = (word*)stack;
	word* t2 = t1 + n;
	stack = t2 + n;
	// pre
	ASSERT(ecIsOperable(ec) && ec->d == 3);
	ASSERT(ecpSeemsOn3(a, ec));
	ASSERT(wwIsSameOrDisjoint(a, b, 3 * n));
	// za == 0 или ya == 0? => b <- O
	if (qrIsZero(ecZ(a, n), ec->f) || qrIsZero(ecY(a, n), ec->f))
	{
		qrSetZero(ecZ(b, n), ec->f);
		return;
	}
	// t1 <- za^2
	qrSqr(t1, ecZ(a, n), ec->f, stack);
	// zb <- ya za
	qrMul(ecZ(b, n), ecY(a, n), ecZ(a, n), ec->f, stack);
	// zb <- 2 zb
	gfpDouble(ecZ(b, n), ecZ(b, n), ec->f);
	// t1 <- t1^2
	qrSqr(t1, t1, ec->f, stack);
	// t1 <- A t1
	qrMul(t1, ec->A, t1, ec->f, stack);
	// t2 <- xa^2
	qrSqr(t2, ecX(a), ec->f, stack);
	// t1 <- t1 + t2
	zmAdd(t1, t1, t2, ec->f);
	// t2 <- 2 t2
	gfpDouble(t2, t2, ec->f);
	// t1 <- t1 + t2
	zmAdd(t1, t1, t2, ec->f);
	// yb <- 2 ya
	gfpDouble(ecY(b, n), ecY(a, n), ec->f);
	// yb <- yb^2
	qrSqr(ecY(b, n), ecY(b, n), ec->f, stack);
	// t2 <- yb^2
	qrSqr(t2, ecY(b, n), ec->f, stack);
	// t2 <- t2 / 2
	gfpHalf(t2, t2, ec->f);
	// yb <- yb xa
	qrMul(ecY(b, n), ecY(b, n), ecX(a), ec->f, stack);
	// xb <- t1^2
	qrSqr(ecX(b), t1, ec->f, stack);
	// xb <- xb - yb
	zmSub(ecX(b), ecX(b), ecY(b, n), ec->f);
	// xb <- xb - yb
	zmSub(ecX(b), ecX(b), ecY(b, n), ec->f);
	// yb <- yb - xb
	zmSub(ecY(b, n), ecY(b, n), ecX(b), ec->f);
	// yb <- yb t1
	qrMul(ecY(b, n), ecY(b, n), t1, ec->f, stack);
	// yb <- yb - t2
	zmSub(ecY(b, n), ecY(b, n), t2, ec->f);
}

static size_t ecpDblJ_deep(size_t n, size_t f_deep)
{
	return O_OF_W(2 * n) + f_deep;
}

// [3n]b <- 2[3n]a (P <- 2P, A = -3)
static void ecpDblJA3(word b[], const word a[], const ec_o* ec, void* stack)
{
	const size_t n = ec->f->n;
	// переменные в stack
	word* t1 = (word*)stack;
	word* t2 = t1 + n;
	stack = t2 + n;
	// pre
	ASSERT(ecIsOperable(ec) && ec->d == 3);
	ASSERT(ecpSeemsOn3(a, ec));
	ASSERT(wwIsSameOrDisjoint(a, b, 3 * n));
	// za == 0 или ya == 0? => b <- O
	if (qrIsZero(ecZ(a, n), ec->f) || qrIsZero(ecY(a, n), ec->f))
	{
		qrSetZero(ecZ(b, n), ec->f);
		return;
	}
	// t1 <- za^2
	qrSqr(t1, ecZ(a, n), ec->f, stack);
	// zb <- ya za
	qrMul(ecZ(b, n), ecY(a, n), ecZ(a, n), ec->f, stack);
	// zb <- 2 zb
	gfpDouble(ecZ(b, n), ecZ(b, n), ec->f);
	// t2 <- xa - t1
	zmSub(t2, ecX(a), t1, ec->f);
	// t1 <- xa + t1
	zmAdd(t1, ecX(a), t1, ec->f);
	// t2 <- t1 t2
	qrMul(t2, t1, t2, ec->f, stack);
	// t1 <- 2 t2
	gfpDouble(t1, t2, ec->f);
	// t1 <- t1 + t2
	zmAdd(t1, t1, t2, ec->f);
	// yb <- 2 ya
	gfpDouble(ecY(b, n), ecY(a, n), ec->f);
	// yb <- yb^2
	qrSqr(ecY(b, n), ecY(b, n), ec->f, stack);
	// t2 <- yb^2
	qrSqr(t2, ecY(b, n), ec->f, stack);
	// t2 <- t2 / 2
	gfpHalf(t2, t2, ec->f);
	// yb <- yb xa
	qrMul(ecY(b, n), ecY(b, n), ecX(a), ec->f, stack);
	// xb <- t1^2
	qrSqr(ecX(b), t1, ec->f, stack);
	// xb <- xb - yb
	zmSub(ecX(b), ecX(b), ecY(b, n), ec->f);
	// xb <- xb - yb
	zmSub(ecX(b), ecX(b), ecY(b, n), ec->f);
	// yb <- yb - xb
	zmSub(ecY(b, n), ecY(b, n), ecX(b), ec->f);
	// yb <- yb t1
	qrMul(ecY(b, n), ecY(b, n), t1, ec->f, stack);
	// yb <- yb - t2
	zmSub(ecY(b, n), ecY(b, n), t2, ec->f);
}

static size_t ecpDblJA3_deep(size_t n, size_t f_deep)
{
	return O_OF_W(2 * n) + f_deep;
}

// [3n]b <- 2[2n]a (P <- 2A)
static void ecpDblAJ(word b[], const word a[], const ec_o* ec, void* stack)
{
	const size_t n = ec->f->n;
	// переменные в stack
	word* t1 = (word*)stack;
	word* t2 = t1 + n;
	word* t3 = t2 + n;
	word* t4 = t3 + n;
	stack = t4 + n;
	// pre
	ASSERT(ecIsOperable(ec) && ec->d == 3);
	ASSERT(ecpSeemsOnA(a, ec));
	ASSERT(a == b || wwIsDisjoint2(a, 2 * n, b, 3 * n));
	// ya == 0? => b <- O
	if (qrIsZero(ecY(a, n), ec->f))
	{
		qrSetZero(ecZ(b, n), ec->f);
		return;
	}
	// t1 <- xa^2 [X1^2 = XX]
	qrSqr(t1, ecX(a), ec->f, stack);
	// t2 <- ya^2 [Y1^2 = YY]
	qrSqr(t2, ecY(a, n), ec->f, stack);
	// t3 <- t2^2 [YY^2 = YYYY]
	qrSqr(t3, t2, ec->f, stack);
	// t2 <- t2 + xa [X1 + YY]
	zmAdd(t2, t2, ecX(a), ec->f);
	// t2 <- t2^2 [(X1 + YY)^2]
	qrSqr(t2, t2, ec->f, stack);
	// t2 <- t2 - t1 [(X1 + YY)^2 - XX]
	zmSub(t2, t2, t1, ec->f);
	// t2 <- t2 - t3 [(X1 + YY)^2 - XX - YYYY]
	zmSub(t2, t2, t3, ec->f);
	// t2 <- 2 t2 [2((X1 + YY)^2 - XX - YYYY) = S]
	gfpDouble(t2, t2, ec->f);
	// t4 <- 2 t1 [2 XX]
	gfpDouble(t4, t1, ec->f);
	// t4 <- t4 + t1 [3 XX]
	zmAdd(t4, t4, t1, ec->f);
	// t4 <- t4 + A [3 XX + A = M]
	zmAdd(t4, t4, ec->A, ec->f);
	// t1 <- 2 t2 [2S]
	gfpDouble(t1, t2, ec->f);
	// xb <- t4^2 [M^2]
	qrSqr(ecX(b), t4, ec->f, stack);
	// xb <- xb - t1 [M^2 - 2S = T]
	zmSub(ecX(b), ecX(b), t1, ec->f);
	// zb <- 2 ya [2Y1]
	gfpDouble(ecZ(b, n), ecY(a, n), ec->f);
	// t2 <- t2 - xb [S - T]
	zmSub(t2, t2, ecX(b), ec->f);
	// yb <- t4 t2 [M(S - T)]
	qrMul(ecY(b, n), t4, t2, ec->f, stack);
	// t3 <- 2 t3 [2 YYYY]
	gfpDouble(t3, t3, ec->f);
	// t3 <- 2 t3 [4 YYYY]
	gfpDouble(t3, t3, ec->f);
	// t3 <- 2 t3 [8 YYYY]
	gfpDouble(t3, t3, ec->f);
	// yb <- yb - t3 [M(S - T) - 8 YYYY]
	zmSub(ecY(b, n), ecY(b, n), t3, ec->f);
}

static size_t ecpDblAJ_deep(size_t n, size_t f_deep)
{
	return O_OF_W(4 * n) + f_deep;
}

// [3n]c <- [3n]a + [3n]b (P <- P + P)
static void ecpAddJ(word c[], const word a[], const word b[], const ec_o* ec,
	void* stack)
{
	const size_t n = ec->f->n;
	// переменные в stack
	word* t1 = (word*)stack;
	word* t2 = t1 + n;
	word* t3 = t2 + n;
	word* t4 = t3 + n;
	stack = t4 + n;
	// pre
	ASSERT(ecIsOperable(ec) && ec->d == 3);
	ASSERT(ecpSeemsOn3(a, ec));
	ASSERT(ecpSeemsOn3(b, ec));
	ASSERT(wwIsSameOrDisjoint(a, c, 3 * n));
	ASSERT(wwIsSameOrDisjoint(b, c, 3 * n));
	// a == O => c <- b
	if (qrIsZero(ecZ(a, n), ec->f))
	{
		wwCopy(c, b, 3 * n);
		return;
	}
	// b == O => c <- a
	if (qrIsZero(ecZ(b, n), ec->f))
	{
		wwCopy(c, a, 3 * n);
		return;
	}
	// t1 <- za^2 [Z1Z1]
	qrSqr(t1, ecZ(a, n), ec->f, stack);
	// t2 <- zb^2 [Z2Z2]
	qrSqr(t2, ecZ(b, n), ec->f, stack);
	// t3 <- zb t2 [Z2 Z2Z2]
	qrMul(t3, ecZ(b, n), t2, ec->f, stack);
	// t3 <- ya t3 [Y1 Z2 Z2Z2 = S1]
	qrMul(t3, ecY(a, n), t3, ec->f, stack);
	// t4 <- za t1 [Z1 Z1Z1]
	qrMul(t4, ecZ(a, n), t1, ec->f, stack);
	// t4 <- yb t4 [Y2 Z1 Z1Z1 = S2]
	qrMul(t4, ecY(b, n), t4, ec->f, stack);
	// zc <- za + zb [Z1 + Z2]
	zmAdd(ecZ(c, n), ecZ(a, n), ecZ(b, n), ec->f);
	// zc <- zc^2 [(Z1 + Z2)^2]
	qrSqr(ecZ(c, n), ecZ(c, n), ec->f, stack);
	// zc <- zc - t1 [(Z1 + Z2)^2 - Z1Z1]
	zmSub(ecZ(c, n), ecZ(c, n), t1, ec->f);
	// zc <- zc - t2 [(Z1 + Z2)^2 - Z1Z1 - Z2Z2]
	zmSub(ecZ(c, n), ecZ(c, n), t2, ec->f);
	// t1 <- xb t1 [X1 Z2Z2 = U2]
	qrMul(t1, ecX(b), t1, ec->f, stack);
	// t2 <- xa t2 [X2 Z1Z1 = U1]
	qrMul(t2, ecX(a), t2, ec->f, stack);
	// t1 <- t1 - t2 [U2 - U1 = H]
	zmSub(t1, t1, t2, ec->f);
	// t1 == 0 => xa zb^2 == xb za^2
	if (qrIsZero(t1, ec->f))
	{
		// t3 == t4 => ya zb^3 == yb za^3 => a == b => c <- 2a
		if (qrCmp(t3, t4, ec->f) == 0)
			ecpDblJ(c, c == a ? b : a, ec, stack);
		// t3 != t4 => a == -b => c <- O
		else
			qrSetZero(ecZ(c, n), ec->f);
		return;
	}
	// zc <- zc t1 [((Z1 + Z2)^2 - Z1Z1 - Z2Z2)H = Z3]
	qrMul(ecZ(c, n), ecZ(c, n), t1, ec->f, stack);
	// t4 <- t4 - t3 [S2 - S1]
	zmSub(t4, t4, t3, ec->f);
	// t4 <- 2 t4 [2(S2 - S1) = r]
	gfpDouble(t4, t4, ec->f);
	// yc <- 2 t1 [2H]
	gfpDouble(ecY(c, n), t1, ec->f);
	// yc <- yc^2 [(2H)^2 = I]
	qrSqr(ecY(c, n), ecY(c, n), ec->f, stack);
	// t1 <- t1 yc [H I = J]
	qrMul(t1, t1, ecY(c, n), ec->f, stack);
	// yc <- t2 yc [U1 I = V]
	qrMul(ecY(c, n), t2, ecY(c, n), ec->f, stack);
	// t2 <- 2 yc [2 V]
	gfpDouble(t2, ecY(c, n), ec->f);
	// xc <- t4^2 [r^2]
	qrSqr(ecX(c), t4, ec->f, stack);
	// xc <- xc - t1 [r^2 - J]
	zmSub(ecX(c), ecX(c), t1, ec->f);
	// xc <- xc - t2 [r^2 - J - 2V = X3]
	zmSub(ecX(c), ecX(c), t2, ec->f);
	// yc <- yc - xc [V - X3]
	zmSub(ecY(c, n), ecY(c, n), ecX(c), ec->f);
	// yc <- t4 yc [r(V - X3)]
	qrMul(ecY(c, n), t4, ecY(c, n), ec->f, stack);
	// t3 <- 2 t3 [2S1]
	gfpDouble(t3, t3, ec->f);
	// t3 <- t3 t1 [2S1 J]
	qrMul(t3, t3, t1, ec->f, stack);
	// yc <- yc - t3 [r(V - X3) - 2 S1 J]
	zmSub(ecY(c, n), ecY(c, n), t3, ec->f);
}

static size_t ecpAddJ_deep(size_t n, size_t f_deep)
{
	return O_OF_W(4 * n) +
		utilMax(2,
			f_deep,
			ecpDblJ_deep(n, f_deep));
}

// [3n]c <- [3n]a + [2n]b (P <- P + A)
static void ecpAddAJ(word c[], const word a[], const word b[], const ec_o* ec,
	void* stack)
{
	const size_t n = ec->f->n;
	// переменные в stack
	word* t1 = (word*)stack;
	word* t2 = t1 + n;
	word* t3 = t2 + n;
	word* t4 = t3 + n;
	stack = t4 + n;
	// pre
	ASSERT(ecIsOperable(ec) && ec->d == 3);
	ASSERT(ecpSeemsOn3(a, ec));
	ASSERT(ecpSeemsOnA(b, ec));
	ASSERT(wwIsSameOrDisjoint(a,  c, 3 * n));
	ASSERT(b == c || wwIsDisjoint2(b, 2 * n, c, 3 * n));
	// a == O => c <- (xb : yb : 1)
	if (qrIsZero(ecZ(a, n), ec->f))
	{
		qrCopy(ecX(c), ecX(b), ec->f);
		qrCopy(ecY(c, n), ecY(b, n), ec->f);
		qrSetUnity(ecZ(c, n), ec->f);
		return;
	}
	// t1 <- za^2
	qrSqr(t1, ecZ(a, n), ec->f, stack);
	// t2 <- t1 za
	qrMul(t2, t1, ecZ(a, n), ec->f, stack);
	// t1 <- t1 xb
	qrMul(t1, t1, ecX(b), ec->f, stack);
	// t2 <- t2 yb
	qrMul(t2, t2, ecY(b, n), ec->f, stack);
	// t1 <- t1 - xa
	zmSub(t1, t1, ecX(a), ec->f);
	// t2 <- t2 - ya
	zmSub(t2, t2, ecY(a, n), ec->f);
	// t1 == 0?
	if (qrIsZero(t1, ec->f))
	{
		// t2 == 0 => c <- 2(xb : yb : 1)
		if (qrIsZero(t2, ec->f))
			ecpDblAJ(c, b, ec, stack);
		// t2 != 0 => c <- O
		else
			qrSetZero(ecZ(c, n), ec->f);
		return;
	}
	// zc <- t1 za
	qrMul(ecZ(c, n), t1, ecZ(a, n), ec->f, stack);
	// t3 <- t1^2
	qrSqr(t3, t1, ec->f, stack);
	// t4 <- t1 t3
	qrMul(t4, t1, t3, ec->f, stack);
	// t3 <- t3 xa
	qrMul(t3, t3, ecX(a), ec->f, stack);
	// t1 <- 2 t3
	gfpDouble(t1, t3, ec->f);
	// xc <- t2^2
	qrSqr(ecX(c), t2, ec->f, stack);
	// xc <- xc - t1
	zmSub(ecX(c), ecX(c), t1, ec->f);
	// xc <- xc - t4
	zmSub(ecX(c), ecX(c), t4, ec->f);
	// t3 <- t3 - xc
	zmSub(t3, t3, ecX(c), ec->f);
	// t3 <- t3 t2
	qrMul(t3, t3, t2, ec->f, stack);
	// t4 <- t4 ya
	qrMul(t4, t4, ecY(a, n), ec->f, stack);
	// yc <- t3 - t4
	zmSub(ecY(c, n), t3, t4, ec->f);
}

static size_t ecpAddAJ_deep(size_t n, size_t f_deep)
{
	return O_OF_W(4 * n) +
		utilMax(2,
			f_deep,
			ecpDblAJ_deep(n, f_deep));
}

// [3n]c <- [3n]a - [3n]b (P <- P - P)
void ecpSubJ(word c[], const word a[], const word b[], const ec_o* ec,
	void* stack)
{
	const size_t n = ec->f->n;
	// переменные в stack
	word* t = (word*)stack;
	stack = t + 3 * n;
	// pre
	ASSERT(ecIsOperable(ec) && ec->d == 3);
	ASSERT(ecpSeemsOn3(a, ec));
	ASSERT(ecpSeemsOn3(b, ec));
	ASSERT(wwIsSameOrDisjoint(a, c, 3 * n));
	ASSERT(wwIsSameOrDisjoint(b, c, 3 * n));
	// t <- -b
	qrCopy(ecX(t), ecX(b), ec->f);
	zmNeg(ecY(t, n), ecY(b, n), ec->f);
	qrCopy(ecZ(t, n), ecZ(b, n), ec->f);
	// c <- a + t
	ecpAddJ(c, a, t, ec, stack);
}

size_t ecpSubJ_deep(size_t n, size_t f_deep)
{
	return O_OF_W(3 * n) + ecpAddJ_deep(n, f_deep);
}

// [3n]c <- [3n]a - [2n]b (P <- P - A)
static void ecpSubAJ(word c[], const word a[], const word b[], const ec_o* ec,
	void* stack)
{
	const size_t n = ec->f->n;
	// переменные в stack
	word* t = (word*)stack;
	stack = t + 2 * n;
	// pre
	ASSERT(ecIsOperable(ec) && ec->d == 3);
	ASSERT(ecpSeemsOn3(a, ec));
	ASSERT(ecpSeemsOnA(b, ec));
	ASSERT(wwIsSameOrDisjoint(a,  c, 3 * n));
	ASSERT(b == c || wwIsDisjoint2(b, 2 * n, c, 3 * n));
	// t <- -b
	qrCopy(ecX(t), ecX(b), ec->f);
	zmNeg(ecY(t, n), ecY(b, n), ec->f);
	// c <- a + t
	ecpAddAJ(c, a, t, ec, stack);
}

static size_t ecpSubAJ_deep(size_t n, size_t f_deep)
{
	return O_OF_W(2 * n) + ecpAddAJ_deep(n, f_deep);
}

// [3n]b <- 3[3n]a (P <- 3P)
static void ecpTplJ(word b[], const word a[], const ec_o* ec, void* stack)
{
	const size_t n = ec->f->n;
	// переменные в stack
	word* t0 = (word*)stack;
	word* t1 = t0 + n;
	word* t2 = t1 + n;
	word* t3 = t2 + n;
	word* t4 = t3 + n;
	word* t5 = t4 + n;
	word* t6 = t5 + n;
	word* t7 = t6 + n;
	stack = t7 + n;
	// pre
	ASSERT(ecIsOperable(ec) && ec->d == 3);
	ASSERT(ecpSeemsOn3(a, ec));
	ASSERT(wwIsSameOrDisjoint(a, b, 3 * n));
	// t0 <- xa^2 [XX]
	qrSqr(t0, ecX(a), ec->f, stack);
	// t1 <- ya^2 [YY]
	qrSqr(t1, ecY(a, n), ec->f, stack);
	// t2 <- za^2 [ZZ]
	qrSqr(t2, ecZ(a, n), ec->f, stack);
	// t3 <- t1^2 [YYYY]
	qrSqr(t3, t1, ec->f, stack);
	// t4 <- 3 t0 + A t2^2 [M]
	qrSqr(t4, t2, ec->f, stack);
	qrMul(t4, t4, ec->A, ec->f, stack);
	gfpDouble(t5, t0, ec->f);
	zmAdd(t5, t0, t5, ec->f);
	zmAdd(t4, t4, t5, ec->f);
	// t5 <- t4^2 [MM]
	qrSqr(t5, t4, ec->f, stack);
	// t6 <- 6((xa + t1)^2 - t0 - t3) - t5 [E]
	zmAdd(t6, ecX(a), t1, ec->f);
	qrSqr(t6, t6, ec->f, stack);
	zmSub(t6, t6, t0, ec->f);
	zmSub(t6, t6, t3, ec->f);
	gfpDouble(t7, t6, ec->f);
	zmAdd(t6, t6, t7, ec->f);
	gfpDouble(t6, t6, ec->f);
	zmSub(t6, t6, t5, ec->f);
	// t7 <- t6^2 [EE]
	qrSqr(t7, t6, ec->f, stack);
	// t3 <- 16 t3 [T]
	gfpDouble(t3, t3, ec->f);
	gfpDouble(t3, t3, ec->f);
	gfpDouble(t3, t3, ec->f);
	gfpDouble(t3, t3, ec->f);
	// zb <- (za + t6)^2 - t2 - t7
	zmAdd(ecZ(b, n), ecZ(a, n), t6, ec->f);
	qrSqr(ecZ(b, n), ecZ(b, n), ec->f, stack);
	zmSub(ecZ(b, n), ecZ(b, n), t2, ec->f);
	zmSub(ecZ(b, n), ecZ(b, n), t7, ec->f);
	// t2 <- (t4 + t6)^2 - t5 - t7 - t3 [U]
	zmAdd(t2, t4, t6, ec->f);
	qrSqr(t2, t2, ec->f, stack);
	zmSub(t2, t2, t5, ec->f);
	zmSub(t2, t2, t7, ec->f);
	zmSub(t2, t2, t3, ec->f);
	// yb <- 8 ya (t2(t3 - t2) - t6 t7)
	zmSub(t3, t3, t2, ec->f);
	qrMul(t3, t2, t3, ec->f, stack);
	qrMul(t6, t6, t7, ec->f, stack);
	zmSub(t3, t3, t6, ec->f);
	qrMul(ecY(b, n), ecY(a, n), t3, ec->f, stack);
	gfpDouble(ecY(b, n), ecY(b, n), ec->f);
	gfpDouble(ecY(b, n), ecY(b, n), ec->f);
	gfpDouble(ecY(b, n), ecY(b, n), ec->f);
	// xb <- 4 (xa t7 - 4 t1 t2)
	qrMul(t1, t1, t2, ec->f, stack);
	gfpDouble(t1, t1, ec->f);
	gfpDouble(t1, t1, ec->f);
	qrMul(ecX(b), ecX(a), t7, ec->f, stack);
	zmSub(ecX(b), ecX(b), t1, ec->f);
	gfpDouble(ecX(b), ecX(b), ec->f);
	gfpDouble(ecX(b), ecX(b), ec->f);
}

static size_t ecpTplJ_deep(size_t n, size_t f_deep)
{
	return O_OF_W(8 * n) + f_deep;
}

// [3n]b <- 3[3n]a (P <- 3P)
static void ecpTplJA3(word b[], const word a[], const ec_o* ec, void* stack)
{
	const size_t n = ec->f->n;
	// переменные в stack
	word* t1 = (word*)stack;
	word* t2 = t1 + n;
	word* t3 = t2 + n;
	word* t4 = t3 + n;
	word* t5 = t4 + n;
	word* t6 = t5 + n;
	word* t7 = t6 + n;
	stack = t7 + n;
	// pre
	ASSERT(ecIsOperable(ec) && ec->d == 3);
	ASSERT(ecpSeemsOn3(a, ec));
	ASSERT(wwIsSameOrDisjoint(a, b, 3 * n));
	// t1 <- ya^2 [YY]
	qrSqr(t1, ecY(a, n), ec->f, stack);
	// t2 <- za^2 [ZZ]
	qrSqr(t2, ecZ(a, n), ec->f, stack);
	// t3 <- t1^2 [YYYY]
	qrSqr(t3, t1, ec->f, stack);
	// t4 <- 3(xa - t2)(xa + t2) [M]
	zmSub(t4, ecX(a), t2, ec->f);
	zmAdd(t5, ecX(a), t2, ec->f);
	qrMul(t4, t4, t5, ec->f, stack);
	gfpDouble(t5, t4, ec->f);
	zmAdd(t4, t4, t5, ec->f);
	// t5 <- t4^2 [MM]
	qrSqr(t5, t4, ec->f, stack);
	// t6 <- 12 xa t1 - t5 [E]
	qrMul(t6, ecX(a), t1, ec->f, stack);
	gfpDouble(t7, t6, ec->f);
	zmAdd(t6, t6, t7, ec->f);
	gfpDouble(t6, t6, ec->f);
	gfpDouble(t6, t6, ec->f);
	zmSub(t6, t6, t5, ec->f);
	// t7 <- t6^2 [EE]
	qrSqr(t7, t6, ec->f, stack);
	// t3 <- 16 t3 [T]
	gfpDouble(t3, t3, ec->f);
	gfpDouble(t3, t3, ec->f);
	gfpDouble(t3, t3, ec->f);
	gfpDouble(t3, t3, ec->f);
	// zb <- (za + t6)^2 - t2 - t7
	zmAdd(ecZ(b, n), ecZ(a, n), t6, ec->f);
	qrSqr(ecZ(b, n), ecZ(b, n), ec->f, stack);
	zmSub(ecZ(b, n), ecZ(b, n), t2, ec->f);
	zmSub(ecZ(b, n), ecZ(b, n), t7, ec->f);
	// t2 <- (t4 + t6)^2 - t5 - t7 - t3 [U]
	zmAdd(t2, t4, t6, ec->f);
	qrSqr(t2, t2, ec->f, stack);
	zmSub(t2, t2, t5, ec->f);
	zmSub(t2, t2, t7, ec->f);
	zmSub(t2, t2, t3, ec->f);
	// yb <- 8 ya (t2(t3 - t2) - t6 t7)
	zmSub(t3, t3, t2, ec->f);
	qrMul(t3, t2, t3, ec->f, stack);
	qrMul(t6, t6, t7, ec->f, stack);
	zmSub(t3, t3, t6, ec->f);
	qrMul(ecY(b, n), ecY(a, n), t3, ec->f, stack);
	gfpDouble(ecY(b, n), ecY(b, n), ec->f);
	gfpDouble(ecY(b, n), ecY(b, n), ec->f);
	gfpDouble(ecY(b, n), ecY(b, n), ec->f);
	// xb <- 4 (xa t7 - 4 t1 t2)
	qrMul(t1, t1, t2, ec->f, stack);
	gfpDouble(t1, t1, ec->f);
	gfpDouble(t1, t1, ec->f);
	qrMul(ecX(b), ecX(a), t7, ec->f, stack);
	zmSub(ecX(b), ecX(b), t1, ec->f);
	gfpDouble(ecX(b), ecX(b), ec->f);
	gfpDouble(ecX(b), ecX(b), ec->f);
}

size_t ecpTplJA3_deep(size_t n, size_t f_deep)
{
	return O_OF_W(7 * n) + f_deep;
}

void ecpDblAddA(word c[], const word a[], const word b[], bool_t neg_b, 
  const ec_o* ec, void* stack) 
{ 
	const size_t n = ec->f->n;
	// координаты b
	const word* tx = ecX(b);
	const word* ty = ecY(b, n);
	// переменные в stack
	word* t1 = (word*)stack;
	word* t2 = t1 + n;
	word* t3 = t2 + n;
	word* t4 = t3 + n;
	word* t5 = t4 + n;
	word* t6 = t5 + n;
	stack = t6 + n;
	// pre
	ASSERT(ecIsOperable(ec) && ec->d == 3);
	ASSERT(ecpSeemsOn3(a, ec));
	ASSERT(ecpSeemsOnA(b, ec));
	ASSERT(wwIsSameOrDisjoint(a, c, 3 * n));
	// todo: - P != Q?
	wwCopy(t1, ecX(a), n);
	wwCopy(t2, ecY(a, n), n);
	wwCopy(t3, ecZ(a, n), n);
	// 3: t4 <- t3^2
	qrSqr(t4, t3, ec->f, stack);
	// 4: t5 <- tx * t4
	qrMul(t5, tx, t4, ec->f, stack);
	// 5: t5 <- t5 - t1
	qrSub(t5, t5, t1, ec->f);
	// 6: t6 <- t3 + t5
	qrAdd(t6, t3, t5, ec->f);
	// 7: t6 <- t6^2
	qrSqr(t6, t6, ec->f, stack);
	// 8: t6 <- t6 - t4
	qrSub(t6, t6, t4, ec->f);
	// 9: t4 <- t3 * t4
	qrMul(t4, t3, t4, ec->f, stack);
	// 10: t4 <- ty * t4
	qrMul(t4, ty, t4, ec->f, stack);
	// 10.1: t4 <- (-1)^neg_b * t4
	zmSetSign(t4, t4, ec->f, neg_b);
	// 11: t4 <- t4 - t2
	qrSub(t4, t4, t2, ec->f);
	// 12: t3 <- t5^2
	t3 = ecZ(c, n);
	qrSqr(t3, t5, ec->f, stack);
	// 13: t6 <- t6 - t3
	qrSub(t6, t6, t3, ec->f);
	// 14: t1 <- t1 * t3
	qrMul(ecX(c), t1, t3, ec->f, stack);
	t1 = ecX(c);
	// 15: t1 <- 4t1
	gfpDouble(t1, t1, ec->f);
	gfpDouble(t1, t1, ec->f);
	// 16: t3 <- t3 * t5
	qrMul(t3, t3, t5, ec->f, stack);
	// 17: t2 <- t2 * t3
	qrMul(ecY(c, n), t2, t3, ec->f, stack);
	t2 = ecY(c, n);
	// 18: t2 <- 8t2
	gfpDouble(t2, t2, ec->f);
	gfpDouble(t2, t2, ec->f);
	gfpDouble(t2, t2, ec->f);
	// 19: t5 <- t4^2
	qrSqr(t5, t4, ec->f, stack);
	// 20: t3 <- t5 - t3
	qrSub(t3, t5, t3, ec->f);
	// 21: t3 <- 4t3
	gfpDouble(t3, t3, ec->f);
	gfpDouble(t3, t3, ec->f);
	// 22: t3 <- t3 - t1
	qrSub(t3, t3, t1, ec->f);
	// 23: t3 <- t3 - t1
	qrSub(t3, t3, t1, ec->f);
	// 24: t3 <- t3 - t1
	qrSub(t3, t3, t1, ec->f);
	// 25: t4 <- t3 + t4
	qrAdd(t4, t3, t4, ec->f);
	// 26: t4 <- t4^2
	qrSqr(t4, t4, ec->f, stack);
	// 27: t4 <- t5 - t4
	qrSub(t4, t5, t4, ec->f);
	// 28: t4 <- t4 - t2
	qrSub(t4, t4, t2, ec->f);
	// 29: t4 <- t4 - t2
	qrSub(t4, t4, t2, ec->f);
	// 30: t5 <- t3^2
	qrSqr(t5, t3, ec->f, stack);
	// 31: t4 <- t4 + t5
	qrAdd(t4, t4, t5, ec->f);
	// 32: t1 <- t1 * t5
	qrMul(t1, t1, t5, ec->f, stack);
	// 33: t5 <- t3 * t5
	qrMul(t5, t3, t5, ec->f, stack);
	// 34: t3 <- t3 * t6
	qrMul(t3, t3, t6, ec->f, stack);
	// 35: t2 <- t2 * t5
	qrMul(t2, t2, t5, ec->f, stack);
	// шаг 36 будет после шага 38
	// 37: t6 <- t4^2
	qrSqr(t6, t4, ec->f, stack);
	// 38: t6 <- t6 - t5
	qrSub(t6, t6, t5, ec->f);
	// 36: t5 <- 3t1
	gfpDouble(t5, t1, ec->f);
	qrAdd(t5, t5, t1, ec->f);
	// 39: t5 <- t5 - t6
	qrSub(t5, t5, t6, ec->f);
	// 40: t4 <- t4 * t5
	qrMul(t4, t4, t5, ec->f, stack);
	// 41: t2 <- t4 - t2
	qrSub(t2, t4, t2, ec->f);
	// 42: t1 <- t1 - t5
	qrSub(t1, t1, t5, ec->f);
}

size_t ecpDblAddA_deep(size_t n, size_t f_deep) 
{
	return O_OF_W(6 * n) + f_deep;
}

void ecpSetSignA(word b[], const word a[], bool_t neg, const ec_o* ec) 
{
	const size_t n = ec->f->n;
	// pre
	ASSERT(ecIsOperable(ec));
	ASSERT(ecpSeemsOnA(a, ec));
	ASSERT(wwIsSameOrDisjoint(a, b, 2 * n));
	// (xb, yb) <- (xa, -1^(neg + 1) * ya)
	qrCopy(ecX(b), ecX(a), ec->f);
	zmSetSign(ecY(b, n), ecY(a, n), ec->f, neg);
}


bool_t ecpCreateJ(ec_o* ec, const qr_o* f, const octet A[], const octet B[],
	void* stack)
{
	register bool_t bA3;
	word* t;
	// pre
	ASSERT(memIsValid(ec, sizeof(ec_o)));
	ASSERT(gfpIsOperable(f));
	ASSERT(memIsValid(A, f->no));
	ASSERT(memIsValid(B, f->no));
	// f->mod > 3?
	if (wwCmpW(f->mod, f->n, 3) <= 0)
		return FALSE;
	// обнулить
	memSetZero(ec, sizeof(ec_o));
	// зафикисровать размерности
	ec->d = 3;
	// запомнить базовое поле
	ec->f = f;
	// сохранить коэффициенты
	ec->A = (word*)ec->descr;
	ec->B = ec->A + f->n;
	if (!qrFrom(ec->A, A, ec->f, stack) || !qrFrom(ec->B, B, ec->f, stack))
		return FALSE;
	// t <- -3
	t = (word*)stack;
	gfpDouble(t, f->unity, f);
	zmAdd(t, t, f->unity, f);
	zmNeg(t, t, f);
	// bA3 <- A == -3?
	bA3 = qrCmp(t, ec->A, f) == 0;
	// подготовить буферы для описания группы точек
	ec->base = ec->B + f->n;
	ec->order = ec->base + 2 * f->n;
	// настроить интерфейсы
	ec->froma = ecpFromAJ;
	ec->toa = ecpToAJ;
	ec->neg = ecpNegJ;
	ec->nega = ecpNegA;
	ec->add = ecpAddJ;
	ec->adda = ecpAddAJ;
	ec->sub = ecpSubJ;
	ec->suba = ecpSubAJ;
	ec->dbl = bA3 ? ecpDblJA3 : ecpDblJ;
	ec->dbla = ecpDblAJ;
	ec->tpl = bA3 ? ecpTplJA3 : ecpTplJ;
	ec->dbl_adda = ecpDblAddA;
	ec->set_signa = ecpSetSignA;
	ec->deep = utilMax(9,
		ecpToAJ_deep(f->n, f->deep),
		ecpAddJ_deep(f->n, f->deep),
		ecpAddAJ_deep(f->n, f->deep),
		ecpSubJ_deep(f->n, f->deep),
		ecpSubAJ_deep(f->n, f->deep),
		bA3 ? ecpDblJA3_deep(f->n, f->deep) : ecpDblJ_deep(f->n, f->deep),
		ecpDblAJ_deep(f->n, f->deep),
		bA3 ? ecpTplJA3_deep(f->n, f->deep) : ecpTplJ_deep(f->n, f->deep),
		ecpDblAddA_deep(f->n, f->deep)
		);
	// настроить
	ec->hdr.keep = sizeof(ec_o) + O_OF_W(5 * f->n + 1);
	ec->hdr.p_count = 6;
	ec->hdr.o_count = 1;
	// все нормально
	bA3 = 0;
	return TRUE;
}

size_t ecpCreateJ_keep(size_t n)
{
	return sizeof(ec_o) + O_OF_W(5 * n + 1);
}

size_t ecpCreateJ_deep(size_t n, size_t f_deep)
{
	return utilMax(11,
		O_OF_W(n),
		ecpToAJ_deep(n, f_deep),
		ecpAddJ_deep(n, f_deep),
		ecpAddAJ_deep(n, f_deep),
		ecpSubJ_deep(n, f_deep),
		ecpSubAJ_deep(n, f_deep),
		ecpDblJ_deep(n, f_deep),
		ecpDblJA3_deep(n, f_deep),
		ecpDblAJ_deep(n, f_deep),
		ecpTplJ_deep(n, f_deep),
		ecpTplJA3_deep(n, f_deep));
}
