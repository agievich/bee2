/*
*******************************************************************************
\file ecp.c
\brief Elliptic curves over prime fields
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2012.06.26
\version 2021.06.30
\license This program is released under the GNU General Public License
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/mem.h"
#include "bee2/core/stack.h"
#include "bee2/core/util.h"
#include "bee2/math/ecp.h"
#include "bee2/math/gfp.h"
#include "bee2/math/pri.h"
#include "bee2/math/ww.h"
#include "bee2/math/zz.h"

/*
*******************************************************************************
Общие положения

Ссылки на все реализованные алгоритмы имеются на сайте
http://www.hyperelliptic.org/EFD. Там же можно найти соглашения по
обозначению сложности алгоритмов. В этих обозначениях фигурируют
следующие формальные выражения:
	add -- сложение или вычитание \mod p,
	c -- умножение на малую константу c (2,3,...) \mod p,
	half -- умножение на 2^{-1} \mod p,
	*A -- умножение на коэффициент A \mod p,
	S -- возведение в квадрат \mod p,
	M -- умножение \mod p,
	D -- деление \mod p.

При общей оценке сложности считается, что 1D = 100M и 1S = 1M.
Аддитивные операции игнорируются.

Используются обозначения:
	A <- A + A -- сложение аффинных точек,
	A <- 2A -- удвоение аффинной точки;
	P <- P + P -- сложение проективных точек;
	P <- P + A -- добавление к проективной точке аффинной;
	P <- 2P -- удвоение проективной точки;
	P <- 2A -- удвоение аффинной точки с переходом к проективным координатам.
*******************************************************************************
*/

#define ecpSeemsOnA(a, ec)\
	(zmIsIn(ecX(a), (ec)->f) && zmIsIn(ecY(a, (ec)->f->n), (ec)->f))

#define ecpSeemsOn3(a, ec)\
	(ecpSeemsOnA(a, ec) && zmIsIn(ecZ(a, (ec)->f->n), (ec)->f))

/*
*******************************************************************************
Якобиановы координаты:
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

void ecpDblAddA(word c[], const word a[], const word b[], bool_t neg_b, const struct ec_o* ec, void* stack) {
	//todo implement properly for ecp
	ecDblAddA(c, a, b, neg_b, ec, stack);
}

void ecpDblAddA_deep() {
	//todo implement properly for ecp
	return 0;
}

bool_t ecpDivp = TRUE;
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
	ec->smulsa = ecpDivp ? ecpSmallMultDivpA : ecSmallMultAdd2A;
	ec->smulsj = ecpDivp ? ecpSmallMultDivpJ : ecSmallMultAdd2J;
	ec->deep = utilMax(8,
		ecpToAJ_deep(f->n, f->deep),
		ecpAddJ_deep(f->n, f->deep),
		ecpAddAJ_deep(f->n, f->deep),
		ecpSubJ_deep(f->n, f->deep),
		ecpSubAJ_deep(f->n, f->deep),
		bA3 ? ecpDblJA3_deep(f->n, f->deep) : ecpDblJ_deep(f->n, f->deep),
		ecpDblAJ_deep(f->n, f->deep),
		bA3 ? ecpTplJA3_deep(f->n, f->deep) : ecpTplJ_deep(f->n, f->deep),
		ecpDblAddA_deep);
	ec->deep += utilMax(3,
		ecpDivp
		    ? ecpSmallMultDivpA_deep(TRUE, 6, f->n, f->deep)
     		: ecSmallMultAdd2A_deep(f->n, ec->deep),
		ecpDivp
		    ? ecpSmallMultDivpJ_deep(TRUE, 6, f->n, f->deep)
     		: ecSmallMultAdd2J_deep()
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

/*
*******************************************************************************
Свойства кривой
*******************************************************************************
*/

bool_t ecpIsValid(const ec_o* ec, void* stack)
{
	size_t n = ec->f->n;
	// переменные в stack
	word* t1 = (word*)stack;
	word* t2 = t1 + n;
	word* t3 = t2 + n;
	stack = t3 + n;
	// кривая работоспособна?
	// поле ec->f корректно?
	// f->mod > 3?
	// ec->deep >= ec->f->deep?
	// A, B \in ec->f?
	if (!ecIsOperable2(ec) ||
		!gfpIsValid(ec->f, stack) ||
		wwCmpW(ec->f->mod, ec->f->n, 3) <= 0 ||
		ec->deep < ec->f->deep ||
		!zmIsIn(ec->A, ec->f) ||
		!zmIsIn(ec->B, ec->f))
		return FALSE;
	// t1 <- 4 A^3
	qrSqr(t1, ec->A, ec->f, stack);
	qrMul(t1, t1, ec->A, ec->f, stack);
	gfpDouble(t1, t1, ec->f);
	gfpDouble(t1, t1, ec->f);
	// t3 <- 3 B^2
	qrSqr(t2, ec->B, ec->f, stack);
	gfpDouble(t3, t2, ec->f);
	zmAdd(t3, t3, t2, ec->f);
	// t2 <- 3 t3 [27 B^2]
	gfpDouble(t2, t3, ec->f);
	zmAdd(t2, t3, t2, ec->f);
	// t1 <- t1 + t2 [4 A^3 + 27 B^2 -- дискриминант]
	zmAdd(t1, t1, t2, ec->f);
	// t1 == 0 => сингулярная кривая
	return !qrIsZero(t1, ec->f);
}

size_t ecpIsValid_deep(size_t n, size_t f_deep)
{
	return O_OF_W(3 * n) +
		utilMax(2,
			f_deep,
			gfpIsValid_deep(n));
}

bool_t ecpSeemsValidGroup(const ec_o* ec, void* stack)
{
	size_t n = ec->f->n;
	int cmp;
	word w;
	// переменные в stack
	word* t1 = (word*)stack;
	word* t2 = t1 + n + 1;
	word* t3 = t2 + n + 2;
	stack = t3 + 2 * n;
	// pre
	ASSERT(ecIsOperable(ec));
	// ecIsOperableGroup(ec) == TRUE? base \in ec?
	if (!ecIsOperableGroup(ec) ||
		!ecpIsOnA(ec->base, ec, stack))
		return FALSE;
	// [n + 2]t1 <- order * cofactor
	t1[n + 1] = zzMulW(t1, ec->order, n + 1, ec->cofactor);
	// t1 <- |t1 - (p + 1)|
	if (zzSubW2(t1, n + 2, 1))
		return FALSE;
	if (wwCmp2(t1, n + 2, ec->f->mod, n) >= 0)
		zzSubW2(t1 + n, 2, zzSub2(t1, ec->f->mod, n));
	else
		zzSub(t1, ec->f->mod, t1, n);
	// n <- длина t1
	n = wwWordSize(t1, n + 2);
	// n > ec->f->n => t1^2 > 4 p
	if (n > ec->f->n)
		return FALSE;
	// [2n]t2 <- ([n]t1)^2
	zzSqr(t2, t1, n, stack);
	// условие Хассе: t2 <= 4 p?
	w = wwGetBits(t2, 0, 2);
	wwShLo(t2, 2 * n, 2);
	cmp = wwCmp2(t2, 2 * n, ec->f->mod, ec->f->n);
	if (cmp > 0 || cmp == 0 && w != 0)
		return FALSE;
	// все нормально
	return TRUE;
}

size_t ecpSeemsValidGroup_deep(size_t n, size_t f_deep)
{
	return O_OF_W(4 * n + 3) +
		utilMax(2,
			ecpIsOnA_deep(n, f_deep),
			zzSqr_deep(n));
}

bool_t ecpIsSafeGroup(const ec_o* ec, size_t mov_threshold, void* stack)
{
	size_t n1 = ec->f->n + 1;
	// переменные в stack
	word* t1 = (word*)stack;
	word* t2 = t1 + n1;
	stack = t2 + n1;
	// pre
	ASSERT(ecIsOperable(ec));
	ASSERT(ecIsOperableGroup(ec));
	// order -- простое?
	n1 = wwWordSize(ec->order, n1);
	if (!priIsPrime(ec->order, n1, stack))
		return FALSE;
	// order == p?
	if (wwCmp2(ec->f->mod, ec->f->n, ec->order, n1) == 0)
		return FALSE;
	// проверка MOV
	if (mov_threshold)
	{
		zzMod(t1, ec->f->mod, ec->f->n, ec->order, n1, stack);
		wwCopy(t2, t1, n1);
		if (wwCmpW(t2, n1, 1) == 0)
			return FALSE;
		while (--mov_threshold)
		{
			zzMulMod(t2, t2, t1, ec->order, n1, stack);
			if (wwCmpW(t2, n1, 1) == 0)
				return FALSE;
		}
	}
	// все нормально
	return TRUE;
}

size_t ecpIsSafeGroup_deep(size_t n)
{
	const size_t n1 = n + 1;
	return O_OF_W(2 * n1) +
		utilMax(3,
			priIsPrime_deep(n1),
			zzMod_deep(n, n1),
			zzMulMod_deep(n1));
}

/*
*******************************************************************************
Арифметика аффинных точек

Сложение A <- A + A:
	1D + 1S + 1M + 6add \approx 102M

Удвоение A <- 2A:
	1D + 2S + 1M + 5add + 1*3 + 1*2 \approx 103M
*******************************************************************************
*/

bool_t ecpIsOnA(const word a[], const ec_o* ec, void* stack)
{
	const size_t n = ec->f->n;
	// переменные в stack
	word* t1 = (word*)stack;
	word* t2 = t1 + n;
	stack = t2 + n;
	// pre
	ASSERT(ecIsOperable(ec));
	// xa, ya \in ec->f?
	if (!zmIsIn(ecX(a), ec->f) || !zmIsIn(ecY(a, n), ec->f))
		return FALSE;
	// t1 <- (xa^2 + A)xa + B
	qrSqr(t1, ecX(a), ec->f, stack);
	zmAdd(t1, t1, ec->A, ec->f);
	qrMul(t1, t1, ecX(a), ec->f, stack);
	zmAdd(t1, t1, ec->B, ec->f);
	// t2 <- ya^2
	qrSqr(t2, ecY(a, n), ec->f, stack);
	// t1 == t2?
	return qrCmp(t1, t2, ec->f) == 0;
}

size_t ecpIsOnA_deep(size_t n, size_t f_deep)
{
	return O_OF_W(2 * n) + f_deep;
}

void ecpNegA(word b[], const word a[], const ec_o* ec)
{
	const size_t n = ec->f->n;
	// pre
	ASSERT(ecIsOperable(ec));
	ASSERT(ecpSeemsOnA(a, ec));
	ASSERT(wwIsSameOrDisjoint(a, b, 2 * n));
	// (xb, yb) <- (xa, -ya)
	qrCopy(ecX(b), ecX(a), ec->f);
	zmNeg(ecY(b, n), ecY(a, n), ec->f);
}

bool_t ecpAddAA(word c[], const word a[], const word b[], const ec_o* ec,
	void* stack)
{
	const size_t n = ec->f->n;
	// переменные в stack
	word* t1 = (word*)stack;
	word* t2 = t1 + n;
	word* t3 = t2 + n;
	stack = t3 + n;
	// pre
	ASSERT(ecIsOperable(ec));
	ASSERT(ecpSeemsOnA(a, ec));
	ASSERT(ecpSeemsOnA(b, ec));
	// xa != xb?
	if (qrCmp(ecX(a), ecX(b), ec->f) != 0)
	{
		// t1 <- xa - xb
		zmSub(t1, ecX(a), ecX(b), ec->f);
		// t2 <- ya - yb
		zmSub(t2, ecY(a, n), ecY(b, n), ec->f);
	}
	else
	{
		// ya != yb или yb == 0 => a == -b => a + b == O
		if (qrCmp(ecY(a, n), ecY(b, n), ec->f) != 0 ||
			qrIsZero(ecY(b, n), ec->f))
			return FALSE;
		// t2 <- 3 xa^2 + A
		qrSqr(t1, ecX(a), ec->f, stack);
		gfpDouble(t2, t1, ec->f);
		zmAdd(t2, t2, t1, ec->f);
		zmAdd(t2, t2, ec->A, ec->f);
		// t1 <- 2 ya
		gfpDouble(t1, ecY(a, n), ec->f);
	}
	// t2 <- t2 / t1 = \lambda
	qrDiv(t2, t2, t1, ec->f, stack);
	// t1 <- \lambda^2 - xa - xb = xc
	qrSqr(t1, t2, ec->f, stack);
	zmSub(t1, t1, ecX(a), ec->f);
	zmSub(t1, t1, ecX(b), ec->f);
	// t3 <- xa - xc
	zmSub(t3, ecX(a), t1, ec->f);
	// t2 <- \lambda(xa - xc) - ya
	qrMul(t2, t2, t3, ec->f, stack);
	zmSub(t2, t2, ecY(a, n), ec->f);
	// выгрузить результат
	qrCopy(ecX(c), t1, ec->f);
	qrCopy(ecY(c, n), t2, ec->f);
	return TRUE;
}

size_t ecpAddAA_deep(size_t n, size_t f_deep)
{
	return O_OF_W(3 * n) + f_deep;
}

bool_t ecpSubAA(word c[], const word a[], const word b[], const ec_o* ec,
	void* stack)
{
	const size_t n = ec->f->n;
	// переменные в stack
	word* t1 = (word*)stack;
	word* t2 = t1 + n;
	word* t3 = t2 + n;
	stack = t3 + n;
	// pre
	ASSERT(ecIsOperable(ec));
	ASSERT(ecpSeemsOnA(a, ec));
	ASSERT(ecpSeemsOnA(b, ec));
	// xa != xb?
	if (qrCmp(ecX(a), ecX(b), ec->f) != 0)
	{
		// t1 <- xa - xb
		zmSub(t1, ecX(a), ecX(b), ec->f);
		// t2 <- ya + yb
		zmAdd(t2, ecY(a, n), ecY(b, n), ec->f);
	}
	else
	{
		// ya == yb => a == b => a - b == O
		if (qrCmp(ecY(a, n), ecY(b, n), ec->f) == 0)
			return FALSE;
		// здесь должно быть a == -b => a - b = 2a
		// t2 <- 3 xa^2 + A
		qrSqr(t1, ecX(a), ec->f, stack);
		gfpDouble(t2, t1, ec->f);
		zmAdd(t2, t2, t1, ec->f);
		zmAdd(t2, t2, ec->A, ec->f);
		// t1 <- 2 ya
		gfpDouble(t1, ecY(a, n), ec->f);
	}
	// t2 <- t2 / t1 = \lambda
	qrDiv(t2, t2, t1, ec->f, stack);
	// t1 <- \lambda^2 - xa - xb = xc
	qrSqr(t1, t2, ec->f, stack);
	zmSub(t1, t1, ecX(a), ec->f);
	zmSub(t1, t1, ecX(b), ec->f);
	// t3 <- xa - xc
	zmSub(t3, ecX(a), t1, ec->f);
	// t2 <- \lambda(xa - xc) - ya
	qrMul(t2, t2, t3, ec->f, stack);
	zmSub(t2, t2, ecY(a, n), ec->f);
	// выгрузить результат
	qrCopy(ecX(c), t1, ec->f);
	qrCopy(ecY(c, n), t2, ec->f);
	return TRUE;
}

size_t ecpSubAA_deep(size_t n, size_t f_deep)
{
	return O_OF_W(3 * n) + f_deep;
}

/*
*******************************************************************************
Алгоритм SWU

\todo Регуляризировать (qrIsUnitySafe).
*******************************************************************************
*/

void ecpSWU(word b[], const word a[], const ec_o* ec, void* stack)
{
	const size_t n = ec->f->n;
	register size_t mask;
	// переменные в stack [x2 после x1, s после y!]
	word* t = (word*)stack;
	word* x1 = t + n;
	word* x2 = x1 + n;
	word* y = x2 + n;
	word* s = y + n;
	stack = s + n;
	// pre
	ASSERT(ecIsOperable(ec));
	ASSERT(zmIsIn(a, ec->f));
	ASSERT(wwGetBits(ec->f->mod, 0, 2) == 3);
	ASSERT(!qrIsZero(ec->A, ec->f) && !qrIsZero(ec->B, ec->f));
	// t <- -a^2
	qrSqr(t, a, ec->f, stack);
	zmNeg(t, t, ec->f);
	// s <- p - 2
	wwCopy(s, ec->f->mod, n);
	zzSubW2(s, n, 2);
	// x1 <- -B(1 + t + t^2)(A(t + t^2))^{p - 2}
	qrSqr(x2, t, ec->f, stack);
	qrAdd(x2, x2, t, ec->f);
	qrMul(x1, x2, ec->A, ec->f, stack);
	qrPower(x1, x1, s, n, ec->f, stack);
	qrAddUnity(x2, x2, ec->f);
	qrMul(x1, x1, x2, ec->f, stack);
	qrMul(x1, x1, ec->B, ec->f, stack);
	zmNeg(x1, x1, ec->f);
	// y <- (x1)^3 + A x1 + B
	qrSqr(x2, x1, ec->f, stack);
	qrMul(x2, x2, x1, ec->f, stack);
	qrMul(y, x1, ec->A, ec->f, stack);
	qrAdd(y, y, x2, ec->f);
	qrAdd(y, y, ec->B, ec->f);
	// x2 <- x1 t
	qrMul(x2, x1, t, ec->f, stack);
	// t <- y^{(p - 1) - (p + 1) / 4} = y^{s - (p - 3) / 4}
	wwCopy(t, ec->f->mod, n);
	wwShLo(t, n, 2);
	zzSub(s, s, t, n);
	qrPower(t, y, s, n, ec->f, stack);
	// s <- a^3 y
	qrSqr(s, a, ec->f, stack);
	qrMul(s, s, a, ec->f, stack);
	qrMul(s, s, y, ec->f, stack);
	// mask <- t^2 y == 1 ? 0 : -1;
	qrSqr(b, t, ec->f, stack);
	qrMul(b, b, y, ec->f, stack);
	mask = qrIsUnity(b, ec->f) - SIZE_1;
	// b <- mask == 0 ? (x1, t y) : (x2, t s)
	qrCopy(ecX(b), x1 + (mask & n), ec->f);
	qrMul(ecY(b, n), t, y + (mask & n), ec->f, stack);
	// очистка
	mask = 0;
}

size_t ecpSWU_deep(size_t n, size_t f_deep)
{
	return O_OF_W(5 * n) +
		utilMax(2,
			f_deep,
			qrPower_deep(n, n, f_deep));
}

#if 0
/*
*******************************************************************************

Вычисление малых кратных в афинных координатах с помощью полиномов деления.

Входная точка [2n]a в афинных коордитанах

w - ширина окна. Вообще говоря, зависит только от стойкости. (Сохранить значеие в кривой ec_o для предвычисленных малых кратных?)

sm_mults - выходной массив малых кратных X3,Y3,X5,Y5... в афинных координатах

\safe алгоритм регулярен

*******************************************************************************
*/
bool_t smMultsA_divPoly(word* sm_mults, const word a[], const word w, const ec_o* ec, void* stack)
{
	//todo проверки?
	const word ec_f_n = ec->f->n;
	const word aff_point_size = ec->f->n * 2;
	size_t i;
	size_t t;
	word* x = ecX(a);
	word* y = ecY(a, ec->f->n);
	word* xx;
	word* bx;
	word* aa;
	word* bb;
	word* ax;
	word* xxx;
	word* dblYSq;

	word* tmp;
	word* tmp2;

	word* W;				//полиномы деления начиная с третьего, W[0] = W_3
	word* WW;				//квадраты полиномов деления начиная c третьего
	word* WWd2;				//произведения W_{n}W_{n+2}, c n = 1
	word* WWd2_dblYSq;		//произведения (2y)^2 W_{n}W_{n+2}, начиная с n = 2
	word* WWd2_dblYPow4;	//значения (2y)^4 W_{n}W_{n+2}, начиная с n = 2
	word* WW_odd_inv;	    //обратные к нечетным квадратам полиномов деления: W_{n}^{-2}, n = 3, 5, ...

	const int W_idx_shift = -3;
	const int WW_idx_shift = -3;
	const int WWd2_idx_shift = -1;
	const int WWd2_dblYSq_idx_shift = -2;
	const int WWd2_dblYPow4_idx_shift = -2;


	//раскладка в stack
	xx = (word*)stack;
	bx = xx + ec->f->n;
	aa = bx + ec->f->n;
	bb = aa + ec->f->n;
	ax = bb + ec->f->n;
	xxx = ax + ec->f->n;
	dblYSq = xxx + ec->f->n;
	tmp = dblYSq + ec->f->n;
	tmp2 = tmp + ec->f->n;

	//todo посчитать количество элементов
	W = tmp2 + ec->f->n * ;
	WW = W + ec->f->n*;
	WWd2 = WW + ec->f->n* ;
	WWd2_dblYSq = WWd2 + ec->f->n* ;
	WWd2_dblYPow4 = WWd2_dblYSq + ec->f->n* ;
	WW_odd_inv = WWd2_dblYPow4 + ec->f->n*;
	stack = WW_odd_inv + ec->f->n*;

	//Вспомогательные значения
	ec_f_n = ec->f->n;
	qrSqr(xx, x, ec->f, stack);
	qrMul(bx, ec->B, x, ec->f, stack);
	qrSqr(aa, ec->A, ec->f, stack);
	qrSqr(bb, ec->B, ec->f, stack);
	qrMul(ax, ec->A, x, ec->f, stack);
	qrMul(xxx, xx, x, ec->f, stack);

	gfpDouble(dblYSq, y, ec->f);
	qrSqr(dblYSq, dblYSq, ec->f, stack);

	//Вычислить W_3 = 3 (x^2 + a)^2 − 4 (a^2 − 3 bx)
	qrAdd(tmp, xx, ec->A, ec->f);  // x^2 + a
	qrSqr(tmp, tmp, ec->f, stack);		  // (x^2 + a)^2
	gfpDouble(tmp2, tmp, ec->f);   // 2 (x^2 + a)^2
	qrAdd(W, tmp, tmp2, ec->f);    // 3 (x^2 + a)^2

	gfpDouble(tmp, bx, ec->f);	  //2 bx
	qrAdd(tmp, tmp, bx, ec->f);	  //3 bx
	qrSub(tmp, aa, tmp, ec->f);   //a^2 − 3 bx
	gfpDouble(tmp, tmp, ec->f);	  //2 (a^2 − 3 bx)
	gfpDouble(tmp, tmp, ec->f);	  //4 (a^2 − 3 bx)

	qrSub(W, W, tmp, ec->f);	  //W_3 = 3 (x^2 + a)^2 − 4 (a^2 − 3 bx)

	//Вычислить W_4
	qrSqr(W + ec_f_n, xxx, ec->f, stack);		//(x^3)^2

	gfpDouble(tmp, xx, ec->f);					//2 x^2
	gfpDouble(tmp, tmp, ec->f);					//4 x^2
	qrAdd(tmp, tmp, xx, ec->f);					//5 x^2
	qrSub(tmp, tmp, ec->A, ec->f);				//5 x^2 - a
	qrMul(tmp, bx, tmp, ec->f, stack);			//bx (5 x^2 - a)
	gfpDouble(tmp, tmp, ec->f);					//2 bx (5 x^2 - a)
	gfpDouble(tmp, tmp, ec->f);					//4 bx (5 x^2 - a)

	qrAdd(W + ec->f->n, W + ec_f_n, tmp, ec->f); //(x^3)^2 + 4 bx (5 x^2 - a)

	qrSub(tmp, xxx, ax, ec->f);					//x^3 - ax
	qrMul(tmp, tmp, ax, ec->f, stack);			//ax (x^3 - ax)
	gfpDouble(tmp2, tmp, ec->f);				//2 ax (x^3 - ax)
	gfpDouble(tmp2, tmp2, ec->f);				//4 ax (x^3 - ax)
	qrAdd(tmp, tmp, tmp2, ec->f);				//5 ax (x^3 - ax)

	qrAdd(W + ec_f_n, W + ec_f_n, tmp, ec->f); //(x^3)^2 + 4 bx (5 x^2 - a) + 5 ax (x^3 - ax)

	gfpDouble(tmp, bb, ec->f);					//2 b^2
	gfpDouble(tmp, tmp, ec->f);					//4 b^2
	gfpDouble(tmp, tmp, ec->f);					//8 b^2

	qrSub(W + ec_f_n, W + ec_f_n, tmp, ec->f); //(x^3)^2 + 4 bx (5 x^2 - a) + 5 ax (x^3 - ax) - 8 b^2

	qrMul(tmp, aa, a, ec->f, stack);				//a^3

	qrSub(W + ec_f_n, W + ec_f_n, tmp, ec->f); //(x^3)^2 + 4 bx (5 x^2 - a) + 5 ax (x^3 - ax) - 8 b^2 - a^3

	gfpDouble(W + ec_f_n, W + ec_f_n, ec->f);	//W_4 = 2 ((x^3)^2 + 4 bx (5 x^2 - a) + 5 ax (x^3 - ax) - 8 b^2 - a^3)


	//(2y)^2
	gfpDouble(dblYSq, y, ec->f);
	qrSqr(dblYSq, dblYSq, ec->f, stack);

	//(W_3)^2
	qrSqr(WW, W, ec->f, stack);

	//(W_4)^2
	qrSqr(WW + ec_f_n, W + ec_f_n, ec->f, stack);

	//W_{1}W_{3} = W{3}
	qrCopy(WWd2, W, ec->f);

	//W_{2}W_{4} = W{4}
	qrCopy(WWd2 + ec_f_n, w + ec_f_n, ec->f);

	//[(2y)2W2W4]
	qrMul(WWd2_dblYSq, WWd2 + ec_f_n, dblYSq, ec->f, stack);

	//[(2y)4W2W4]
	qrMul(WWd2_dblYPow4, WWd2_dblYSq, dblYSq, ec->f, stack);

	//[W5] ← [(2y)4W2W4] −[W1W3] ·[W_{3}^2]
	qrMul(tmp, WWd2, WW, ec->f, stack);
	qrSub(W + 2 * ec_f_n, WWd2_dblYPow4, tmp, ec->f, stack);

	//[W5 ^2] ←([W5])2
	qrSqr(WW + 2 * ec_f_n, W + 2 * ec_f_n, ec->f, stack);

	//i 3 = .. 2^{w-1}
	t = (SIZE_1 << (w - 1));
	for (i = 3; i <= t; ++i)
	{
		//[WnWn+2] ← (([Wn] + [Wn+2])^2 − [W2n] −[W2 n + 2]) / 2
		qrAdd(tmp, W + ec_f_n * (i + W_idx_shift), W + ec_f_n * (i + W_idx_shift + 2), ec->f, stack);
		qrSqr(tmp, tmp, ec->f, stack);
		qrSub(tmp, tmp, WW + ec_f_n * (i + WW_idx_shift), ec->f);
		qrSub(tmp, tmp, WW + ec_f_n * (i + WW_idx_shift + 2), ec->f);
		gfpHalf(WWd2 + ec_f_n * (i-1), tmp, ec->f);

		if (i == 3)
		{
			//[W2n] ← [WnWn+2] − [Wn−2Wn] · [W2 n + 1]: 1M + 1A
			qrMul(tmp, WWd2  + ec_f_n * (i + WWd2_idx_shift - 2), WW + ec_f_n * (i + WW_idx_shift + 1), ec->f, stack);
			qrSub(W + ec_f_n * (2 * i + W_idx_shift), WWd2 + ec_f_n * (i - 1), tmp, ec->f, stack);
		}
		else
		{
			//[W2n] ← [WnWn+2] · [W2 n−1] −[Wn−2Wn] ·[W2 n + 1]
			qrMul(tmp, WWd2 + ec_f_n * (i + WWd2_idx_shift - 2), WW + ec_f_n * (i + WW_idx_shift + 1), ec->f, stack);
			qrMul(tmp2, WWd2 + ec_f_n * (i + WWd2_idx_shift), WW + ec_f_n * (i + WW_idx_shift - 1), ec->f, stack);
			qrSub(W + ec_f_n * (2 * i + W_idx_shift), tmp2, tmp, ec->f, stack);
		}

		//i нечетное?
		if (i & 1 == 1)
		{
			//[W2n+1] ← [WnWn+2] · [W2 n] − [(2y)4Wn−1Wn + 1] ·[W2 n + 1]
			qrMul(tmp, WWd2 + ec_f_n * (i + WWd2_idx_shift), WW + ec_f_n * (i + WW_idx_shift), ec->f, stack);
			qrMul(tmp2, WWd2_dblYPow4 + ec_f_n * (i + WWd2_dblYPow4_idx_shift - 1), WW + ec_f_n * (i + WW_idx_shift + 1), ec->f, stack);
			qrSub(W + ec_f_n * (2*i + 1 + W_idx_shift), tmp, tmp2, ec->f);
 		}
		else
		{
			//(a) [(2y)2WnWn + 2] ←[(2y)2] ·[WnWn + 2]: 1M
			qrMul(WWd2_dblYSq + ec_f_n * (i + WWd2_dblYSq_idx_shift), dblYSq, WWd2 + ec_f_n * (i + WWd2_idx_shift), ec->f, stack);

			//(b)[(2y)4WnWn + 2] ←[(2y)2] ·[(2y)2WnWn + 2]: 1M
			qrMul(WWd2_dblYPow4 + ec_f_n * (i + WWd2_dblYPow4_idx_shift), dblYSq, WWd2_dblYSq + ec_f_n * (i + WWd2_dblYSq_idx_shift), ec->f, stack);

			//(c) [W2n+1] ← [(2y)4WnWn + 2] ·[W2n] −[Wn−1Wn + 1] ·[W2 n + 1]: 2M + 1A
			qrMul(tmp, WWd2_dblYPow4 + ec_f_n * (i + WWd2_dblYPow4_idx_shift), WW + ec_f_n * (i + WW_idx_shift), ec->f, stack);
			qrMul(tmp2, WWd2 + ec_f_n * (i - 1 + WWd2_idx_shift), WW + ec_f_n * (i + WW_idx_shift + 1), ec->f, stack);
			qrSub(W + ec_f_n * (2 * i + 1 + W_idx_shift), tmp, tmp2, ec->f);
		}

		if (i != t)
		{
			//[W2 2n + 1] ←([W2n + 1])2
			qrSqr(WW + ec_f_n * (2 * i + 1 + WW_idx_shift), W + ec_f_n * (2 * i + 1 + W_idx_shift), ec->f, stack);
		}
	}

	//обратить квадраты нечетных малых кратных
	for (i = 0; i < t; ++i)
	{
		//WW_odd_inv <- W_n^2, n = 3, 5, ... 2^w - 1
		qrCopy(WW_odd_inv + ec_f_n * i, WW + ec_f_n * (i * 2 + 3 + WW_idx_shift), ec->f);
	}
	//WW_odd_inv <- W_n^(-2), n = 3, 5, ... 2^w - 1
	qrMontInv(WW_odd_inv, WW_odd_inv, t - 1, ec->f, stack);

	for (int i = 3; i <= t + 1; i += 2)
	{
		//[X'n] ← x −[(2y)2 Wn−1Wn + 1] ·[W−2 n]
		qrMul(tmp, WWd2_dblYSq + ec_f_n * (i - 1 + WWd2_dblYSq_idx_shift), WW_odd_inv + ec_f_n * ((i - 3) / 2), ec->f, stack);
		qrSub(ecX(sm_mults + aff_point_size * ((i - 3) / 2)), x, tmp, ec->f);
	}

	for (int i = t + 3; i <= t * 2 - 1; i += 2)
	{
		//tmp ←(([Wn−1] + [Wn + 1])2 −[W2 n−1] −[W2n + 1]) / 2
		qrAdd(tmp, W + ec_f_n * (i - 1 + W_idx_shift), W + ec_f_n * (i + 1 + W_idx_shift), ec->f, stack);
		qrSqr(tmp, tmp, ec->f, stack);
		qrSub(tmp, tmp, WW + ec_f_n * (i - 1 + WW_idx_shift), ec->f);
		qrSub(tmp, tmp, WW + ec_f_n * (i + 1 + WW_idx_shift ), ec->f);
		gfpHalf(tmp, tmp, ec->f);

		//[X'n] ← x −[(2y)2] · tmp ·[W−2 n]
		qrMul(tmp, tmp, WW_odd_inv + ec_f_n * ((i - 3) / 2), ec->f, stack);
		qrMul(tmp, dblYSq, tmp, ec->f, stack);
		qrSub(ecX(sm_mults + aff_point_size * ((i - 3) / 2)), x, tmp, ec->f);
	}

	for (i = 3; i <= t - 1; i += 2)
	{
		//. [Y'n] ← y ·[W2n] ·([W−2 n])2
		qrSqr(tmp, WW_odd_inv + ec_f_n * ((i - 3) / 2), ec->f, stack);
		qrMul(tmp, tmp, W + ec_f_n * (2 * i + W_idx_shift), ec->f, stack);
		qrMul(ecY(sm_mults + aff_point_size * ((i - 3) / 2), ec_f_n), tmp, y, ec->f, stack);
	}

	for (i = t + 1; i <= t * 2 - 3; i += 2)
	{
		//[WnWn+2] ← (([Wn] + [Wn+2])^2 − [W2n] −[W2 n + 2]) / 2
		qrAdd(tmp, W + ec_f_n * (i + W_idx_shift), W + ec_f_n * (i + W_idx_shift + 2), ec->f, stack);
		qrSqr(tmp, tmp, ec->f, stack);
		qrSub(tmp, tmp, WW + ec_f_n * (i + WW_idx_shift), ec->f);
		qrSub(tmp, tmp, WW + ec_f_n * (i + WW_idx_shift + 2), ec->f);
		gfpHalf(WWd2 + ec_f_n * (i - 1), tmp, ec->f);

		//tmp2 ← [WnWn+2] · [W2 n−1] −[Wn−2Wn] ·[W2 n + 1]
		qrMul(tmp, WWd2 + ec_f_n * (i + WWd2_idx_shift - 2), WW + ec_f_n * (i + WW_idx_shift + 1), ec->f, stack);
		qrMul(tmp2, WWd2 + ec_f_n * (i + WWd2_idx_shift), WW + ec_f_n * (i + WW_idx_shift - 1), ec->f, stack);
		qrSub(tmp2, tmp2, tmp, ec->f, stack);

		//[Y'n] ← y · tmp2 ·([W−2 n])2
		qrSqr(tmp, WW_odd_inv + ec_f_n * ((i - 3) / 2), ec->f, stack);
		qrMul(tmp, tmp, tmp2, ec->f, stack);
		qrMul(ecY(sm_mults + aff_point_size * ((i - 3) / 2), ec_f_n), tmp, y, ec->f, stack);
	}

	i = t * 2 - 1;
	//[Y'2w−1] ← y·([W2w−1]·[W2w + 1]·[W2 2w−2]−[W2w−3W2w−1]·[W2 2w])·([W−2 2w−1])2

	//tmp <- [W2w−1]·[W2w + 1]·[W2 2w−2]
	qrMul(tmp, W + ec_f_n * (i + W_idx_shift), W + ec_f_n * (i + W_idx_shift + 2), ec->f, stack);
	qrMul(tmp, tmp, WW + ec_f_n * (i + WW_idx_shift - 1), ec->f, stack);

	//tmp2 <-[W_2w−3 W_2w−1]·[W2 2w]
	qrMul(tmp2, WWd2 + ec_f_n * (i + WWd2_idx_shift - 2), WW + ec_f_n * (i + WW_idx_shift + 1), ec->f, stack);

	//tmp <- ([W 2w−1]·[W 2w + 1]·[W2 2w−2]−[W 2w−3 W 2w−1]·[W2 2w]) = tmp - tmp2
	qrSub(tmp, tmp, tmp2, ec->f);

	//[Y'2w−1] ← y·tmp·tmp2
	qrMul(tmp, tmp, tmp2, ec->f, stack);
	qrMul(ecY(sm_mults + aff_point_size * ((i - 3) / 2), ec_f_n), tmp, y, ec->f, stack);

	//todo cleanup
}
#endif

#ifdef _DEBUG
#define stack_walloc(p, k)					\
	do {									\
		*(word*)(stack) = (word)(k);		\
		*((word*)(stack) + 1) = 0xfeedbeef;	\
		(p) = (word*)(stack) + 2;			\
		*((word*)(stack) + 2) = 0xbeeffeed;	\
		stack = (word*)(stack) + 3 + (k);	\
		*((word*)(stack) - 2) = 0xfeedbeef;	\
		*((word*)(stack) - 1) = 0xbeeffeed;	\
	} while(0)
#define stack_wfree(p)														\
	do {																	\
		ASSERT(*((word*)(p) - 1) == 0xfeedbeef);							\
		ASSERT(*((word*)(p)) != 0xbeeffeed);								\
		ASSERT(stack == ((word*)(p) + 1 + (size_t)*((word*)(p)-2)));		\
		ASSERT(*((word*)(p) + (size_t)*((word*)(p)-2) - 1) != 0xfeedbeef);	\
		ASSERT(*((word*)(p) + (size_t)*((word*)(p)-2)) == 0xbeeffeed);		\
		stack = (word*)(p) - 2;												\
	} while(0)
#else
#define stack_walloc(p, k)				\
	do {								\
		(p) = (word*)(stack);			\
		stack = (word*)(stack) + (k);	\
	} while(0)
#define stack_wfree(p)
#endif

void ecpSmallMultDivpA(word* c, word da[], const word a[], const size_t w, const ec_o* ec, void* stack)
{
	// размер координаты
	const size_t n = ec->f->n;
	// размер аффинной точки
	const size_t na = n * 2;
	// координата x базовой точки
	const word* x = ecX(a);
	// координата y базовой точки
	const word* y = ecY(a, n);

	size_t i;

	// Основные этапы алгоритма:
	// 0) Wᵢ, i=3,4,5
	// 1) for i=3,4..2ʷ⁻¹
	// 2) Wᵢ⁻², i=3,5..2ʷ-1
	// 3) 2P
	// 4*) for i=3,5..2ʷ⁻¹-1
	// 4) for i=3,5..2ʷ⁻¹+1
	// 5) for i=2ʷ⁻¹+1,2ʷ⁻¹+3..2ʷ-1
	// 5*) for i=2ʷ⁻¹+3,2ʷ⁻¹+5..2ʷ-1
	//
	// Таблица. Подвыражения на этапах.
	// Подвыражение    | 0)       | 1)                | 2)   | 3)     | 4)         | 5)                 |
	// --------------------------------------------------------------------------------------------------
	// Wᵢ              | W[3,4,5] | R[i,i+2,2i+1]     |      | R[3,4] | R[*2i]     | R[*i-1,i,*i+1,i+2] |
	//                 |          | W[2i,2i+1]        |      |        |            |                    |
	// Wᵢ²             | W[3,4,5] | R[i-1,i,i+1,'i+2] | R[i] |        |            | R[i-1,'i,i+1,'i+2] |
	//                 |          | W[2i,2i+1]        |      |        |            |                    |
	// Wᵢ⁻²            |          |                   | W[i] |        | R[i]       | R[i]               |
	// Wᵢ₋₁ Wᵢ₊₁       | W[2,3]   | W[i+1]            |      |        |            | R[i-1], W[i+1]     |
	//                 |          | R[i-1,i(e),i+1]   |      |        |            |                    |
	// (2y)² Wᵢ₋₁ Wᵢ₊₁ | W[3]     | W[i(e)+1]         |      |        | R[i]       |                    |
	// (2y)⁴ Wᵢ₋₁ Wᵢ₊₁ | W[3]     | R[i(o)]           |      |        |            |                    |
	//                 |          | WR[i(e)+1]        |      |        |            |                    |
	//

	// Выделяемая память
	word* tmp;
	word* tmp2;
	// 2y
	word* dy;
	// (2y)⁻¹
	word* dyi;
	// (2y)²
	word* dy2;
	// полиномы деления: Wᵢ, i=3,4..(2ʷ+1)
	// этапы: 0), 1), 3), 4), 5)
	// память: 2ʷ-1
	// Значения расчитываются на этапе 1) по индексам 2i и 2i+1.
	// На этапе 1) значения считываются последовательно, по индексам i, i+2.
	// На этапе 4) значения считываются по чётным индексам 2i.
	// На этапе 5) значения считываются последовательно, по индексам i-1,i,i+1,i+2.
	// Упростить кэширование не получается - необходимо выделять память под все значения.
	word* pW;
#define W(i) (pW + ((i)-3) * n)
	// квадраты: Wᵢ², i=3,4..2ʷ
	// этапы: 2), 4), 5)
	// память: 2ʷ-2[+1]
	// Если на этапе 5) не используется gfpMul2 (вычисление произведения через квадраты),
	// то на этапе 5) используются только значения по чётным индексам, поэтому память
	// под квадраты по нечётным индексам можно переиспользовать под обратные (макрос W2i).
	// Квадраты с нечётными индексами сгруппированы вместе для упрощения их обращения.
	// Если требуется найти также двойную точки (da != NULL), то требуется также инвертировать
	// значение 2y. Оно добавляется к квадратам по нечётным индексам для обращения.
	// Квадраты по чётным индексам: W₂ᵢ², i=2,3..2ʷ⁻¹, - выделяются в pW2[0].
	// Квадраты по нечётным индексам: W₂ᵢ₋₁²[,2y], i=2,3..2ʷ⁻¹, - выделяются в pw2[1].
	word* pW2[2];
#define W2(i) (pW2[(i)&1] + (((i)-3)>>1) * n)
	// обратные нечётные квадраты: W₂ᵢ₋₁⁻², i=2,3..2ʷ⁻¹
	// этапы: 2), 4), 5)
	// память: 2ʷ⁻¹-1
	// Обратные нечётные квадраты формируются на этапе 2) и используются на этапах 4) и 5).
	word* pW2i;
#define W2i(i) (pW2i + (((i)-3)>>1) * n)
	// произведения: Wᵢ₋₁ Wᵢ₊₁, i=2,3..2ʷ⁻¹+1
	// этапы: 0), 1), 5)
	// память: 3
	// На этапе 1) значения формируются и используются последовательно с индексами i-1,i,i+1,
	// поэтому можно выделять память лишь под 3 текущие значения.
	// На этапе 5) происходит чтение по индексу i-1, и запись по индексу i+1, поэтому
	// память можно выделять только под 1 значение.
	// Макрос WW(i) имеет вид (i+D)%3, где D - константа.
	// D выбрано как 2ʷ, чтобы WW(2ʷ⁻¹)=[(2ʷ⁻¹(1+2))%3]=0.
	// Макрос WW переопределен перед этапом 5) так, чтобы WW(i)=0.
	word* pWW;
#define WW(i) (pWW + (((i) + (SIZE_1 << w))%3) * n)
	// произведения: (2y)² Wᵢ₋₁ Wᵢ₊₁, i=3,5..2ʷ⁻¹+1
	// этапы: 0), 1), 4)
	// память: 2ʷ⁻²
	// Значения формируются на этапах 0), 1), чтение - на этапе 4). Кэшировать нужно все значения.
	word* pWW2;
#define WWy2(i) (pWW2 + (((i)-3) >> 1) * n)
	// текущее произведение: (2y)⁴ Wᵢ₋₁ Wᵢ₊₁, i=3,5..(2ʷ⁻¹-1)
	// этапы: 0), 1)
	// память: 1
	// Запись на пред. шаге, чтение на текущем. Кэшировать можно только одно текущее значение.
	word* pWW4;
#define WWy4(i) (pWW4)

	stack_walloc(dy2, n);
	stack_walloc(tmp, n);
	stack_walloc(tmp2, n);
	stack_walloc(pW, n * ((SIZE_1 << w) - 1));
	stack_walloc(pW2[0], n * ((SIZE_1 << (w-1)) - 1));
	stack_walloc(pW2[1], n * ((SIZE_1 << (w-1)) - (da ? 0 : 1)));
	stack_walloc(pW2i, n * ((SIZE_1 << (w-1)) - (da ? 0 : 1)));
	stack_walloc(pWW, n * 3);
	stack_walloc(pWW2, n * (SIZE_1 << (w-2)));
	stack_walloc(pWW4, n);
	dy = da ? pW2[1] + n * ((SIZE_1 << (w-1)) - 1) : dy2;

	// Этап 0)

	// [(2y)²]
	gfpDouble(dy, y, ec->f);
	qrSqr(dy2, dy, ec->f, stack);

	{
		// вспомогательные значения
		word* xx;
		word* bx;
		word* aa;

		xx = pW2i;
		bx = xx + n;
		aa = bx + n;

		qrSqr(xx, x, ec->f, stack);			// x ²
		qrMul(bx, ec->B, x, ec->f, stack);	// b x
		qrSqr(aa, ec->A, ec->f, stack);		// a ²

		// [W₃]
		{
			qrAdd(tmp, xx, ec->A, ec->f);	// x² + a
			qrSqr(tmp, tmp, ec->f, stack);	// (x²+a) ²
			gfpDouble(tmp2, tmp, ec->f);	// 2 (x²+a)²
			qrAdd(W(3), tmp, tmp2, ec->f);	// 3 (x²+a)²

			gfpDouble(tmp, bx, ec->f);		// 2 bx
			qrAdd(tmp, tmp, bx, ec->f);		// 3 bx
			qrSub(tmp, aa, tmp, ec->f);		// a² − 3bx
			gfpDouble(tmp, tmp, ec->f);		// 2 (a²−3bx)
			gfpDouble(tmp, tmp, ec->f);		// 4 (a²−3bx)

			qrSub(W(3), W(3), tmp, ec->f);	// W₃ = 3(x²+a)² − 4(a²−3bx)
		}

		// [W₄]
		{
			word* u = da ? ecY(da, n) : W(4);
			gfpDouble(tmp, xx, ec->f);				// 2 x²
			gfpDouble(tmp, tmp, ec->f);				// 4 x²
			qrAdd(tmp, tmp, xx, ec->f);				// 5 x²
			qrSub(tmp, tmp, ec->A, ec->f);			// 5x² - a
			qrMul(tmp, bx, tmp, ec->f, stack);		// bx (5x²-a)
			gfpDouble(tmp, tmp, ec->f);				// 2 bx(5x²-a)
			gfpDouble(W(4), tmp, ec->f);			// 4 bx(5x²-a)

			qrMul(tmp, xx, x, ec->f, stack);		// x³
			qrSqr(tmp2, tmp, ec->f, stack);			// x⁶
			qrAdd(W(4), tmp2, W(4), ec->f);			// x⁶ + 4bx(5x²-a)

			qrMul(tmp2, ec->A, x, ec->f, stack);	// a x
			qrSub(tmp, tmp, tmp2, ec->f);			// x³ - ax
			qrMul(tmp, tmp, tmp2, ec->f, stack);	// ax (x³-ax)
			gfpDouble(tmp2, tmp, ec->f);			// 2 ax(x³-ax)
			gfpDouble(tmp2, tmp2, ec->f);			// 4 ax(x³-ax)
			qrAdd(tmp, tmp, tmp2, ec->f);			// 5 ax(x³-ax)
			qrAdd(W(4), W(4), tmp, ec->f);			// x⁶+4bx(5x²-a) + 5ax(x³-ax)

			qrSqr(tmp, ec->B, ec->f, stack);		// b ²
			gfpDouble(tmp, tmp, ec->f);				// 2 b²
			gfpDouble(tmp, tmp, ec->f);				// 4 b²
			gfpDouble(tmp, tmp, ec->f);				// 8 b²
			qrSub(W(4), W(4), tmp, ec->f);			// x⁶+4bx(5x²-a)+5ax(x³-ax) - 8b²

			qrMul(tmp2, aa, ec->A, ec->f, stack);	// a² a
			qrSub(u, W(4), tmp2, ec->f);			// W₄/2 = x⁶+4bx(5x²-a)+5ax(x³-ax)-8b² - a³

			gfpDouble(W(4), u, ec->f);				// W₄ = 2 (x⁶+4bx(5x²-a)+5ax(x³-ax)-8b²-a³)
		}

		// [W₃²], [W₁W₃], [W₄²], [W₂W₄], [(2y)²W₂W₄], [(2y)⁴W₂W₄]
		qrSqr(W2(3), W(3), ec->f, stack);			// W₃²
		qrCopy(WW(2), W(3), ec->f);					// W₁W₃ = W₃
		qrSqr(W2(4), W(4), ec->f, stack);			// W₄²
		qrCopy(WW(3), W(4), ec->f);					// W₂W₄ = W₄
		qrMul(WWy2(3), dy2, WW(3), ec->f, stack);	// (2y)² W₂W₄
		qrMul(WWy4(3), dy2, WWy2(3), ec->f, stack);	// (2y)² (2y)²W₂W₄
	}

	// [W₅], [W₅²]
	{
		qrMul(tmp, WW(2), W2(3), ec->f, stack);		// W₁W₃ W₃²
		qrSub(W(5), WWy4(3), tmp, ec->f);			// W₅ = (2y)⁴W₂W₄ − W₁W₃W₃²
		qrSqr(W2(5), W(5), ec->f, stack);			// W₅ ²
	}

	// Этап 1)
	// для i=3,4..2ʷ⁻¹: [W₂ᵢ], [W₂ᵢ₊₁], [Wᵢ Wᵢ₊₂]
	for (i = 3;;)
	{
		// [WᵢWᵢ₊₂] = ((Wᵢ + Wᵢ₊₂) ² - Wᵢ² - Wᵢ₊₂²) / 2
		gfpMul2(WW(i+1), W(i), W(i+2), W2(i), W2(i+2), ec->f, stack);

		// [W₂ᵢ]
		if (i == 3)
		{
			qrMul(tmp, WW(i-1), W2(i+1), ec->f, stack);		// (W₁W₃) W₄²
			qrSub(W(2*i), WW(i+1), tmp, ec->f);				// W₆ = W₃W₅ - W₁W₃W₄²
		}
		else
		{
			qrMul(tmp, WW(i-1), W2(i+1), ec->f, stack);		// (Wᵢ₋₂Wᵢ) Wᵢ₊₁²
			qrMul(W(2*i), WW(i+1), W2(i-1), ec->f, stack);	// (WᵢWᵢ₊₂) Wᵢ₋₁²
			qrSub(W(2*i), W(2*i), tmp, ec->f);				// W₂ᵢ = (WᵢWᵢ₊₂)Wᵢ₋₁² - (Wᵢ₋₂Wᵢ)Wᵢ₊₁²
		}

		// [W₂ᵢ²]
		qrSqr(W2(2*i), W(2*i), ec->f, stack);				// W₂ᵢ ²

		// [W₂ᵢ₊₁]
		if ((i & 1) == 1)
		{
			qrMul(tmp, WWy4(i), W2(i+1), ec->f, stack);		// (2y)⁴Wᵢ₋₁Wᵢ₊₁ Wᵢ₊₁²
			qrMul(W(2*i+1), WW(i+1), W2(i), ec->f, stack);	// WᵢWᵢ₊₂ Wᵢ²
			qrSub(W(2*i+1), W(2*i+1), tmp, ec->f);			// W₂ᵢ₊₁ = WᵢWᵢ₊₂Wᵢ² - (2y)⁴Wᵢ₋₁Wᵢ₊₁Wᵢ₊₁²
 		}
		else
		{
			// [(2y)²WᵢWᵢ₊₂]
			qrMul(WWy2(i+1), dy2, WW(i+1), ec->f, stack);	// (2y)² WᵢWᵢ₊₂
			// [(2y)⁴WᵢWᵢ₊₂]
			qrMul(WWy4(i+1), dy2, WWy2(i+1), ec->f, stack);	// (2y)² (2y)²WᵢWᵢ₊₂
			qrMul(tmp, WW(i), W2(i+1), ec->f, stack);		// Wᵢ₋₁Wᵢ₊₁ Wᵢ₊₁²
			qrMul(W(2*i+1), WWy4(i+1), W2(i), ec->f, stack);	// (2y)⁴WᵢWᵢ₊₂ Wᵢ²
			qrSub(W(2*i+1), W(2*i+1), tmp, ec->f);			// W₂ᵢ₊₁ = (2y)⁴WᵢWᵢ₊₂Wᵢ² - Wᵢ₋₁Wᵢ₊₁Wᵢ₊₁²
		}

		if (i != SIZE_1 << (w - 1))
		{
			// [W₂ᵢ₊₁²]
			qrSqr(W2(2*i+1), W(2*i+1), ec->f, stack);		// W₂ᵢ₊₁ ²
			++i;
		} else
			break;
	}

	// [1]P
	wwCopy(c, a, na);
	c += na;

	// Этап 2)
	// [Wᵢ⁻²][,2y], i=3,5..2ʷ-1
	qrMontInv(W2i(3), W2(3), da ? i : i - 1, ec->f, stack);

	// Этап 3)
	// [2]P
	if(da)
	{
		dyi = pW2i + n * ((SIZE_1 << (w - 1)) - 1);
		// X₂ = x-W₁W₃/(2yW₂)² = x - W₃ / (2y)²
		qrSqr(tmp, dyi, ec->f, stack);						// (2y) ⁻²
		qrMul(ecX(da), W(3), tmp, ec->f, stack);			// W₃ / (2y)²
		qrSub(ecX(da), x, ecX(da), ec->f);					// x - W₃/(2y)²
		// Y₂ = (W₄W₁²-W₀W₃²)/2/(2yW₂)³ = W₄ / 2 / (2y)³
		qrMul(tmp, tmp, dyi, ec->f, stack);					// (2y) ⁻³
		qrMul(ecY(da, n), ecY(da, n), tmp, ec->f, stack);	// W₄/2 / (2y)³
	}

	// Этап 4)
	for (i = 3;;)
	{
		// i=3,5..2ʷ⁻¹+1: [Xᵢ] = x − (2y)²Wᵢ₋₁Wᵢ₊₁ Wᵢ⁻²
		qrMul(tmp, WWy2(i), W2i(i), ec->f, stack);
		qrSub(ecX(c), x, tmp, ec->f);

		if (i == (SIZE_1 << (w - 1)) + 1) break;

		// i=3,5..2ʷ⁻¹-1: [Yᵢ] = y W₂ᵢ Wᵢ⁻⁴
		qrSqr(tmp, W2i(i), ec->f, stack);
		qrMul(tmp, W(2*i), tmp, ec->f, stack);
		qrMul(ecY(c, n), y, tmp, ec->f, stack);

		i += 2, c += na;
	}
	// Этап 5)
#undef WW
#define WW(i) (pWW)
	for (;;)
	{
		// i=2ʷ⁻¹+1,2ʷ⁻¹+3..2ʷ-1: [Yᵢ] = y (WᵢWᵢ₊₂ Wᵢ₋₁² - Wᵢ₋₂Wᵢ Wᵢ₊₁²) Wᵢ⁻⁴
		qrMul(tmp, WW(i-1), W2(i+1), ec->f, stack); 						// Wᵢ₋₂Wᵢ Wᵢ₊₁²
		// [WᵢWᵢ₊₂]
		if (i != (SIZE_1 << w) - 1)
			gfpMul2(WW(i+1), W(i), W(i+2), W2(i), W2(i+2), ec->f, stack);	// Wᵢ Wᵢ₊₂
		else
			// Wᵢ₊₂² undefined
			qrMul(WW(i+1), W(i), W(i+2), ec->f, stack);						// Wᵢ Wᵢ₊₂
		qrMul(tmp2, WW(i+1), W2(i-1), ec->f, stack); 						// WᵢWᵢ₊₂ Wᵢ₋₁²
		qrSub(tmp2, tmp2, tmp, ec->f);										// WᵢWᵢ₊₂Wᵢ₋₁² - Wᵢ₋₂WᵢWᵢ₊₁²
		qrSqr(tmp, W2i(i), ec->f, stack);									// Wᵢ⁻² ²
		qrMul(tmp, tmp2, tmp, ec->f, stack);								// (WᵢWᵢ₊₂Wᵢ₋₁²-Wᵢ₋₂WᵢWᵢ₊₁²) Wᵢ⁻⁴
		qrMul(ecY(c, n), y, tmp, ec->f, stack);								// y (WᵢWᵢ₊₂Wᵢ₋₁²-Wᵢ₋₂WᵢWᵢ₊₁²)Wᵢ⁻⁴

		i += 2, c += na;
		if (i == (SIZE_1 << w) + 1) break;

		// i=2ʷ⁻¹+3,2ʷ⁻¹+5..2ʷ-1: [Xᵢ] = x − (2y)² Wᵢ₋₁ Wᵢ₊₁ Wᵢ⁻²
		gfpMul2(tmp, W(i-1), W(i+1), W2(i-1), W2(i+1), ec->f, stack);		// Wᵢ₋₁ Wᵢ₊₁
		qrMul(tmp, dy2, tmp, ec->f, stack);									// (2y)² Wᵢ₋₁Wᵢ₊₁
		qrMul(tmp, W2i(i), tmp, ec->f, stack);								// (2y)²Wᵢ₋₁Wᵢ₊₁ Wᵢ⁻²
		qrSub(ecX(c), x, tmp, ec->f);										// x − (2y)²Wᵢ₋₁Wᵢ₊₁Wᵢ⁻²
	}

	stack_wfree(pWW4);
	stack_wfree(pWW2);
	stack_wfree(pWW);
	stack_wfree(pW2i);
	stack_wfree(pW2[1]);
	stack_wfree(pW2[0]);
	stack_wfree(pW);
	stack_wfree(tmp2);
	stack_wfree(tmp);
	stack_wfree(dy2);

#undef W
#undef W2
#undef W2i
#undef WW
#undef WWy2
#undef WWy4

}

size_t ecpSmallMultDivpA_deep(bool_t da, const size_t w, size_t n, size_t f_deep)
{
	size_t const ww = SIZE_1 << w;
	size_t r = n * (0
		+ 1						// dy2
		+ 1						// tmp
		+ 1						// tmp2
		+ (ww - 1)				// pW
		+ (ww/2 - 1)			// pW2[0]
		+ (ww/2 - (da ? 0 : 1))	// pW2[1]
		+ (ww/2 - (da ? 0 : 1))	// pW2i
		+ 3						// pWW
		+ ww/4					// pWW2
		+ 1						// pWW4
		);
#ifdef _DEBUG
	r += 3 * 10;
#endif
	return O_OF_W(r) +
		utilMax(2,
			f_deep,
			qrMontInv_deep(n, da ? ww/2 : ww/2 - 1, f_deep));
;
}

void ecpSmallMultDivpJ(word* c, word da[], const word a[], const size_t w, const ec_o* ec, void* stack)
{
	// размер координаты
	const size_t n = ec->f->n;
	// размер якобиевой точки
	const size_t nj = n * ec->d;
	// координата x базовой точки
	const word* x = ecX(a);
	// координата y базовой точки
	const word* y = ecY(a, n);

	size_t i;

	// Основные этапы алгоритма:
	// 0) Wᵢ, i=3,4,5
	// 1) for i=3,4..2ʷ⁻¹
	// 3) 2P
	// 4*) for i=3,5..2ʷ⁻¹-1
	// 4) for i=3,5..2ʷ⁻¹+1
	// 5) for i=2ʷ⁻¹+1,2ʷ⁻¹+3..2ʷ-1
	// 5*) for i=2ʷ⁻¹+3,2ʷ⁻¹+5..2ʷ-1
	//
	// Таблица. Подвыражения на этапах.
	// Подвыражение    | 0)       | 1)                | 3)     | 4)         | 5)                 |
	// -------------------------------------------------------------------------------------------
	// Wᵢ              | W[3,4,5] | R[i,i+2,2i+1]     | R[3,4] | R[*2i]     | R[*i-1,i,*i+1,i+2] |
	//                 |          | W[2i,2i+1]        |        |            |                    |
	// Wᵢ²             | W[3,4,5] | R[i-1,i,i+1,'i+2] |        |            | R[i-1,'i,i+1,'i+2] |
	//                 |          | W[2i,2i+1]        |        |            |                    |
	// Wᵢ₋₁ Wᵢ₊₁       | W[2,3]   | W[i+1]            |        |            | R[i-1], W[i+1]     |
	//                 |          | R[i-1,i(e),i+1]   |        |            |                    |
	// (2y)² Wᵢ₋₁ Wᵢ₊₁ | W[3]     | W[i(e)+1]         |        | R[i]       |                    |
	// (2y)⁴ Wᵢ₋₁ Wᵢ₊₁ | W[3]     | R[i(o)]           |        |            |                    |
	//                 |          | WR[i(e)+1]        |        |            |                    |
	//

	// Выделяемая память
	word* tmp;
	word* tmp2;
	// 2y
	word* dy;
	// (2y)²
	word* dy2;
	// полиномы деления: Wᵢ, i=3,4..(2ʷ+1)
	// этапы: 0), 1), 3), 4), 5)
	// память: 2ʷ-1
	// Значения расчитываются на этапе 1) по индексам 2i и 2i+1.
	// На этапе 1) значения считываются последовательно, по индексам i, i+2.
	// На этапе 4) значения считываются по чётным индексам 2i.
	// На этапе 5) значения считываются последовательно, по индексам i-1,i,i+1,i+2.
	// Упростить кэширование не получается - необходимо выделять память под все значения.
	word* pW;
#define W(i) (pW + ((i)-3) * n)
	// квадраты: Wᵢ², i=3,4..2ʷ
	// этапы: 2), 4), 5)
	// память: 2ʷ-2[+1]
	// Квадраты с нечётными индексами сгруппированы вместе для упрощения их обращения.
	// Если требуется найти также двойную точки (da != NULL), то требуется также инвертировать
	// значение 2y. Оно добавляется к квадратам по нечётным индексам для обращения.
	// Квадраты по чётным индексам: W₂ᵢ², i=2,3..2ʷ⁻¹, - выделяются в pW2[0].
	// Квадраты по нечётным индексам: W₂ᵢ₋₁²[,2y], i=2,3..2ʷ⁻¹, - выделяются в pw2[1].
	word* pW2[2];
#define W2(i) (pW2[(i)&1] + (((i)-3)>>1) * n)
	// произведения: Wᵢ₋₁ Wᵢ₊₁, i=2,3..2ʷ⁻¹+1
	// этапы: 0), 1), 5)
	// память: 3
	// На этапе 1) значения формируются и используются последовательно с индексами i-1,i,i+1,
	// поэтому можно выделять память лишь под 3 текущие значения.
	// На этапе 5) происходит чтение по индексу i-1, и запись по индексу i+1, поэтому
	// память можно выделять только под 1 значение.
	// Макрос WW(i) имеет вид (i+D)%3, где D - константа.
	// D выбрано как 2ʷ, чтобы WW(2ʷ⁻¹)=[(2ʷ⁻¹(1+2))%3]=0.
	// Макрос WW переопределен перед этапом 5) так, чтобы WW(i)=0.
	word* pWW;
#define WW(i) (pWW + (((i) + (SIZE_1 << w))%3) * n)
	// произведения: (2y)² Wᵢ₋₁ Wᵢ₊₁, i=3,5..2ʷ⁻¹+1
	// этапы: 0), 1), 4)
	// память: 2ʷ⁻²
	// Значения формируются на этапах 0), 1), чтение - на этапе 4). Кэшировать нужно все значения.
	word* pWW2;
#define WWy2(i) (pWW2 + (((i)-3) >> 1) * n)
	// текущее произведение: (2y)⁴ Wᵢ₋₁ Wᵢ₊₁, i=3,5..(2ʷ⁻¹-1)
	// этапы: 0), 1)
	// память: 1
	// Запись на пред. шаге, чтение на текущем. Кэшировать можно только одно текущее значение.
	word* pWW4;
#define WWy4(i) (pWW4)

	stack_walloc(dy2, n);
	stack_walloc(tmp, n);
	stack_walloc(tmp2, n);
	stack_walloc(pW, n * ((SIZE_1 << w) - 1));
	stack_walloc(pW2[0], n * ((SIZE_1 << (w-1)) - 1));
	stack_walloc(pW2[1], n * ((SIZE_1 << (w-1)) - (da ? 0 : 1)));
	stack_walloc(pWW, n * 3);
	stack_walloc(pWW2, n * (SIZE_1 << (w-2)));
	stack_walloc(pWW4, n);
	dy = da ? pW2[1] + n * ((SIZE_1 << (w-1)) - 1) : dy2;

	// Этап 0)

	// [(2y)²]
	gfpDouble(dy, y, ec->f);
	qrSqr(dy2, dy, ec->f, stack);

	{
		// вспомогательные значения
		word* xx;
		word* bx;
		word* aa;

		xx = pWW;
		bx = xx + n;
		aa = bx + n;

		qrSqr(xx, x, ec->f, stack);			// x ²
		qrMul(bx, ec->B, x, ec->f, stack);	// b x
		qrSqr(aa, ec->A, ec->f, stack);		// a ²

		// [W₃]
		{
			qrAdd(tmp, xx, ec->A, ec->f);	// x² + a
			qrSqr(tmp, tmp, ec->f, stack);	// (x²+a) ²
			gfpDouble(tmp2, tmp, ec->f);	// 2 (x²+a)²
			qrAdd(W(3), tmp, tmp2, ec->f);	// 3 (x²+a)²

			gfpDouble(tmp, bx, ec->f);		// 2 bx
			qrAdd(tmp, tmp, bx, ec->f);		// 3 bx
			qrSub(tmp, aa, tmp, ec->f);		// a² − 3bx
			gfpDouble(tmp, tmp, ec->f);		// 2 (a²−3bx)
			gfpDouble(tmp, tmp, ec->f);		// 4 (a²−3bx)

			qrSub(W(3), W(3), tmp, ec->f);	// W₃ = 3(x²+a)² − 4(a²−3bx)
		}

		// [W₄]
		{
			word* u = da ? ecY(da, n) : W(4);
			gfpDouble(tmp, xx, ec->f);				// 2 x²
			gfpDouble(tmp, tmp, ec->f);				// 4 x²
			qrAdd(tmp, tmp, xx, ec->f);				// 5 x²
			qrSub(tmp, tmp, ec->A, ec->f);			// 5x² - a
			qrMul(tmp, bx, tmp, ec->f, stack);		// bx (5x²-a)
			gfpDouble(tmp, tmp, ec->f);				// 2 bx(5x²-a)
			gfpDouble(W(4), tmp, ec->f);			// 4 bx(5x²-a)

			qrMul(tmp, xx, x, ec->f, stack);		// x³
			qrSqr(tmp2, tmp, ec->f, stack);			// x⁶
			qrAdd(W(4), tmp2, W(4), ec->f);			// x⁶ + 4bx(5x²-a)

			qrMul(tmp2, ec->A, x, ec->f, stack);	// a x
			qrSub(tmp, tmp, tmp2, ec->f);			// x³ - ax
			qrMul(tmp, tmp, tmp2, ec->f, stack);	// ax (x³-ax)
			gfpDouble(tmp2, tmp, ec->f);			// 2 ax(x³-ax)
			gfpDouble(tmp2, tmp2, ec->f);			// 4 ax(x³-ax)
			qrAdd(tmp, tmp, tmp2, ec->f);			// 5 ax(x³-ax)
			qrAdd(W(4), W(4), tmp, ec->f);			// x⁶+4bx(5x²-a) + 5ax(x³-ax)

			qrSqr(tmp, ec->B, ec->f, stack);		// b ²
			gfpDouble(tmp, tmp, ec->f);				// 2 b²
			gfpDouble(tmp, tmp, ec->f);				// 4 b²
			gfpDouble(tmp, tmp, ec->f);				// 8 b²
			qrSub(W(4), W(4), tmp, ec->f);			// x⁶+4bx(5x²-a)+5ax(x³-ax) - 8b²

			qrMul(tmp2, aa, ec->A, ec->f, stack);	// a² a
			qrSub(u, W(4), tmp2, ec->f);			// W₄/2 = x⁶+4bx(5x²-a)+5ax(x³-ax)-8b² - a³

			gfpDouble(W(4), u, ec->f);				// W₄ = 2 (x⁶+4bx(5x²-a)+5ax(x³-ax)-8b²-a³)
		}

		// [W₃²], [W₁W₃], [W₄²], [W₂W₄], [(2y)²W₂W₄], [(2y)⁴W₂W₄]
		qrSqr(W2(3), W(3), ec->f, stack);			// W₃²
		qrCopy(WW(2), W(3), ec->f);					// W₁W₃ = W₃
		qrSqr(W2(4), W(4), ec->f, stack);			// W₄²
		qrCopy(WW(3), W(4), ec->f);					// W₂W₄ = W₄
		qrMul(WWy2(3), dy2, WW(3), ec->f, stack);	// (2y)² W₂W₄
		qrMul(WWy4(3), dy2, WWy2(3), ec->f, stack);	// (2y)² (2y)²W₂W₄
	}

	// [W₅], [W₅²]
	{
		qrMul(tmp, WW(2), W2(3), ec->f, stack);		// W₁W₃ W₃²
		qrSub(W(5), WWy4(3), tmp, ec->f);			// W₅ = (2y)⁴W₂W₄ − W₁W₃W₃²
		qrSqr(W2(5), W(5), ec->f, stack);			// W₅ ²
	}

	// Этап 1)
	// для i=3,4..2ʷ⁻¹: [W₂ᵢ], [W₂ᵢ₊₁], [Wᵢ Wᵢ₊₂]
	for (i = 3;;)
	{
		// [WᵢWᵢ₊₂] = ((Wᵢ + Wᵢ₊₂) ² - Wᵢ² - Wᵢ₊₂²) / 2
		gfpMul2(WW(i+1), W(i), W(i+2), W2(i), W2(i+2), ec->f, stack);

		// [W₂ᵢ]
		if (i == 3)
		{
			qrMul(tmp, WW(i-1), W2(i+1), ec->f, stack);		// (W₁W₃) W₄²
			qrSub(W(2*i), WW(i+1), tmp, ec->f);				// W₆ = W₃W₅ - W₁W₃W₄²
		}
		else
		{
			qrMul(tmp, WW(i-1), W2(i+1), ec->f, stack);		// (Wᵢ₋₂Wᵢ) Wᵢ₊₁²
			qrMul(W(2*i), WW(i+1), W2(i-1), ec->f, stack);	// (WᵢWᵢ₊₂) Wᵢ₋₁²
			qrSub(W(2*i), W(2*i), tmp, ec->f);				// W₂ᵢ = (WᵢWᵢ₊₂)Wᵢ₋₁² - (Wᵢ₋₂Wᵢ)Wᵢ₊₁²
		}

		// [W₂ᵢ²]
		qrSqr(W2(2*i), W(2*i), ec->f, stack);				// W₂ᵢ ²

		// [W₂ᵢ₊₁]
		if ((i & 1) == 1)
		{
			qrMul(tmp, WWy4(i), W2(i+1), ec->f, stack);		// (2y)⁴Wᵢ₋₁Wᵢ₊₁ Wᵢ₊₁²
			qrMul(W(2*i+1), WW(i+1), W2(i), ec->f, stack);	// WᵢWᵢ₊₂ Wᵢ²
			qrSub(W(2*i+1), W(2*i+1), tmp, ec->f);			// W₂ᵢ₊₁ = WᵢWᵢ₊₂Wᵢ² - (2y)⁴Wᵢ₋₁Wᵢ₊₁Wᵢ₊₁²
 		}
		else
		{
			// [(2y)²WᵢWᵢ₊₂]
			qrMul(WWy2(i+1), dy2, WW(i+1), ec->f, stack);	// (2y)² WᵢWᵢ₊₂
			// [(2y)⁴WᵢWᵢ₊₂]
			qrMul(WWy4(i+1), dy2, WWy2(i+1), ec->f, stack);	// (2y)² (2y)²WᵢWᵢ₊₂
			qrMul(tmp, WW(i), W2(i+1), ec->f, stack);		// Wᵢ₋₁Wᵢ₊₁ Wᵢ₊₁²
			qrMul(W(2*i+1), WWy4(i+1), W2(i), ec->f, stack);	// (2y)⁴WᵢWᵢ₊₂ Wᵢ²
			qrSub(W(2*i+1), W(2*i+1), tmp, ec->f);			// W₂ᵢ₊₁ = (2y)⁴WᵢWᵢ₊₂Wᵢ² - Wᵢ₋₁Wᵢ₊₁Wᵢ₊₁²
		}

		if (i != SIZE_1 << (w - 1))
		{
			// [W₂ᵢ₊₁²]
			qrSqr(W2(2*i+1), W(2*i+1), ec->f, stack);		// W₂ᵢ₊₁ ²
			++i;
		} else
			break;
	}

	// [1]P
	ecFromA(c, a, ec, stack);
	c += nj;

	// Этап 3)
	// [2]P
	if(da)
	{
		// X₂ = x(2y)²W₂²-W₁W₃ = (2y)²x - W₃
		qrMul(ecX(da), dy2, x, ec->f, stack);				// (2y)² x
		qrSub(ecX(da), ecX(da), W(3), ec->f);				// (2y)²x - W₃
		// Y₂ = (W₄W₁²-W₀W₃²)/2 = W₄/2
		// Z₂ = 2yW₂ = 2y
		gfpDouble(ecZ(da, n), y, ec->f);
	}

	// Этап 4)
	for (i = 3;;)
	{
		// i=3,5..2ʷ⁻¹+1: [Xᵢ] = x Wᵢ² − (2y)²Wᵢ₋₁Wᵢ₊₁
		qrMul(ecX(c), x, W2(i), ec->f, stack);
		qrSub(ecX(c), ecX(c), WWy2(i), ec->f);

		if (i == (SIZE_1 << (w - 1)) + 1) break;

		// i=3,5..2ʷ⁻¹-1: [Yᵢ] = y (Wᵢ₊₂ Wᵢ₋₁² - Wᵢ₋₂ Wᵢ₊₁²)
		if (i < 4)
			wwCopy(tmp, W(i+2), n);
		else
			qrMul(tmp, W(i+2), W2(i-1), ec->f, stack);
		if (i < 5)
			wwCopy(ecY(c, n), W2(i+1), n);
		else
			qrMul(ecY(c, n), W(i-2), W2(i+1), ec->f, stack);
		qrSub(ecY(c, n), tmp, ecY(c, n), ec->f);
		qrMul(ecY(c, n), y, ecY(c, n), ec->f, stack);
		// [Zᵢ] = Wᵢ
		wwCopy(ecZ(c, n), W(i), n);

		i += 2, c += nj;
	}
	// Этап 5)
#undef WW
#define WW(i) (pWW)
	for (;;)
	{
		// i=2ʷ⁻¹+1,2ʷ⁻¹+3..2ʷ-1: [Yᵢ] = y (Wᵢ₊₂ Wᵢ₋₁² - Wᵢ₋₂ Wᵢ₊₁²)
		qrMul(tmp, W(i+2), W2(i-1), ec->f, stack);
		qrMul(ecY(c, n), W(i-2), W2(i+1), ec->f, stack);
		qrSub(ecY(c, n), tmp, ecY(c, n), ec->f);
		qrMul(ecY(c, n), y, ecY(c, n), ec->f, stack);
		// [Zᵢ] = Wᵢ
		wwCopy(ecZ(c, n), W(i), n);

		i += 2, c += nj;
		if (i == (SIZE_1 << w) + 1) break;

		// i=2ʷ⁻¹+3,2ʷ⁻¹+5..2ʷ-1: [Xᵢ] = x Wᵢ² − (2y)² Wᵢ₋₁ Wᵢ₊₁
		gfpMul2(tmp, W(i-1), W(i+1), W2(i-1), W2(i+1), ec->f, stack);		// Wᵢ₋₁ Wᵢ₊₁
		qrMul(tmp, dy2, tmp, ec->f, stack);									// (2y)² Wᵢ₋₁Wᵢ₊₁
		qrMul(ecX(c), x, W2(i), ec->f, stack);								// x Wᵢ²
		qrSub(ecX(c), ecX(c), tmp, ec->f);									// x Wᵢ² − (2y)²Wᵢ₋₁Wᵢ₊₁
	}

	stack_wfree(pWW4);
	stack_wfree(pWW2);
	stack_wfree(pWW);
	stack_wfree(pW2[1]);
	stack_wfree(pW2[0]);
	stack_wfree(pW);
	stack_wfree(tmp2);
	stack_wfree(tmp);
	stack_wfree(dy2);

#undef W
#undef W2
#undef WW
#undef WWy2
#undef WWy4

}

size_t ecpSmallMultDivpJ_deep(bool_t da, const size_t w, size_t n, size_t f_deep)
{
	size_t const ww = SIZE_1 << w;
	size_t r = n * (0
		+ 1						// dy2
		+ 1						// tmp
		+ 1						// tmp2
		+ (ww - 1)				// pW
		+ (ww/2 - 1)			// pW2[0]
		+ (ww/2 - (da ? 0 : 1))	// pW2[1]
		+ 3						// pWW
		+ ww/4					// pWW2
		+ 1						// pWW4
		);
#ifdef _DEBUG
	r += 3 * 9;
#endif
	return O_OF_W(r) + f_deep;
}

#undef stack_walloc
#undef stack_wfree
