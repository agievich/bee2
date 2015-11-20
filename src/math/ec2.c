/*
*******************************************************************************
\file ec2.c
\brief Elliptic curves over binary fields
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2012.06.26
\version 2014.07.15
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/mem.h"
#include "bee2/core/stack.h"
#include "bee2/core/util.h"
#include "bee2/math/ec2.h"
#include "bee2/math/gf2.h"
#include "bee2/math/pri.h"
#include "bee2/math/ww.h"
#include "bee2/math/zz.h"

/*
*******************************************************************************
Общие положения

Ссылки на все реализованные алгоритмы имеются на сайте
http://www.hyperelliptic.org/efd. Там же можно найти соглашения по
обозначению сложности алгоритмов. В этих обозначениях фигурируют
следующие формальные выражения:
	add -- сложение или вычитание в GF(2^m),
	c -- умножение на малую константу c в GF(2^m),
	*A -- умножение на коэффициент A в GF(2^m),
	*B -- умножение на коэффициент B в GF(2^m),
	S -- возведение в квадрат в GF(2^m),
	M -- умножение в GF(2^m),
	D -- деление в GF(2^m).

При общей оценке сложности считается, что 1D = 24M, 1*B = 1M и 1S = 0M.
Аддитивные операции игнорируются. В общем случае 1*A = 1M, но в наиболее
распространенных на практике случаях A \in {0, 1} и 1*A = 0M.

\warning Соотношение 1D = 24M получено экспериментальным путем
на платформе x86 и возможно требует пересмотра.
На упомянутом сайте http://www.hyperelliptic.org/efd используется другое
соотношение: 1D = 10M. Считаем его слишком оптимистичным
(по отношению к D).

Используются обозначения:
	A <- A + A -- сложение аффинных точек,
	A <- 2A -- удвоение аффинной точки;
	P <- P + P -- сложение проективных точек;
	P <- P + A -- добавление к проективной точке аффинной;
	P <- 2P -- удвоение проективной точки;
	P <- 2A -- удвоение аффинной точки с переходом к проективным координатам.
*******************************************************************************
*/

#define ec2SeemsOnA(a, ec)\
	(gf2IsIn(ecX(a), (ec)->f) && gf2IsIn(ecY(a, (ec)->f->n), (ec)->f))

#define ec2SeemsOn3(a, ec)\
	(ec2SeemsOnA(a, ec) && gf2IsIn(ecZ(a, (ec)->f->n), (ec)->f))

/*
*******************************************************************************
Кривая в проективных координатах Лопеса -- Дахаба (LD):
	x = X / Z, y = Y / Z^2,
	O = (1 : 0 : 0),
	-(X : Y : Z) = (X : ZX + Y : Z).

\warning Ошибка в книге [Hankerson D., Menezes A., Vanstone S. Guide to
Elliptic Curve Cryptography, Springer, 2004] при определении обратной
точки в LD-координатах.

В функции ec2DblLD() выполняется удвоение P <- 2P. Реализован алгоритм
dbl-2005-l [Lange, 2005]. Сложность алгоритма:
	4M + 4S + 1*A + 5add \approx 5M,
причем умножение на A не выполняется, если A \in {0, 1}.

\todo Ссравнить с алгоритмом dbl-2005-dl.

В функции ec2DblALD() выполняется удвоение P <- 2A (Z-координата
проективной точки равняется 1). Реализован алгоритм
mdbl-2005-dl [Doche-Lange, 2005]. Сложность алгоритма:
	1M + 3S + 1*A + 1*B + 4add \approx 3M.
причем умножение на A не выполняется, если A \in {0, 1}.

В функции ec2AddLD() выполняется сложение P <- P + P.
Реализован алгоритм add-2005-dl [Doche-Lange-Takagi, 2005].
Сложность алгоритма:
	13M + 4S + 9add \approx 13M.

В функции ec2AddALD() выполняется сложение P <- P + A (Z-координата
второго слагаемого равняется 1).
Реализован алгоритм madd-2005-dl [Doche, Lange, Al-Daoude, 2005].
Сложность алгоритма:
		8M + 5S + 1*A + 9add \approx 9M,
причем умножение на A не выполняется, если A \in {0, 1}.

Целевые функции ci(l), определенные в описании реализации ecMul() в ec.c,
принимают следующий вид (считаем, что коэффициент A \in {0, 1}):
	c1(l) = l/3 8;
	c2(l, w) = 26 + (2^{w-2} - 2)26 + l/(w + 1) 8;
	c3(l, w) = 2 + (2^{w-2} - 2)13 + l/(w + 1) 13.

Расчеты показывают, что
	с1(l) <= min_w c2(l), l <= 39,
	min_w c2(l, w) <= min_w c3(l, w).
Поэтому для практически используемых размерностей l (39 <= l)
первая и третья стратегии являются проигрышными. Реализована только стратегия 2.

\todo Реализовать быстрые формулы для особенных B:
B = 1 (кривые Коблица),	известен \sqrt{B}.

\todo Реализовать редакции функций с A \in {0, 1}.

\todo Исследовать расширенные LD-координаты (дополнительно поддерживается Z^2).
*******************************************************************************
*/

// [3n]b <- [2n]a (P <- A)
static bool_t ec2FromALD(word b[], const word a[], const ec_o* ec,
	void* stack)
{
	const size_t n = ec->f->n;
	// pre
	ASSERT(ecIsOperable(ec) && ec->d == 3);
	ASSERT(ec2SeemsOnA(a, ec));
	ASSERT(a == b || wwIsDisjoint2(a, 2 * n, b, 3 * n));
	// xb <- xa
	qrCopy(ecX(b), ecX(a), ec->f);
	// yb <- ya
	qrCopy(ecY(b, n), ecY(a, n), ec->f);
	// zb <- 1
	qrSetUnity(ecZ(b, n), ec->f);
	return TRUE;
}

// [2n]b <- [3n]a (A <- P)
static bool_t ec2ToALD(word b[], const word a[], const ec_o* ec, void* stack)
{
	const size_t n = ec->f->n;
	// переменные в stack
	word* t1 = (word*)stack;
	stack = t1 + n;
	// pre
	ASSERT(ecIsOperable(ec) && ec->d == 3);
	ASSERT(ec2SeemsOn3(a, ec));
	ASSERT(a == b || wwIsDisjoint2(a, 3 * n, b, 2 * n));
	// a == O => b <- O
	if (qrIsZero(ecZ(a, n), ec->f))
		return FALSE;
	// t1 <- za^{-1}
	qrInv(t1, ecZ(a, n), ec->f, stack);
	// xb <- xa t1
	qrMul(ecX(b), ecX(a), t1, ec->f, stack);
	// t1 <- t1^2
	qrSqr(t1, t1, ec->f, stack);
	// yb <- ya t1
	qrMul(ecY(b, n), ecY(a, n), t1, ec->f, stack);
	// b != O
	return TRUE;
}

static size_t ec2ToALD_deep(size_t n, size_t f_deep)
{
	return O_OF_W(n) + f_deep;
}

// [3n]b <- -[3n]a (P <- -P)
static void ec2NegLD(word b[], const word a[], const ec_o* ec, void* stack)
{
	const size_t n = ec->f->n;
	// переменные в stack
	word* t1 = (word*)stack;
	stack = t1 + n;
	// pre
	ASSERT(ecIsOperable(ec) && ec->d == 3);
	ASSERT(ec2SeemsOn3(a, ec));
	ASSERT(wwIsSameOrDisjoint(a, b, 3 * n));
	// t1 <- xa * za
	qrMul(t1, ecX(a), ecZ(a, n), ec->f, stack);
	// b <- (xa, ya + t1, za)
	wwCopy(b, a, 3 * n);
	gf2Add2(ecY(b, n), t1, ec->f);
}

static size_t ec2NegLD_deep(size_t n, size_t f_deep)
{
	return O_OF_W(n) + f_deep;
}

// [3n]b <- 2[3n]a (P <- 2P)
static void ec2DblLD(word b[], const word a[], const ec_o* ec, void* stack)
{
	const size_t n = ec->f->n;
	// переменные в stack
	word* t1 = (word*)stack;
	word* t2 = t1 + n;
	stack = t2 + n;
	// pre
	ASSERT(ecIsOperable(ec) && ec->d == 3);
	ASSERT(ec2SeemsOn3(a, ec));
	ASSERT(wwIsSameOrDisjoint(a, b, 3 * n));
	// za == 0 или xa == 0? => b <- O
	if (qrIsZero(ecZ(a, n), ec->f) || qrIsZero(ecX(a), ec->f))
	{
		qrSetZero(ecZ(b, n), ec->f);
		return;
	}
	// t1 <- xa za [A]
	qrMul(t1, ecX(a), ecZ(a, n), ec->f, stack);
	// zb <- t1^2 [A^2]
	qrSqr(ecZ(b, n), t1, ec->f, stack);
	// t2 <- xa^2 [B]
	qrSqr(t2, ecX(a), ec->f, stack);
	// xb <- ya + t2 [C]
	gf2Add(ecX(b), ecY(a, n), t2, ec->f);
	// t1 <- t1 xb [D]
	qrMul(t1, t1, ecX(b), ec->f, stack);
	// xb <- xb^2 + t1 [C^2 + D]
	qrSqr(ecX(b), ecX(b), ec->f, stack);
	gf2Add2(ecX(b), t1, ec->f);
	// t1 <- t1 + zb [Z3 + D]
	gf2Add2(t1, ecZ(b, n), ec->f);
	// yb <- t2^2 zb [B^2 Z3]
	qrSqr(ecY(b, n), t2, ec->f, stack);
	qrMul(ecY(b, n), ecY(b, n), ecZ(b, n), ec->f, stack);
	// xb <- xb + A * zb [C^2 + D + a2 * Z3]
	if (qrIsUnity(ec->A, ec->f))
		gf2Add2(ecX(b), ecZ(b, n), ec->f);
	else if (!qrIsZero(ec->A, ec->f))
	{
		qrMul(t2, ec->A, ecZ(b, n), ec->f, stack);
		gf2Add2(ecX(b), t2, ec->f);
	}
	// t1 <- t1 xb [(Z3 + D)X3]
	qrMul(t1, t1, ecX(b), ec->f, stack);
	// yb <- yb + t1 [(Z3 + D)X3 + B^2 Z3]
	gf2Add2(ecY(b, n), t1, ec->f);
}

static size_t ec2DblLD_deep(size_t n, size_t f_deep)
{
	return O_OF_W(2 * n) + f_deep;
}

// [3n]b <- 2[2n]a (P <- 2A)
static void ec2DblALD(word b[], const word a[], const ec_o* ec, void* stack)
{
	const size_t n = ec->f->n;
	// переменные в stack
	word* t1 = (word*)stack;
	stack = t1 + n;
	// pre
	ASSERT(ecIsOperable(ec) && ec->d == 3);
	ASSERT(ec2SeemsOnA(a, ec));
	ASSERT(a == b || wwIsDisjoint2(a, 2 * n, b, 3 * n));
	// xa == 0? => b <- O
	if (qrIsZero(ecX(a), ec->f))
	{
		qrSetZero(ecZ(b, n), ec->f);
		return;
	}
	// zb <- xa^2 [C]
	qrSqr(ecZ(b, n), ecX(a), ec->f, stack);
	// xb <- zb^2 + B [C^2 + a6]
	qrSqr(ecX(b), ecZ(b, n), ec->f, stack);
	gf2Add2(ecX(b), ec->B, ec->f);
	// yb <- ya^2 + B [Y1^2 + a6]
	qrSqr(ecY(b, n), ecY(a, n), ec->f, stack);
	gf2Add2(ecY(b, n), ec->B, ec->f);
	// yb <- yb + A zb [Y1^2 + a2*Z3 + a6]
	if (qrIsUnity(ec->A, ec->f))
		gf2Add2(ecY(b, n), ecZ(b, n), ec->f);
	else if (!qrIsZero(ec->A, ec->f))
	{
		qrMul(t1, ec->A, ecZ(b, n), ec->f, stack);
		gf2Add2(ecY(b, n), t1, ec->f);
	}
	// yb <- yb xb [(Y1^2 + a2*Z3 + a6) * X3]
	qrMul(ecY(b, n), ecY(b, n), ecX(b), ec->f, stack);
	// t1 <- B zb [a6 * Z3]
	qrMul(t1, ec->B, ecZ(b, n), ec->f, stack);
	// yb <- yb + t1 [(Y1^2 + a2*Z3 + a6) * X3 + a6 * Z3]
	gf2Add2(ecY(b, n), t1, ec->f);
}

static size_t ec2DblALD_deep(size_t n, size_t f_deep)
{
	return O_OF_W(n) + f_deep;
}

// [3n]c <- [3n]a + [3n]b (P <- P + P)
static void ec2AddLD(word c[], const word a[], const word b[],
	const ec_o* ec, void* stack)
{
	const size_t n = ec->f->n;
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
	ASSERT(ec2SeemsOn3(a, ec));
	ASSERT(ec2SeemsOn3(b, ec));
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
	// t1 <- xa zb [A]
	qrMul(t1, ecX(a), ecZ(b, n), ec->f, stack);
	// t2 <- xb za [B]
	qrMul(t2, ecX(b), ecZ(a, n), ec->f, stack);
	// t3 <- ya zb^2 [G]
	qrSqr(t3, ecZ(b, n), ec->f, stack);
	qrMul(t3, t3, ecY(a, n), ec->f, stack);
	// t4 <- yb za^2 [H]
	qrSqr(t4, ecZ(a, n), ec->f, stack);
	qrMul(t4, t4, ecY(b, n), ec->f, stack);
	// A == B => a == \pm b
	if (qrCmp(t1, t2, ec->f) == 0)
	{
		// t3 == t4 => a == b => c <- 2a
		if (qrCmp(t3, t4, ec->f) == 0)
			ec2DblLD(c, a, ec, stack);
		// t3 != t4 => a == -b => c <- O
		else
			qrSetZero(ecZ(c, n), ec->f);
		return;
	}
	// t5 <- t1 + t2 [E]
	gf2Add(t5, t1, t2, ec->f);
	// t6 <- t3 + t4 [I]
	gf2Add(t6, t3, t4, ec->f);
	// t5 <- t5 t6 [J]
	qrMul(t5, t5, t6, ec->f, stack);
	// xc <- t1^2 [C]
	qrSqr(ecX(c), t1, ec->f, stack);
	// yc <- t2^2 [D]
	qrSqr(ecY(c, n), t2, ec->f, stack);
	// t6 <- xc + yc [ec->f]
	gf2Add(t6, ecX(c), ecY(c, n), ec->f);
	// zc <- t6 za zb [ec->f * Z1 * Z2]
	qrMul(ecZ(c, n), ecZ(a, n), ecZ(b, n), ec->f, stack);
	qrMul(ecZ(c, n), t6, ecZ(c, n), ec->f, stack);
	// t4 <- t1 (t4 + yc) [A * (H + D)]
	gf2Add2(t4, ecY(c, n), ec->f);
	qrMul(t4, t1, t4, ec->f, stack);
	// xc <- t2 (xc + t3) + t4 [B * (C + G) + A * (H + D)]
	gf2Add2(ecX(c), t3, ec->f);
	qrMul(ecX(c), t2, ecX(c), ec->f, stack);
	gf2Add2(ecX(c), t4, ec->f);
	// t1 <- t1 t5 [A * J]
	qrMul(t1, t1, t5, ec->f, stack);
	// t3 <- t3 t6 [ec->f * G]
	qrMul(t3, t3, t6, ec->f, stack);
	// t1 <- (t1 + t3) t6 [(A * J + ec->f * G) * ec->f]
	gf2Add2(t1, t3, ec->f);
	qrMul(t1, t1, t6, ec->f, stack);
	// yc <- (t5 + zc) xc [(J + Z3) * X3]
	gf2Add(ecY(c, n), t5, ecZ(c, n), ec->f);
	qrMul(ecY(c, n), ecY(c, n), ecX(c), ec->f, stack);
	// yc <- yc + t1 [(A * J + ec->f * G) * ec->f + (J + Z3) * X3]
	gf2Add2(ecY(c, n), t1, ec->f);
}

static size_t ec2AddLD_deep(size_t n, size_t f_deep)
{
	return O_OF_W(6 * n) +
		utilMax(2,
			f_deep,
			ec2DblLD_deep(n, f_deep));
}

// [3n]c <- [3n]a + [2n]b (P <- P + A)
static void ec2AddALD(word c[], const word a[], const word b[],
	const ec_o* ec, void* stack)
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
	ASSERT(ec2SeemsOn3(a, ec));
	ASSERT(ec2SeemsOnA(b, ec));
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
	// t1 <- ya + yb za^2 [A]
	qrSqr(t1, ecZ(a, n), ec->f, stack);
	qrMul(t1, ecY(b, n), t1, ec->f, stack);
	gf2Add2(t1, ecY(a, n), ec->f);
	// t2 <- xa + xb za [B]
	qrMul(t2, ecX(b), ecZ(a, n), ec->f, stack);
	gf2Add2(t2, ecX(a), ec->f);
	// t2 == 0 => a == \pm b
	if (qrIsZero(t2, ec->f))
	{
		// t1 == 0 => a == b => c <- 2b
		if (qrIsZero(t1, ec->f))
			ec2DblALD(c, b, ec, stack);
		// t1 != 0 => a == -b => c <- O
		else
			qrSetZero(ecZ(c, n), ec->f);
		return;
	}
	// t3 <- t2 za [C]
	qrMul(t3, t2, ecZ(a, n), ec->f, stack);
	// zc <- t3^2 [C^2]
	qrSqr(ecZ(c, n), t3, ec->f, stack);
	// t4 <- xb zc [D]
	qrMul(t4, ecX(b), ecZ(c, n), ec->f, stack);
	// yc <- xb + yb [X2 + Y2]
	gf2Add(ecY(c, n), ecX(b), ecY(b, n), ec->f);
	// xc <- t2^2 + t1 + A t3 [B^2 + A + a2 * C]
	qrSqr(ecX(c), t2, ec->f, stack);
	gf2Add2(ecX(c), t1, ec->f);
	if (qrIsUnity(ec->A, ec->f))
		gf2Add2(ecX(c), t3, ec->f);
	else if (!qrIsZero(ec->A, ec->f))
	{
		qrMul(t2, ec->A, t3, ec->f, stack);
		gf2Add2(ecX(c), t2, ec->f);
	}
	// xc <- xc t3 + t1^2 [C * (A + B^2 + a2 * C) + A^2]
	qrMul(ecX(c), ecX(c), t3, ec->f, stack);
	qrSqr(t2, t1, ec->f, stack);
	gf2Add2(ecX(c), t2, ec->f);
	// yc <- yc zc^2 [(Y2 + X2) * Z3^2]
	qrSqr(t2, ecZ(c, n), ec->f, stack);
	qrMul(ecY(c, n), ecY(c, n), t2, ec->f, stack);
	// t4 <- t4 + xc [D + X3]
	gf2Add2(t4, ecX(c), ec->f);
	// t1 <- t1 t3 + zc [A * C + Z3]
	qrMul(t1, t1, t3, ec->f, stack);
	gf2Add2(t1, ecZ(c, n), ec->f);
	// t1 <- t1 t4 [(D + X3)(A * C + Z3)]
	qrMul(t1, t1, t4, ec->f, stack);
	// yc <- yc + t1 [(D + X3)(A * C + Z3) + (Y2 + X2) * Z3^2]
	gf2Add2(ecY(c, n), t1, ec->f);
}

static size_t ec2AddALD_deep(size_t n, size_t f_deep)
{
	return O_OF_W(4 * n) +
		utilMax(2,
			f_deep,
			ec2DblALD_deep(n, f_deep));
}

// [3n]c <- [3n]a - [3n]b (P <- P - P)
static void ec2SubLD(word c[], const word a[], const word b[],
	const ec_o* ec, void* stack)
{
	const size_t n = ec->f->n;
	// переменные в stack
	word* t = (word*)stack;
	stack = t + 3 * n;
	// pre
	ASSERT(ecIsOperable(ec) && ec->d == 3);
	ASSERT(ec2SeemsOn3(a, ec));
	ASSERT(ec2SeemsOn3(b, ec));
	ASSERT(wwIsSameOrDisjoint(a, c, 3 * n));
	ASSERT(wwIsSameOrDisjoint(b, c, 3 * n));
	// t <- -b
	qrMul(ecY(t, n), ecX(b), ecZ(b, n), ec->f, stack);
	gf2Add2(ecY(t, n), ecY(b, n), ec->f);
	qrCopy(ecX(t), ecX(b), ec->f);
	qrCopy(ecZ(t, n), ecZ(b, n), ec->f);
	// c <- a + t
	ec2AddLD(c, a, t, ec, stack);
}

static size_t ec2SubLD_deep(size_t n, size_t f_deep)
{
	return O_OF_W(3 * n) +
		utilMax(2,
			f_deep,
			ec2AddLD_deep(n, f_deep));
}

// [3n]c <- [3n]a - [2n]b (P <- P - A)
static void ec2SubALD(word c[], const word a[], const word b[],
	const ec_o* ec, void* stack)
{
	const size_t n = ec->f->n;
	// переменные в stack
	word* t = (word*)stack;
	stack = t + 2 * n;
	// pre
	ASSERT(ecIsOperable(ec) && ec->d == 3);
	ASSERT(ec2SeemsOn3(a, ec));
	ASSERT(ec2SeemsOnA(b, ec));
	ASSERT(wwIsSameOrDisjoint(a,  c, 3 * n));
	ASSERT(b == c || wwIsDisjoint2(b, 2 * n, c, 3 * n));
	// t <- -b
	wwCopy(t, b, 2 * n);
	gf2Add2(ecY(t, n), ecX(t), ec->f);
	// c <- a + t
	ec2AddALD(c, a, t, ec, stack);
}

static size_t ec2SubALD_deep(size_t n, size_t f_deep)
{
	return O_OF_W(2 * n) + ec2AddALD_deep(n, f_deep);
}

bool_t ec2CreateLD(ec_o* ec, const qr_o* f, const octet A[], const octet B[],
	void* stack)
{
	ASSERT(memIsValid(ec, sizeof(ec_o)));
	ASSERT(gf2IsOperable(f));
	ASSERT(memIsValid(A, f->no));
	ASSERT(memIsValid(B, f->no));
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
	// подготовить буферы для описания группы точек
	ec->base = ec->B + f->n;
	ec->order = ec->base + 2 * f->n;
	// настроить интерфейсы
	ec->froma = ec2FromALD;
	ec->toa = ec2ToALD;
	ec->neg = ec2NegLD;
	ec->add = ec2AddLD;
	ec->adda = ec2AddALD;
	ec->sub = ec2SubLD;
	ec->suba = ec2SubALD;
	ec->dbl = ec2DblLD;
	ec->dbla = ec2DblALD;
	ec->deep = utilMax(8,
		ec2ToALD_deep(f->n, f->deep),
		ec2NegLD_deep(f->n, f->deep),
		ec2AddLD_deep(f->n, f->deep),
		ec2AddALD_deep(f->n, f->deep),
		ec2SubLD_deep(f->n, f->deep),
		ec2SubALD_deep(f->n, f->deep),
		ec2DblLD_deep(f->n, f->deep),
		ec2DblALD_deep(f->n, f->deep));
	// настроить заголовок
	ec->hdr.keep = sizeof(ec_o) + O_OF_W(5 * f->n + 1);
	ec->hdr.p_count = 6;
	ec->hdr.o_count = 1;
	// все нормально
	return TRUE;
}

size_t ec2CreateLD_keep(size_t n)
{
	return sizeof(ec_o) + O_OF_W(5 * n + 1);
}

size_t ec2CreateLD_deep(size_t n, size_t f_deep)
{
	return utilMax(8,
		ec2ToALD_deep(n, f_deep),
		ec2NegLD_deep(n, f_deep),
		ec2AddLD_deep(n, f_deep),
		ec2AddALD_deep(n, f_deep),
		ec2SubLD_deep(n, f_deep),
		ec2SubALD_deep(n, f_deep),
		ec2DblLD_deep(n, f_deep),
		ec2DblALD_deep(n, f_deep));
}

/*
*******************************************************************************
Свойства кривой
*******************************************************************************
*/

bool_t ec2IsValid(const ec_o* ec, void* stack)
{
	// кривая работоспособна? поле ec->f корректно?
	// ec->deep >= ec->f->deep?
	// A, B \in ec->f, B != 0?
	return ecIsOperable2(ec) &&
		gf2IsValid(ec->f, stack) &&
		ec->deep >= ec->f->deep &&
		gf2IsIn(ec->A, ec->f) &&
		gf2IsIn(ec->B, ec->f) &&
		!qrIsZero(ec->B, ec->f);
}

size_t ec2IsValid_deep(size_t n)
{
	return gf2IsValid_deep(n);
}

bool_t ec2SeemsValidGroup(const ec_o* ec, void* stack)
{
	size_t n = ec->f->n;
	// переменные в stack
	word* t1 = (word*)stack;
	word* t2 = t1 + n + 1;
	word* t3 = t2 + n + 2;
	stack = t3 + 2 * n;
	// pre
	ASSERT(ecIsOperable(ec));
	// ecIsOperableGroup(ec) == TRUE? base \in ec?
	if (!ecIsOperableGroup(ec) ||
		!ec2IsOnA(ec->base, ec, stack))
		return FALSE;
	// [n + 1]t1 <- 2^m
	wwSetZero(t1, n + 1);
	wwFlipBit(t1, gf2Deg(ec->f));
	// [n + 2]t2 <- order * cofactor
	t2[n + 1] = zzMulW(t2, ec->order, n + 1, ec->cofactor);
	// t2 <- |t2 - (2^m + 1)|
	if (zzSubW2(t2, n + 2, 1))
		return FALSE;
	if (wwCmp2(t2, n + 2, t1, n + 1) >= 0)
		t2[n + 1] -= zzSub2(t2, t1, n + 1);
	else
		zzSub(t2, t1, t2, n + 1);
	// n <- длина t2
	n = wwWordSize(t2, n + 2);
	// n > ec->f->n => t2^2 > 4 2^m
	if (n > ec->f->n)
		return FALSE;
	// [2n]t3 <- ([n]t2)^2
	zzSqr(t3, t2, n, stack);
	// t1 <- 4 2^m
	wwFlipBit(t1, gf2Deg(ec->f));
	wwFlipBit(t1, gf2Deg(ec->f) + 2);
	// условие Хассе: t3 <= 4 2^m?
	return wwCmp2(t3, 2 * n, t3, ec->f->n + 1) <= 0;
}

size_t ec2SeemsValidGroup_deep(size_t n, size_t f_deep)
{
	return O_OF_W(4 * n + 3) +
		utilMax(2,
			ec2IsOnA_deep(n, f_deep),
			zzSqr_deep(n));
}

bool_t ec2IsSafeGroup(const ec_o* ec, size_t mov_threshold, void* stack)
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
	// t1 <- 2^m
	wwSetZero(t1, ec->f->n + 1);
	wwFlipBit(t1, gf2Deg(ec->f));
	// order == 2^m?
	if (wwCmp2(t1, ec->f->n + 1, ec->order, n1) == 0)
		return FALSE;
	// проверка MOV
	if (mov_threshold)
	{
		zzMod(t1, t1, ec->f->n + 1, ec->order, n1, stack);
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

size_t ec2IsSafeGroup_deep(size_t n)
{
	const size_t n1 = n + 1;
	return O_OF_W(2 * n1) +
		utilMax(3,
			priIsPrime_deep(n1),
			zzMod_deep(n + 1, n1),
			zzMulMod_deep(n1));
}

/*
*******************************************************************************
Арифметика аффинных точек

Сложение A <- A + A:
		1D + 2M + 1S + 9add \approx 26M

Удвоение A <- 2A:
		1D + 2M + 1S + 6add \approx 26M
*******************************************************************************
*/

bool_t ec2IsOnA(const word a[], const ec_o* ec, void* stack)
{
	const size_t n = ec->f->n;
	// переменные в stack
	word* t1 = (word*)stack;
	word* t2 = t1 + n;
	stack = t2 + n;
	// pre
	ASSERT(ecIsOperable(ec));
	// xa, ya \in ec->f?
	if (!ec2SeemsOnA(a, ec))
		return FALSE;
	// t1 <- (xa + A)xa^2 + B
	qrSqr(t1, ecX(a), ec->f, stack);
	gf2Add(t2, ecX(a), ec->A, ec->f);
	qrMul(t1, t1, t2, ec->f, stack);
	gf2Add2(t1, ec->B, ec->f);
	// t2 <- ya(ya + xa)
	gf2Add(t2, ecX(a), ecY(a, n), ec->f);
	qrMul(t2, t2, ecY(a, n), ec->f, stack);
	// t1 == t2?
	return qrCmp(t1, t2, ec->f) == 0;
}

size_t ec2IsOnA_deep(size_t n, size_t f_deep)
{
	return O_OF_W(2 * n) + f_deep;
}

void ec2NegA(word b[], const word a[], const ec_o* ec)
{
	const size_t n = ec->f->n;
	// pre
	ASSERT(ecIsOperable(ec));
	ASSERT(ec2SeemsOnA(a, ec));
	ASSERT(wwIsSameOrDisjoint(a, b, 3 * n));
	// b <- (xa, ya + xa)
	qrCopy(ecX(b), ecX(a), ec->f);
	gf2Add(ecY(b, n), ecX(a), ecY(a, n), ec->f);
}

bool_t ec2AddAA(word c[], const word a[], const word b[], const ec_o* ec,
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
	ASSERT(ec2SeemsOnA(a, ec));
	ASSERT(ec2SeemsOnA(b, ec));
	ASSERT(wwIsDisjoint(a, c, 2 * n));
	// xa == xb => (xa, ya) == \pm(xb, yb)
	if (qrCmp(ecX(a), ecX(b), ec->f) == 0)
	{
		// (xa, ya) == -(xb, yb)?
		if (qrCmp(ecY(a, n), ecY(b, n), ec->f) != 0)
			return FALSE;
		// xa == 0 => 2(xa, ya) == O
		if (qrIsZero(ecX(a), ec->f))
			return FALSE;
		// t1 <- ya / xa + xa [\lambda]
		qrDiv(t1, ecY(a, n), ecX(a), ec->f, stack);
		gf2Add2(t1, ecX(a), ec->f);
		// t2 <- xa
		qrCopy(t2, ecX(a), ec->f);
		// xc <- t1^2 + t1 + A [xa^2 + B / xa^2]
		qrSqr(ecX(c), t1, ec->f, stack);
		gf2Add2(ecX(c), t1, ec->f);
		gf2Add2(ecX(c), ec->A, ec->f);
		// t2 <- t1 * (t2 + xc) [\lambda(xa + xc)]
		gf2Add2(t2, ecX(c), ec->f);
		qrMul(t2, t1, t2, ec->f, stack);
		// yc <- ya + t2 + xc
		gf2Add(ecY(c, n), ecY(a, n), t2, ec->f);
		gf2Add2(ecY(c, n), ecX(c), ec->f);
		// получена аффинная точка
		return TRUE;
	}
	// t1 <- xa
	qrCopy(t1, ecX(a), ec->f);
	// xc <- xa + xb
	gf2Add(ecX(c), ecX(a), ecX(b), ec->f);
	// t2 <- ya + yb
	gf2Add(t2, ecY(a, n), ecY(b, n), ec->f);
	// t2 <- t2 / xc [\lambda]
	qrDiv(t2, t2, ecX(c), ec->f, stack);
	// t3 <- t2^2 [\lambda^2]
	qrSqr(t3, t2, ec->f, stack);
	// xc <- xc + t2 + t3 + A [\lambda^2 + \lambda + (xa + xb) + A]
	gf2Add2(ecX(c), t2, ec->f);
	gf2Add2(ecX(c), t3, ec->f);
	gf2Add2(ecX(c), ec->A, ec->f);
	// t1 <- t1 + xc [xa + xc]
	gf2Add2(t1, ecX(c), ec->f);
	// t1 <- t1 * t2 [(xa + xc)\lambda]
	qrMul(t1, t1, t2, ec->f, stack);
	// yc <- xc + ya + t1 [(xa + xc)\lambda + xc + ya]
	gf2Add(ecY(c, n), ecY(a, n), ecX(c), ec->f);
	gf2Add2(ecY(c, n), t1, ec->f);
	// получена аффинная точка
	return TRUE;
}

size_t ec2AddAA_deep(size_t n, size_t f_deep)
{
	return O_OF_W(3 * n) + f_deep;
}

bool_t ec2SubAA(word c[], const word a[], const word b[], const ec_o* ec,
	void* stack)
{
	const size_t n = ec->f->n;
	// переменные в stack
	word* t = (word*)stack;
	stack = t + 2 * n;
	// t <- -b
	ec2NegA(t, b, ec);
	// с <- a + t
	return ec2AddAA(c, a, t, ec, stack);
}

size_t ec2SubAA_deep(size_t n, size_t f_deep)
{
	return O_OF_W(2 * n) + ec2AddAA_deep(n, f_deep);
}
