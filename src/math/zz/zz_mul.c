/*
*******************************************************************************
\file zz_mul.c
\brief Multiple-precision unsigned integers: multiplicative operations
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2012.04.22
\version 2019.06.26
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/mem.h"
#include "bee2/core/util.h"
#include "bee2/core/word.h"
#include "bee2/math/ww.h"
#include "bee2/math/zz.h"
#include "zz_lcl.h"

/*
*******************************************************************************
Умножение / возведение в квадрат

\todo Возведение в квадрат за один проход (?), сначала с квадратов (?).
\todo Умножение Карацубы.
*******************************************************************************
*/

word zzMulW(word b[], const word a[], size_t n, register word w)
{
	register word carry = 0;
	register dword prod;
	size_t i;
	ASSERT(wwIsSameOrDisjoint(a, b, n));
	for (i = 0; i < n; ++i)
	{
		_MUL(prod, w, a[i]);
		prod += carry;
		b[i] = (word)prod;
		carry = (word)(prod >> B_PER_W);
	}
	prod = 0, w = 0;
	return carry;
}

word zzAddMulW(word b[], const word a[], size_t n, register word w)
{
	register word carry = 0;
	register dword prod;
	size_t i;
	ASSERT(wwIsSameOrDisjoint(a, b, n));
	for (i = 0; i < n; ++i)
	{
		_MUL(prod, w, a[i]);
		prod += carry;
		prod += b[i];
		b[i] = (word)prod;
		carry = (word)(prod >> B_PER_W);
	}
	prod = 0, w = 0;
	return carry;
}

word zzSubMulW(word b[], const word a[], size_t n, register word w)
{
	register word borrow = 0;
	register dword prod;
	size_t i;
	ASSERT(wwIsSameOrDisjoint(a, b, n));
	for (i = 0; i < n; ++i)
	{
		_MUL(prod, w, a[i]);
		prod = (dword)0 - prod;
		prod += b[i];
		prod -= borrow;
		b[i] = (word)prod;
		borrow = WORD_0 - (word)(prod >> B_PER_W);
	}
	prod = 0, w = 0;
	return borrow;
}

void zzMul(word c[], const word a[], size_t n, const word b[], size_t m, 
	void* stack)
{
	register word carry = 0;
	register dword prod;
	size_t i, j;
	ASSERT(wwIsDisjoint2(a, n, c, n + m));
	ASSERT(wwIsDisjoint2(b, m, c, n + m));
	wwSetZero(c, n + m);
	for (i = 0; i < n; ++i)
	{
		for (j = 0; j < m; ++j)
		{
			_MUL(prod, a[i], b[j]);
			prod += carry;
			prod += c[i + j];
			c[i + j] = (word)prod;
			carry = (word)(prod >> B_PER_W);
		}
		c[i + j] = carry;
		carry = 0;
	}
	prod = 0;
}

size_t zzMul_deep(size_t n, size_t m)
{
	return 0;
}

void zzSqr(word b[], const word a[], size_t n, void* stack)
{
	register word carry = 0;
	register word carry1;
	register dword prod;
	size_t i, j;
	ASSERT(wwIsDisjoint2(a, n, b, n + n));
	// b <- \sum_{i < j} a_i a_j B^{i + j}
	wwSetZero(b, n + n);
	for (i = 0; i < n; ++i)
	{
		for (j = i + 1; j < n; ++j)
		{
			_MUL(prod, a[i], a[j]);
			prod += carry;
			prod += b[i + j];
			b[i + j] = (word)prod;
			carry = (word)(prod >> B_PER_W);
		}
		b[i + j] = carry;
		carry = 0;
	}
	// b <- 2 b
	for (i = 0; i < n + n; ++i)
	{
		carry1 = b[i] >> (B_PER_W - 1);
		b[i] = (b[i] << 1) | carry;
		carry = carry1;
	}
	// b <- b + \sum_i a_i^2 B^{i + i}
	for (i = 0; i < n; ++i)
	{
		_MUL(prod, a[i], a[i]);
		prod += carry;
		prod += b[i + i];
		b[i + i] = (word)prod;
		prod >>= B_PER_W;
		prod += b[i + i + 1];
		b[i + i + 1] = (word)prod;
		carry = (word)(prod >> B_PER_W);
	}
	prod = 0;
	carry = carry1 = 0;
}

size_t zzSqr_deep(size_t n)
{
	return 0;
}

/*
*******************************************************************************
Деление на машинное слово

В функции zzModW2() сначала определяется значение (b = B \mod mod):
	r = \sum_i a[i] b^i \equiv \sum_i a[i] B^i = a \mod mod,
которое затем приводится \mod mod.
Используется следующий алгоритм:
	r = (r1 r0) <- 0
	for i = n - 1,..., 0:
		r <- (r1 b + r0)b + a[i]	(*)
	while (r1 != 0)
		r <- r1 b + (r0 % mod)		(**)
	return r0 % mod
После каждой итерации (*):
	r <= (B - 1)(1 + b + b^2) <= (B - 1)(mod^2 - mod + 1)
	  <= (B - 1)(B + 1) < B^2.
По окончании первой итерации (**):
	r <= (B - 1)(mod - 1) + (mod - 1) = B(mod - 1).
По окончании второй итерации (**):
	r <= (mod - 1)(mod - 1) + (mod - 1) = mod(mod - 1) < B.
Таким образом, r \mod mod = r0 \mod mod.
*******************************************************************************
*/

word zzDivW(word q[], const word a[], size_t n, register word w)
{
	register word r = 0;
	register dword divisor;
	ASSERT(w > 0);
	ASSERT(wwIsSameOrDisjoint(a, q, n));
	while (n--)
	{
		divisor = r;
		divisor <<= B_PER_W;
		divisor |= a[n];
		q[n] = (word)(divisor / w);
		r = (word)(divisor % w);
	}
	divisor = 0, w = 0;
	return r;
}

word zzModW(const word a[], size_t n, register word w)
{
	register word r = 0;
	register dword divisor;
	ASSERT(w > 0);
	ASSERT(wwIsValid(a, n));
	while (n--)
	{
		divisor = r;
		divisor <<= B_PER_W;
		divisor |= a[n];
		r = (word)(divisor % w);
	}
	divisor = 0, w = 0;
	return r;
}

word zzModW2(const word a[], size_t n, register word w)
{
	register word r0 = 0;
	register dword r1 = 0;
	register word b;
	// pre
	ASSERT(w > 0);
	ASSERT(w <= WORD_BIT_HALF);
	ASSERT(wwIsValid(a, n));
	// b <- B \mod mod
	b = (WORD_MAX - w + 1) % w;
	// (r1 r0) <- \sum_i a[i] b^i
	while (n--)
	{
		r1 *= b;
		r1 += r0;
		r1 *= b;
		r1 += a[n];
		r0 = (word)r1;
		r1 >>= B_PER_W;
	}
	// нормализация
#ifdef SAFE_FAST
	while (r1 != 0)
	{
		r1 *= b;
		r1 += r0 % w;
		r0 = (word)r1;
		r1 >>= B_PER_W;
	}
	r0 %= w;
#else
	r1 *= b;
	r1 += r0 % w;
	r0 = (word)r1;
	r1 >>= B_PER_W;
	r1 *= b;
	r1 += r0 % w;
	r0 = (word)r1 % w;
#endif
	// очистка и возврат
	r1 = 0, b = w = 0;
	return r0;
}

/*
*******************************************************************************
Общее деление

\opt При делении слов определять остаток по частному: (/,*) вместо (/, %).

\todo Убрать ограничение n >= m в zzDiv().

\todo T. Jabelean. An Algorithm for exact division. J. of Symb. Computations, 
15 (2): 169-180, 1993.

\todo: В zzMod() отказаться от divident.

В функциях zzDiv(), zzMod() делимое a = a[n - 1]...a[0] и делитель
b = b[m - 1]...b[0] предварительно нормализуются:
	a = a[n]...a[0] <- a * 2^shift;
	b = b[m - 1]...b[0] <- b * 2^shift.
Здесь shift --- минимальное натуральное т.ч. старший бит b[m - 1] * 2^shift
равняется 1.

Деление выполняется по алгоритму 14.20 из [Menezes A., van Oorschot P.,
Vanstone S. Handbook of Applied Cryptography]:
	for i = n, n - 1, ...., m:
		if a[i] == b[m - 1]											(#)
			q[i - m] <- B - 1
		else
			q[i - m] <- a[i]a[i - 1] div b[m - 1]
		while (q[i - m] * b[m - 1]b[m - 2] > a[i]a[i - 1]a[i - 2])	(##)
			q[i - m]--
		a <- a - q[i - m] * b * B^{i - m}
		if (a < 0)
			a += b * B^{i - m}, q[i - m]--
	return q = q[n - m]...q[0] --- частное и a --- остаток

В реализации вместо (#):
	d <- a[i]a[i - 1] div b[m - 1]
	if d >= B
		d <- B - 1
	q[i - m] <- d

\opt Если a[i] == b[m - 1] в (#), то цикл (##) можно не выполнять:
	q[i - m] * b[m - 1]b[m - 2] <=
		(B - 1) * (a[i] * B + (B - 1)) =
		B^2 * a[i] + B^2 - 1 - a[i] * B < a[i]a[i - 1]a[i - 2]

\opt Если известен остаток d = a[i]a[i - 1] mod b[m - 1], то (##) можно
	заменить на
		while (q[i - m] * b[m - 2] > d * B + a[i - 2])
			q[i - m]--, d += b[m - 1]
*******************************************************************************
*/

void zzDiv(word q[], word r[], const word a[], size_t n, const word b[],
	size_t m, void* stack)
{
	register dword dividentHi;
	register word borrow;
	register size_t shift;
	size_t i;
	// переменные в stack
	word* divident;		/*< нормализованное делимое (n + 1 слово) */
	word* divisor;		/*< нормализованный делитель (m слов) */
	word* mul;			/*< вспомогательное произведение (3 слова) */
	// pre
	ASSERT(n >= m);
	ASSERT(wwIsValid(a, n) && wwIsValid(b, m));
	ASSERT(m > 0 && b[m - 1] > 0);
	ASSERT(wwIsDisjoint2(q, n + 1 - m, r, m));
	ASSERT(a == r || wwIsDisjoint2(a, n, r, m));
	// a < b?
	if (wwCmp2(a, n, b, m) < 0)
	{
		// q <- 0, r <- a
		wwSetZero(q, n - m + 1);
		wwCopy(r, a, m);
		return;
	}
	// делим на одноразрядное число?
	if (m == 1)
	{
		r[0] = zzDivW(q, a, n, b[0]);
		return;
	}
	// резервируем переменные в stack
	divident = (word*)stack;
	divisor = divident + n + 1;
	mul = divisor + m;
	stack = mul + 3;
	// divident <- a
	wwCopy(divident, a, n);
	divident[n] = 0;
	// divisor <- b
	wwCopy(divisor, b, m);
	// нормализация
	shift = wordCLZ(b[m - 1]);
	wwShHi(divident, n + 1, shift);
	wwShHi(divisor, m, shift);
	// цикл по разрядам делимого
	for (i = n; i >= m; --i)
	{
		// вычислить пробное частное
		dividentHi = divident[i];
		dividentHi <<= B_PER_W;
		dividentHi |= divident[i - 1];
		dividentHi /= divisor[m - 1];
		if (dividentHi > WORD_MAX)
			q[i - m] = WORD_MAX;
		else
			q[i - m] = (word)dividentHi;
		// уточнить пробное частное
		wwCopy(mul, divisor + m - 2, 2);
		mul[2] = zzMulW(mul, mul, 2, q[i - m]);
		while (wwCmp2(mul, 3, divident + i - 2, 3) > 0)
		{
			q[i - m]--;
			mul[2] -= zzSub2(mul, divisor + m - 2, 2);
		}
		// учесть пробное частное
		borrow = zzSubMulW(divident + i - m, divisor, m, q[i - m]);
		divident[i] -= borrow;
		if (divident[i] > (word)~borrow)
		{
			// окончательно подправить пробное частное
			q[i - m]--;
			// корректирующее сложение
			divident[i] += zzAdd2(divident + i - m, divisor, m);
		}
	}
	// денормализация
	wwShLo(divident, n + 1, shift);
	// сохранить остаток
	wwCopy(r, divident, m);
	// очистить регистровые переменные
	shift = 0;
	borrow = 0;
	dividentHi = 0;
}

size_t zzDiv_deep(size_t n, size_t m)
{
	return O_OF_W(n + m + 4);
}

void zzMod(word r[], const word a[], size_t n, const word b[], size_t m, void* stack)
{
	register dword dividentHi;
	register word temp;
	register size_t shift;
	size_t i;
	// переменные в stack
	word* divident;		/*< нормализованное делимое (n + 1 слово) */
	word* divisor;		/*< нормализованный делитель (m слов) */
	word* mul;			/*< вспомогательное произведение (3 слова) */
	// pre
	ASSERT(wwIsValid(a, n) && wwIsValid(b, m));
	ASSERT(m > 0 && b[m - 1] > 0);
	ASSERT(a == r || wwIsDisjoint2(a, n, r, m));
	// a < b?
	if (wwCmp2(a, n, b, m) < 0)
	{
		// r <- a
		if (n < m)
			wwSetZero(r + n, m - n), m = n;
		wwCopy(r, a, m);
		return;
	}
	// делим на одноразрядное число?
	if (m == 1)
	{
		r[0] = zzModW(a, n, b[0]);
		return;
	}
	// резервируем переменные в stack
	divident = (word*)stack;
	divisor = divident + n + 1;
	mul = divisor + m;
	stack = mul + 3;
	// divident <- a
	wwCopy(divident, a, n);
	divident[n] = 0;
	// divisor <- b
	wwCopy(divisor, b, m);
	// нормализация
	shift = wordCLZ(b[m - 1]);
	wwShHi(divident, n + 1, shift);
	wwShHi(divisor, m, shift);
	// цикл по разрядам делимого
	for (i = n; i >= m; --i)
	{
		// вычислить пробное частное
		dividentHi = divident[i];
		dividentHi <<= B_PER_W;
		dividentHi |= divident[i - 1];
		dividentHi /= divisor[m - 1];
		if (dividentHi > WORD_MAX)
			temp = WORD_MAX;
		else
			temp = (word)dividentHi;
		// уточнить пробное частное
		wwCopy(mul, divisor + m - 2, 2);
		mul[2] = zzMulW(mul, mul, 2, temp);
		while (wwCmp2(mul, 3, divident + i - 2, 3) > 0)
		{
			temp--;
			mul[2] -= zzSub2(mul, divisor + m - 2, 2);
		}
		// учесть пробное частное
		temp = zzSubMulW(divident + i - m, divisor, m, temp);
		divident[i] -= temp;
		if (divident[i] > (word)~temp)
			// корректирующее сложение
			divident[i] += zzAdd2(divident + i - m, divisor, m);
	}
	// денормализация
	wwShLo(divident, n + 1, shift);
	// сохранить остаток
	wwCopy(r, divident, m);
	// очистить регистровые переменные
	shift = 0;
	temp = 0;
	dividentHi = 0;
}

size_t zzMod_deep(size_t n, size_t m)
{
	return O_OF_W(n + m + 4);
}
