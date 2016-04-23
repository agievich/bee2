/*
*******************************************************************************
\file zz.c
\brief Multiple-precision unsigned integers
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2012.04.22
\version 2015.11.02
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/mem.h"
#include "bee2/core/util.h"
#include "bee2/core/word.h"
#include "bee2/math/ww.h"
#include "bee2/math/zm.h"
#include "bee2/math/zz.h"

/*
*******************************************************************************
Замечания по языку C

В языке С все операции с беззнаковыми целыми, которые короче unsigned int,
выполняются после их предварительного приведения к unsigned int
[так назваемое integer promotions, см. C99, п. 6.3.1.4].

Сказанное учтено в реализации. Пусть, например, требуется проверить, что для
слов a, b типа word выполнено условие:
	a * b + 1 \equiv 0 (\mod 2^B_PER_W).
Можно подумать, что можно организовать проверку следующим образом:
\code
	ASSERT(a * b + 1 == 0);
\endcode
Данная проверка будет давать неверный результат при
sizeof(word) < sizeof(unsigned int). Правильный способ:
\code
	ASSERT((word)(a * b + 1) == 0);
\endcode

\warning При тестировании арифметики длина слова искусственно понижалась
до 16 битов. При этом при включении определеннных опций компилятор GCC
выдавал ошибки предупреждения при сравнении word с ~word:
comparison of promoted ~unsigned with unsigned [-Werror=sign-compare].
*******************************************************************************
*/

/*
*******************************************************************************
Макросы умножения слов

_MUL:
	dword c;
	word a, b;
	c <- a, c <- c * b;

_MUL_LO:
	word a, b;
	return (word)(a * b);

\todo _MUL_HI.
*******************************************************************************
*/

#if defined(_MSC_VER) && (B_PER_W == 32)
	#include <intrin.h>
	#define _MUL(c, a, b)\
		(c) = __emulu((word)(a), (word)(b))
#else
	#define _MUL(c, a, b)\
		(c) = (word)(a), (c) *= (word)(b)
#endif 

#define _MUL_LO(c, a, b)\
	(c) = (word)(a) * (word)(b);

/*
*******************************************************************************
Свойства
*******************************************************************************
*/

bool_t zzIsEven(const word a[], size_t n)
{
	ASSERT(wwIsValid(a, n));
	return n == 0 || a[0] % 2 == 0;
}

bool_t zzIsOdd(const word a[], size_t n)
{
	ASSERT(wwIsValid(a, n));
	return n > 0 && a[0] % 2 == 1;
}

/*
*******************************************************************************
Аддитивные операции

Функции zzAddW(), zzAddW2() регулярны -- сложение не прекращается, даже если 
слово переноса w становится нулевым. Для ускорения сложения (с потерей)
регулярности оператор
	for (i = 0; i < n; ++i)
следует заменить на 
	for (i = 0; w && i < n; ++i)
Аналогичное замечание касается функций zzSubW(), zzSubW2().

В функциях zzSubW(), zzSubW2() использовано тождество:
	WORD_MAX - w = 11...11 + ~w + 00...01 = ~w
Если до вычитания a -= w выполняется неравенство a < w, то результат 
вычитания имеет вид 
	a' = WORD_MAX + 1 + a - w = a + 1 + ~w => ~w < a'.
Если же до вычитания a >= w, то
	a' = a - w <= WORD_MAX - w = ~w => ~w >= a'.
Таким образом, предикат (~w < a') является новым флагом заема.
*******************************************************************************
*/

word zzAdd(word c[], const word a[], const word b[], size_t n)
{
	register word carry = 0;
	register word w;
	size_t i;
	ASSERT(wwIsSameOrDisjoint(a, c, n));
	ASSERT(wwIsSameOrDisjoint(b, c, n));
	for (i = 0; i < n; ++i)
	{
#ifndef SAFE_FAST
		w = a[i] + carry;
		carry = wordLess01(w, carry);
		c[i] = w + b[i];
		carry |= wordLess01(c[i], w);
#else
		w = a[i] + carry;
		if (w < carry)
			c[i] = b[i];
		else
			w += b[i], carry = w < b[i], c[i] = w;
#endif
	}
	w = 0;
	return carry;
}

word zzAdd2(word b[], const word a[], size_t n)
{
	register word carry = 0;
	register word w;
	size_t i;
	ASSERT(wwIsSameOrDisjoint(a, b, n));
	for (i = 0; i < n; ++i)
	{
#ifndef SAFE_FAST
		w = a[i] + carry;
		carry = wordLess01(w, carry);
		b[i] += w;
		carry |= wordLess01(b[i], w);
#else
		w = a[i] + carry;
		if (w >= carry)
			w += b[i], carry = w < b[i], b[i] = w;
#endif
	}
	w = 0;
	return carry;
}

word zzAdd3(word c[], const word a[], size_t n, const word b[], size_t m)
{
	if (n > m)
	{
		wwCopy(c + m, a + m, n - m);
		return zzAddW2(c + m, n - m, zzAdd(c, a, b, m));
	}
	if (n < m)
	{
		wwCopy(c + n, b + n, m - n);
		return zzAddW2(c + n, m - n, zzAdd(c, a, b, n));
	}
	return zzAdd(c, a, b, n);
}

word zzAddW(word b[], const word a[], size_t n, register word w)
{
	size_t i;
	ASSERT(wwIsSameOrDisjoint(a, b, n));
	for (i = 0; i < n; ++i)
#ifndef SAFE_FAST
		b[i] = a[i] + w, w = wordLess01(b[i], w);
#else
		b[i] = a[i] + w, w = b[i] < w;
#endif
	return w;
}

word zzAddW2(word a[], size_t n, register word w)
{
	size_t i;
	ASSERT(wwIsValid(a, n));
#ifndef SAFE_FAST
	for (i = 0; i < n; ++i)
		a[i] += w, w = wordLess(a[i], w);
#else
	for (i = 0; w && i < n; ++i)
		a[i] += w, w = a[i] < w;
#endif
	return w;
}

bool_t SAFE(zzIsSumEq)(const word c[], const word a[], const word b[], 
	size_t n)
{
	register word diff = 0;
	register word carry = 0;
	register word w;
	size_t i;
	ASSERT(wwIsValid(a, n));
	ASSERT(wwIsValid(b, n));
	ASSERT(wwIsValid(c, n));
	for (i = 0; i < n; ++i)
	{
		w = a[i] + carry;
		carry = wordLess01(w, carry);
		diff |= c[i] ^ (w + b[i]);
		carry |= wordLess01(c[i], w);
	}
	w = 0;
	return wordEq(diff | carry, 0);
}

bool_t FAST(zzIsSumEq)(const word c[], const word a[], const word b[], 
	size_t n)
{
	register word carry = 0;
	register word w;
	size_t i;
	ASSERT(wwIsValid(a, n));
	ASSERT(wwIsValid(b, n));
	ASSERT(wwIsValid(c, n));
	for (i = 0; i < n; ++i)
	{
		w = a[i] + carry;
		if (w < carry)
			if (c[i] != b[i])
				return FALSE;
			else
				continue;
		if (c[i] != (word)(w + b[i]))
			return FALSE;
		carry = c[i] < w;
	}
	w = 0;
	return carry == 0;
}

bool_t SAFE(zzIsSumWEq)(const word b[], const word a[], size_t n, 
	register word w)
{
	register word diff = 0;
	size_t i;
	ASSERT(wwIsValid(a, n));
	ASSERT(wwIsValid(b, n));
	for (i = 0; i < n; ++i)
	{
		diff |= b[i] ^ (a[i] + w);
		w = wordLess01(b[i], a[i]);
	}
	return wordEq(diff | w, 0);
}

bool_t FAST(zzIsSumWEq)(const word b[], const word a[], size_t n, 
	register word w)
{
	size_t i;
	ASSERT(wwIsValid(a, n));
	ASSERT(wwIsValid(b, n));
	for (i = 0; i < n; ++i)
	{
		if (b[i] != (word)(a[i] + w))
		{
			w = 0;
			return FALSE;
		}
		w = b[i] < a[i];
	}
	return w == 0;
}

word zzSub(word c[], const word a[], const word b[], size_t n)
{
	register word borrow = 0;
	register word w;
	size_t i;
	ASSERT(wwIsSameOrDisjoint(a, c, n));
	ASSERT(wwIsSameOrDisjoint(b, c, n));
	for (i = 0; i < n; ++i)
	{
#ifndef SAFE_FAST
		w = b[i] + borrow;
		borrow = wordLess01(w, borrow);
		borrow |= wordLess01(a[i], w);
		c[i] = a[i] - w;
#else
		w = a[i] - borrow;
		if (w > (word)~borrow)
			c[i] = ~b[i];
		else
			w -= b[i], borrow = w > (word)~b[i], c[i] = w;
#endif
	}
	w = 0;
	return borrow;
}

word zzSub2(word b[], const word a[], size_t n)
{
	register word borrow = 0;
	register word w;
	size_t i;
	ASSERT(wwIsSameOrDisjoint(a, b, n));
	for (i = 0; i < n; ++i)
	{
#ifndef SAFE_FAST
		w = a[i] + borrow;
		borrow = wordLess01(w, borrow);
		borrow |= wordLess01(b[i], w);
		b[i] -= w;
#else
		w = b[i] - borrow;
		if (w > (word)~borrow)
			w = ~a[i];
		else
			w -= a[i], borrow = w > (word)~a[i];
		b[i] = w;
#endif
	}
	w = 0;
	return borrow;
}

word zzSubW(word b[], const word a[], size_t n, register word w)
{
	size_t i;
	ASSERT(wwIsSameOrDisjoint(a, b, n));
	for (i = 0; i < n; ++i)
#ifndef SAFE_FAST
		b[i] = a[i] - w, w = wordLess01(~w, b[i]);
#else
		b[i] = a[i] - w, w = b[i] > (word)~w;
#endif
	return w;
}

word zzSubW2(word a[], size_t n, register word w)
{
	size_t i;
	ASSERT(wwIsValid(a, n));
#ifndef SAFE_FAST
	for (i = 0; i < n; ++i)
		a[i] -= w, w = wordLess01(~w, a[i]);
#else
	for (i = 0; w && i < n; ++i)
		a[i] -= w, w = a[i] > (word)~w;
#endif
	return w;
}

void zzNeg(word b[], const word a[], size_t n)
{
	size_t i;
	ASSERT(wwIsSameOrDisjoint(a, b, n));
	for (i = 0; i < n; ++i)
		b[i] = ~a[i];
	zzAddW2(b, n, 1);
}

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
Квадратный корень

Базовый алгоритм [Cohen, A course in Computational Algebraic Number Theory]:
	t <- произвольное целое >= \sqrt(a) // например, 2^{(len(a) + 1) / 2}
	do
		b <- t
		t <- (b + a / b) / 2 // деления нацело
	while (b > t)
	return b

Обоснование:
-#	В начале непоследней итерации 
		t >= \sqrt(a) => 
		a / b <= \sqrt(a) => 
		t уменьшается или остается прежним.
-#	Если t остается прежним (t == b), то b -- искомый корень снизу (см. Cohen).

Реализация:
-#	Если a / b >= b, то итерации будут закончены. При этом a -- полный квадрат
	только если a делится нацело на b и a / b == b.
*******************************************************************************
*/

bool_t zzSqrt(word b[], const word a[], size_t n, void* stack)
{
	register int cmp;
	size_t m = (n + 1) / 2;
	word* t = (word*)stack;
	word* r = t + m + 1;
	stack = r + m;
	// pre
	ASSERT(wwIsDisjoint2(a, n, b, m));
	// нормализовать a и обработать a == 0
	if ((n = wwWordSize(a, n)) == 0)
	{
		wwSetZero(b, m);
		return TRUE;
	}
	// t <- 2^{(len(a) + 1) / 2} - 1 (умещается в m слов)
	wwSetZero(t, m + 1);
	wwSetBit(t, (wwBitSize(a, n) + 1) / 2, 1);
	zzSubW2(t, m + 1, 1);
	ASSERT(t[m] == 0);
	// итерации
	while (1)
	{
		// b <- t
		wwCopy(b, t, m);
		m = wwWordSize(b, m);
		// t <- a / b
		zzDiv(t, r, a, n, b, m, stack);
		// частное [n - m + 1]t включает ненулевое слово t[m] => t > b
		if (n - m == m && t[m] > 0)
			return FALSE;
		// сравнить [m]b и [m]t
		cmp = wwCmp(b, t, m);
		// b == t => a -- полный квадрат <=> r == 0
		if (cmp == 0)
			return wwIsZero(r, m);
		// b < t => выход, a -- не полный квадрат
		if (cmp < 0)
			break;
		// t <- (b + t) / 2
		t[m] = zzAdd2(t, b, m);
		wwShLo(t, m + 1, 1);
		ASSERT(t[m] == 0);
	}
	return FALSE;
}

size_t zzSqrt_deep(size_t n)
{
	const size_t m = (n + 1) / 2;
	return m + 1 + m + zzDiv_deep(n, m);
}

/*
*******************************************************************************
Деление

\opt При делении слов определять остаток по частному: (/,*) вместо (/, %).

\todo Убрать ограничение n >= m в zzDiv.

\todo T. Jabelean. An Algorithm for exact division. J. of Symb. Computations, 
15 (2): 169-180, 1993.

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
	ASSERT(w < WORD_BIT_HALF);
	ASSERT(wwIsValid(a, n));
	// b <- B \mod mod
	b = WORD_MAX % w + 1;
	if (b == w)
		return n ? a[0] % w : 0;
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
	while (r1 != 0)
	{
		r1 *= b;
		r1 += r0 % w;
		r0 = (word)r1;
		r1 >>= B_PER_W;
	}
	r0 %= w;
	// очистка и возврат
	r1 = 0, b = w = 0;
	return r0;
}

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

// todo: отказаться от divident
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

/*
*******************************************************************************
Алгоритм Евклида

В функциях zzGCD(), zzExGCD() реализованы бинарные алгоритмы,
не требующие прямых делений.

В функции zzExGCD() пересчитываются числа da, db, da0, db0 такие, что
	da0 * aa - db0 * bb = (-1)^sign0 u,
	da * aa - db * bb = (-1)^sign v,
где aa = a / 2^s, bb = b / 2^s, s -- max целое т.ч. 2^s | a и 2^s | b.

Числа u и v поддерживают вычисление НОД(aa, bb). Если u >= v, то u
заменяется на u - v, а если u < v, то v заменяется на v - u.
Как только u == 0 вычисления останавливаются и возвращается тройка
(2^s * v, da, db).

В функции zzExGCD() реализован алгоритм:
	u <- aa
	da0 <- 1, db0 <- 0, sign0 <- 0
	v <- bb
	da <- 0, db <- 1, sign <- 0
	пока (u != 0)
	{
		пока (u -- четное)
			u <- u / 2
			если (da0 -- четное) // db0 также четное
				da0 <- da0 / 2, db0 <- db0 / 2
			иначе
				da0 <- (da0 + bb) / 2, db0 <- (db0 + aa) / 2
		пока (v -- четное)
			v <- v / 2
			если (da -- четное) // db также четное
				da <- da / 2, db <- db / 2
			иначе
				da <- (da + bb) / 2, db <- (db + aa) / 2
		если (u >= v)
			u <- u - v
			если (sign0 == sign)
				da0 <- da0 - da, db0 <- db0 - db
				если (da0 < 0)
					da0 <- -da0, db0 <- -db0, sign0 <- 1 - sign0
			иначе // sign0 != sign
				da0 <- da0 + da, db0 <- db0 + db
				если (da0 > bb)
					da0 <- da0 - bb, db0 <- db0 - aa			(*)
		иначе // u < v
			v <- v - u
			если (sign0 == sign)
				da <- da - da0, db <- db - db0
				если (da < 0)
					da <- -da, db <- -db, sign <- 1 - sign
			иначе // sign0 != sign
				da <- da + da0, db <- db + db0
				если (da > bb)
					da <- da - bb, db <- db - aa				(**)
	}
	Корректировки (*), (**) гарантируют, что da0, da < bb, а db0, db < aa.

\todo Эксперименты с различными реализациями алгоритма Евклида.
Проведенные эксперименты: бинарный алгоритм опережает обычный
(полные деления) примерно в 2 раза и опережает смешанный (полные деления
и деления на 2) примерно в 1.5 раза.

\todo Регуляризация?
*******************************************************************************
*/

void zzGCD(word d[], const word a[], size_t n, const word b[], size_t m,
	void* stack)
{
	register size_t s;
	// переменные в stack
	word* u = (word*)stack;
	word* v = u + n;
	stack = v + m;
	// pre
	ASSERT(wwIsDisjoint2(a, n, d, MIN2(n, m)));
	ASSERT(wwIsDisjoint2(b, m, d, MIN2(n, m)));
	ASSERT(!wwIsZero(a, n) && !wwIsZero(b, m));
	// d <- 0
	wwSetZero(d, MIN2(n, m));
	// u <- a, v <- b
	wwCopy(u, a, n);
	wwCopy(v, b, m);
	// найти максимальное s т.ч. 2^s | u и 2^s | v
	s = utilMin(2, wwLoZeroBits(u, n), wwLoZeroBits(v, m));
	// u <- u / 2^s, v <- v / 2^s
	wwShLo(u, n, s);
	n = wwWordSize(u, n);
	wwShLo(v, m, s);
	m = wwWordSize(v, m);
	// итерации
	do
	{
		wwShLo(u, n, wwLoZeroBits(u, n));
		n = wwWordSize(u, n);
		wwShLo(v, m, wwLoZeroBits(v, m));
		m = wwWordSize(v, m);
		// u >= v?
		if (wwCmp2(u, n, v, m) >= 0)
			// u <- u - v
			zzSubW2(u + m, n - m, zzSub2(u, v, m));
		else
			// v <- v - u
			zzSubW2(v + n, m - n, zzSub2(v, u, n));
	}
	while (!wwIsZero(u, n));
	// d <- v
	wwCopy(d, v, m);
	// d <- d * 2^s
	wwShHi(d, W_OF_B(wwBitSize(d, m) + s), s);
	// очистка
	s = 0;
}

size_t zzGCD_deep(size_t n, size_t m)
{
	return O_OF_W(n + m);
}

bool_t zzIsCoprime(const word a[], size_t n, const word b[], size_t m, void* stack)
{
	word* d = (word*)stack;
	stack = d + MIN2(n, m);
	// a == 0 => (a, b) = b
	if (wwIsZero(a, n))
		return wwIsW(b, m, 1);
	// b == 0 => (a, b) = a
	if (wwIsZero(b, m))
		return wwIsW(a, n, 1);
	// d <- (a, b), d == 1?
	zzGCD(d, a, n, b, m, stack);
	return wwIsW(d, MIN2(n, m), 1);
}

size_t zzIsCoprime_deep(size_t n, size_t m)
{
	return O_OF_W(MIN2(n, m)) + zzGCD_deep(n, m);
}

void zzLCM(word d[], const word a[], size_t n, const word b[], size_t m,
	void* stack)
{
	// переменные в stack
	word* prod = (word*)stack;
	word* gcd = prod + n + m;
	stack = gcd + MIN2(n, m);
	// pre
	ASSERT(wwIsDisjoint2(a, n, d, MAX2(n, m)));
	ASSERT(wwIsDisjoint2(b, m, d, MAX2(n, m)));
	ASSERT(!wwIsZero(a, n) && !wwIsZero(b, m));
	// d <- 0
	wwSetZero(d, MAX2(n, m));
	// нормализация
	n = wwWordSize(a, n);
	m = wwWordSize(b, m);
	// prod <- a * b
	zzMul(prod, a, n, b, m, stack);
	// gcd <- (a, b)
	zzGCD(gcd, a, n, b, m, stack);
	// (n, m) <- (|prod|, |gcd|)
	if (n < m)
		SWAP(n, m);
	n += m;
	m = wwWordSize(gcd, m);
	// d <- prod \mod gcd
	zzMod(d, prod, n, gcd, m, stack);
}

size_t zzLCM_deep(size_t n, size_t m)
{
	return O_OF_W(n + m + MIN2(n, m)) +
		utilMax(3, 
			zzMul_deep(n, m), 
			zzGCD_deep(n, m), 
			zzMod_deep(n + m, MIN2(n, m)));
}

int zzExGCD(word d[], word da[], word db[], const word a[], size_t n,
	const word b[], size_t m, void* stack)
{
	register size_t s;
	register size_t nu, mv;
	register int sign0 = 0, sign = 1;
	// переменные в stack
	word* aa = (word*)stack;
	word* bb = aa + n;
	word* u = bb + m;
	word* v = u + n;
	word* da0 = v + m;
	word* db0 = da0 + m;
	stack = db0 + n;
	// pre
	ASSERT(wwIsDisjoint3(da, m, db, n, d, MIN2(n, m)));
	ASSERT(wwIsDisjoint2(a, n, d, MIN2(n, m)));
	ASSERT(wwIsDisjoint2(b, m, d, MIN2(n, m)));
	ASSERT(wwIsDisjoint2(a, n, da, m));
	ASSERT(wwIsDisjoint2(b, m, da, m));
	ASSERT(wwIsDisjoint2(a, n, db, n));
	ASSERT(wwIsDisjoint2(b, m, db, n));
	ASSERT(!wwIsZero(a, n) && !wwIsZero(b, m));
	// d <- 0, da0 <- 1, db0 <- 0, da <- 0, db <- 1
	wwSetZero(d, MIN2(n, m));
	wwSetW(da0, m, 1);
	wwSetZero(db0, n);
	wwSetZero(da, m);
	wwSetW(db, n, 1);
	// найти максимальное s т.ч. 2^s | a и 2^s | b
	s = utilMin(2, wwLoZeroBits(a, n), wwLoZeroBits(b, m));
	// aa <- a / 2^s, bb <- b / 2^s
	wwCopy(aa, a, n), wwShLo(aa, n, s), n = wwWordSize(aa, n);
	wwCopy(bb, b, m), wwShLo(bb, m, s), m = wwWordSize(bb, m);
	// u <- aa, v <- bb
	wwCopy(u, aa, n);
	wwCopy(v, bb, m);
	nu = n, mv = m;
	// итерации
	do
	{
		// пока u четное
		for (; wwTestBit(u, 0) == 0; wwShLo(u, nu, 1))
			if (wwTestBit(da0, 0) == 0)
			{
				// da0 <- da0 / 2, db0 <- db0 / 2
				wwShLo(da0, m, 1);
				ASSERT(wwTestBit(db0, 0) == 0);
				wwShLo(db0, n, 1);
			}
			else
			{
				// da0 <- (da0 + bb) / 2, db0 <- (db0 + aa) / 2
				wwShLoCarry(da0, m, 1, zzAdd2(da0, bb, m));
				ASSERT(wwTestBit(db0, 0) == 1);
				wwShLoCarry(db0, n, 1, zzAdd2(db0, aa, n));
			}
		// пока v четное
		for (; wwTestBit(v, 0) == 0; wwShLo(v, mv, 1))
			if (wwTestBit(da, 0) == 0)
			{
				// da <- da / 2, db <- db / 2
				wwShLo(da, m, 1);
				ASSERT(wwTestBit(db, 0) == 0);
				wwShLo(db, n, 1);
			}
			else
			{
				// da <- (da + bb) / 2, db <- (db + aa) / 2
				wwShLoCarry(da, m, 1, zzAdd2(da, bb, m));
				ASSERT(wwTestBit(db, 0) == 1);
				wwShLoCarry(db, n, 1, zzAdd2(db, aa, n));
			}
		// нормализация
		nu = wwWordSize(u, nu);
		mv = wwWordSize(v, mv);
		// u >= v?
		if (wwCmp2(u, nu, v, mv) >= 0)
		{
			// u <- u - v
			zzSubW2(u + mv, nu - mv, zzSub2(u, v, mv));
			if (sign0 != sign)
			{
				if (zzAdd2(da0, da, m) || wwCmp(da0, bb, m) >= 0)
					zzSub2(da0, bb, m);
				if (zzAdd2(db0, db, n) || wwCmp(db0, aa, n) >= 0)
					zzSub2(db0, aa, n);
			}
			else if (wwCmp(da0, da, m) >= 0)
			{
				ASSERT(wwCmp(db0, db, n) >= 0);
				zzSub2(da0, da, m);
				zzSub2(db0, db, n);
			}
			else
			{
				ASSERT(wwCmp(db0, db, n) < 0);
				zzSub(da0, da, da0, m);
				zzSub(db0, db, db0, n);
				sign0 = 1 - sign0;
			}
		}
		else
		{
			// v <- v - u
			zzSubW2(v + nu, mv - nu, zzSub2(v, u, nu));
			if (sign0 != sign)
			{
				if (zzAdd2(da, da0, m) || wwCmp(da, bb, m) >= 0)
					zzSub2(da, bb, m);
				if (zzAdd2(db, db0, n) || wwCmp(db, aa, n) >= 0)
					zzSub2(db, aa, n);
			}
			else if (wwCmp(da, da0, m) >= 0)
			{
				ASSERT(wwCmp(db, db0, n) >= 0);
				zzSub2(da, da0, m);
				zzSub2(db, db0, n);
			}
			else
			{
				ASSERT(wwCmp(db, db0, n) < 0);
				zzSub(da, da0, da, m);
				zzSub(db, db0, db, n);
				sign = 1 - sign;
			}
		}
	}
	while (!wwIsZero(u, nu));
	// d <- v
	wwCopy(d, v, m);
	// d <- d * 2^s
	wwShHi(d, W_OF_B(wwBitSize(d, m) + s), s);
	// очистка
	s = 0;
	sign0 = sign = 0;
	nu = mv = 0;
	// возврат
	return sign;
}

size_t zzExGCD_deep(size_t n, size_t m)
{
	return O_OF_W(3 * n + 3 * m);
}

/*
*******************************************************************************
Квадратичные вычеты

Реализован алгоритм 2.148 из [Menezes A., van Oorschot P., Vanstone S.
Handbook of Applied Cryptography] в редакции CТБ 34.101.45 (приложение Ж).

В некоторых приложениях область определения символа Якоби расширяется
до любых b по следующим правилам:
	(a / 2) = 0, если a четное,
	(a / 2) = (-1)^{(a^2 - 1) / 8}, если a нечетное.
	(a / 1) = 1,
	(1 / 0) = 1,
	(a / 0) = 0, если a != 1.
Такое расширение реализовано, например, в пакете Mathematica. Мы не 
реализовали расширение, поскольку оно не востребовано в криптографическом 
контексте и только замедляет расчеты.
*******************************************************************************
*/

int zzJacobi(const word a[], size_t n, const word b[], size_t m, void* stack)
{
	register int t = 1;
	register size_t s;
	// переменные в stack
	word* u = (word*)stack;
	word* v = u + n;
	stack = v + m;
	// pre
	ASSERT(wwIsValid(a, n));
	ASSERT(zzIsOdd(b, m));
	// v <- b
	wwCopy(v, b, m);
	m = wwWordSize(v, m);
	// u <- a \mod b
	zzMod(u, a, n, v, m, stack);
	n = wwWordSize(u, n);
	// основной цикл
	while (wwCmpW(v, m, 1) > 0)
	{
		// u == 0 => (u / v) <- 0
		if (wwIsZero(u, n))
		{
			t = 0;
			break;
		}
		// u == 1 => (u / v) <- s
		if (wwIsW(u, n, 1))
			break;
		// s <- max_{2^i | u}i
		s = wwLoZeroBits(u, n);
		// s -- нечетное, v \equiv 3, 5 \mod 8 => t <- -t
		if (s % 2 && ((v[0] & 7) == 3 || (v[0] & 7) == 5))
			t = -t;
		// u <- u / 2^s
		wwShLo(u, n, s);
		n = wwWordSize(u, n);
		// u, v \equiv 3 \mod 4 => t <- -t
		if ((u[0] & 3) == 3 && (v[0] & 3) == 3)
			t = -t;
		// v <- v \mod u
		zzMod(v, v, m, u, n, stack);
		m = wwWordSize(v, m);
		// v <-> u
		wwSwap(u, v, n);
		s = m, m = n, n = s;
	}
	// символ Якоби
	return t;
}

size_t zzJacobi_deep(size_t n, size_t m)
{
	return O_OF_W(n + m) + 
		utilMax(2, 
			zzMod_deep(n, m), 
			zzMod_deep(m, n));
}

/*
*******************************************************************************
Модулярная арифметика

В zzDivMod() реализован упрощенный вариант zzExGCD(): рассчитываются
только da0, da, причем da0 = divident (а не 1).

\todo Реализовать в zzDivMod() случай произвольного (а не только 
нечетного) mod.

В zzAlmostDivMod() реализован алгоритм Калиски [B.S.Kaliski Jr. The Montgomery 
inverse and its applications. IEEE Transactions on Computers, 44(8):1064–1065, 
1995]:
	u <- a
	da0 <- 1
	v <- mod
	da <- 0
	k <- 0
	пока (u != 0)
	{
		если (v -- четное)
			v <- v / 2, da0 <- da0 * 2
		иначе если (u -- четное)
			u <- u / 2, da <- da * 2
		иначе если (v > u)
			v <- (v - u) / 2, da <- da + da0, da0 <- da0 * 2
		иначе // если (u >= v)
			u <- (u - v) / 2, da0 <- da0 + da, da <- da * 2
		k <- k + 1
	}
	если (da >= mod)
		da <- da - mod
	da <- mod - da
	return (da, k)

Инварианты на итерациях zzAlmostDivMod():
	mod = v * da0 + u * da
	a * da = -v (\mod mod)

В оригинальной статье Калиски доказано, что при 0 < a < mod: 
-	числа da, da0 лежат в интервале [0, 2 * mod - 1];
-	wwBitSize(mod) <= k <= 2 * wwBitSize(mod).

\remark В [E. Savas, K. Koc. The Montgomery Modular Inverse -- Revisited. 
IEEE Transactions on Computers, 49(7):763–766, 2000] рассмотрен случай, когда 
a и mod < 2^m, причем условие a < mod может нарушаться. Доказано, что в этом 
случае
-	числа da, da0 лежат в интервале [0, 2 * mod - 1];
-	wwBitSize(mod) <= k <= m + wwBitSize(mod).

\todo В перечисленных статьях предполагается, что mod -- простое число.
Проверить, что результаты можно распространить на случай произвольного 
нечетного mod. Можно ли сузить интервал [0, 2 * mod - 1]?
*******************************************************************************
*/

void zzAddMod(word c[], const word a[], const word b[], const word mod[],
	size_t n)
{
	ASSERT(wwIsSameOrDisjoint(a, c, n));
	ASSERT(wwIsSameOrDisjoint(b, c, n));
	ASSERT(wwIsDisjoint(c, mod, n));
	ASSERT(wwCmp(a, mod, n) < 0 && wwCmp(b, mod, n) < 0);
	// вычисления (a + b >= mod => a + b - mod < mod)
	if (zzAdd(c, a, b, n) || wwCmp(c, mod, n) >= 0)
		zzSub2(c, mod, n);
}

void zzAddWMod(word b[], const word a[], register word w, 
	const word mod[], size_t n)
{
	ASSERT(wwIsSameOrDisjoint(a, b, n));
	ASSERT(wwIsDisjoint(b, mod, n));
	ASSERT(wwCmp(a, mod, n) < 0 && wwCmpW(mod, n, w) > 0);
	// a + w >= mod => a + w - mod < mod
	if (zzAddW(b, a, n, w) || wwCmp(b, mod, n) >= 0)
		zzSub2(b, mod, n);
	w = 0;
}

void zzSubMod(word c[], const word a[], const word b[], const word mod[],
	size_t n)
{
	ASSERT(wwIsSameOrDisjoint(a, c, n));
	ASSERT(wwIsSameOrDisjoint(b, c, n));
	ASSERT(wwIsDisjoint(c, mod, n));
	ASSERT(wwCmp(a, mod, n) < 0 && wwCmp(b, mod, n) < 0);
	// a < b => a - b + mod < mod
	if (zzSub(c, a, b, n))
		zzAdd2(c, mod, n);
}

void zzSubWMod(word b[], const word a[], register word w, 
	const word mod[], size_t n)
{
	ASSERT(wwIsSameOrDisjoint(a, b, n));
	ASSERT(wwIsDisjoint(b, mod, n));
	ASSERT(wwCmp(a, mod, n) < 0 && wwCmpW(mod, n, w) >= 0);
	// a < w => a - w + mod < mod
	if (zzSubW(b, a, n, w))
		zzAdd2(b, mod, n);
	w = 0;
}

void zzNegMod(word b[], const word a[], const word mod[], size_t n)
{
	ASSERT(wwIsSameOrDisjoint(a, b, n));
	ASSERT(wwIsDisjoint(b, mod, n));
	ASSERT(wwCmp(a, mod, n) < 0);
	// a != 0 => b <- mod - a
	if (!wwIsZero(a, n))
		zzSub(b, mod, a, n);
	else
		wwSetZero(b, n);
}

void zzMulMod(word c[], const word a[], const word b[], const word mod[],
	size_t n, void* stack)
{
	word* prod = (word*)stack;
	stack = prod + 2 * n;
	ASSERT(wwCmp(a, mod, n) < 0);
	ASSERT(wwCmp(b, mod, n) < 0);
	ASSERT(wwIsValid(c, n));
	ASSERT(n > 0 && mod[n - 1] != 0);
	zzMul(prod, a, n, b, n, stack);
	zzMod(c, prod, 2 * n, mod, n, stack);
}

size_t zzMulMod_deep(size_t n)
{
	return O_OF_W(2 * n) + 
		utilMax(2, 
			zzMul_deep(n, n), 
			zzMod_deep(2 * n, n));
}

void zzSqrMod(word b[], const word a[], const word mod[], size_t n,
	void* stack)
{
	word* sqr = (word*)stack;
	stack = sqr + 2 * n;
	ASSERT(wwCmp(a, mod, n) < 0);
	ASSERT(wwIsValid(b, n));
	ASSERT(n > 0 && mod[n - 1] != 0);
	zzSqr(sqr, a, n, stack);
	zzMod(b, sqr, 2 * n, mod, n, stack);
}

size_t zzSqrMod_deep(size_t n)
{
	return O_OF_W(2 * n) +
		utilMax(2, 
			zzSqr_deep(n), 
			zzMod_deep(2 * n, n));
}

void zzDivMod(word b[], const word divident[], const word a[],
	const word mod[], size_t n, void* stack)
{
	register size_t nu, nv;
	register int sign0 = 0, sign = 1;
	// переменные в stack
	word* u = (word*)stack;
	word* v = u + n;
	word* da0 = v + n;
	word* da = da0 + n;
	stack = da + n;
	// pre
	ASSERT(wwCmp(a, mod, n) < 0);
	ASSERT(wwCmp(divident, mod, n) < 0);
	ASSERT(wwIsDisjoint(b, mod, n));
	ASSERT(zzIsOdd(mod, n) && mod[n - 1] != 0);
	// da0 <- divident, da <- 0
	wwCopy(da0, divident, n);
	wwSetZero(da, n);
	// u <- a, v <- mod
	wwCopy(u, a, n);
	wwCopy(v, mod, n);
	nu = wwWordSize(u, n);
	nv = n;
	// итерации со следующими инвариантами:
	//	da0 * a \equiv (-1)^sign0 * divident * u \mod mod
	//	da * a \equiv (-1)^sign * divident * v \mod mod
	while (!wwIsZero(u, nu))
	{
		// пока u -- четное
		for (; wwTestBit(u, 0) == 0; wwShLo(u, nu, 1))
			if (wwTestBit(da0, 0) == 0)
				// da0 <- da0 / 2
				wwShLo(da0, n, 1);
			else
				// da0 <- (da0 + mod) / 2
				wwShLoCarry(da0, n, 1, zzAdd2(da0, mod, n));
		// пока v -- четное
		for (; wwTestBit(v, 0) == 0; wwShLo(v, nv, 1))
			if (wwTestBit(da, 0) == 0)
				// da <- da / 2
				wwShLo(da, n, 1);
			else
				// da <- (da + mod) / 2
				wwShLoCarry(da, n, 1, zzAdd2(da, mod, n));
		// нормализация
		nu = wwWordSize(u, nu);
		nv = wwWordSize(v, nv);
		// u >= v?
		if (wwCmp2(u, nu, v, nv) >= 0)
		{
			// u <- u - v
			zzSubW2(u + nv, nu - nv, zzSub2(u, v, nv));
			if (sign0 != sign)
			{
				if (zzAdd2(da0, da, n) || wwCmp(da0, mod, n) >= 0)
					zzSub2(da0, mod, n);
			}
			else if (wwCmp(da0, da, n) >= 0)
				zzSub2(da0, da, n);
			else
				zzSub(da0, da, da0, n),
				sign0 = 1 - sign0;
		}
		else
		{
			// v <- v - u
			zzSubW2(v + nu, nv - nu, zzSub2(v, u, nu));
			if (sign0 != sign)
			{
				if (zzAdd2(da, da0, n) || wwCmp(da, mod, n) >= 0)
					zzSub2(da, mod, n);
			}
			else if (wwCmp(da, da0, n) >= 0)
				zzSub2(da, da0, n);
			else
				zzSub(da, da0, da, n),
				sign = 1 - sign;
		}
	}
	// здесь v == (a, mod)
	EXPECT(wwIsW(v, nv, 1));
	// \gcd(a, mod) != 1? b <- 0
	if (!wwIsW(v, nv, 1))
		wwSetZero(b, n);
	// здесь da * a \equiv (-1)^sign * divident \mod mod
	// если sign == 1, то b <- mod - da, иначе b <- da
	else if (sign == 1)
		zzSub(b, mod, da, n);
	else
		wwCopy(b, da, n);
	// очистка
	sign0 = sign = 0;
	nu = nv = 0;
}

size_t zzDivMod_deep(size_t n)
{
	return O_OF_W(4 * n);
}

void zzInvMod(word b[], const word a[], const word mod[], size_t n,
	void* stack)
{
	word* divident = (word*)stack;
	stack = divident + n;
	wwSetW(divident, n, 1);
	zzDivMod(b, divident, a, mod, n, stack);
}

size_t zzInvMod_deep(size_t n)
{
	return O_OF_W(n) + zzDivMod_deep(n);
}

void zzDoubleMod(word b[], const word a[], const word mod[], size_t n)
{
	register word carry = 0;
	register word hi;
	size_t i;
	// pre
	ASSERT(wwCmp(a, mod, n) < 0);
	ASSERT(wwIsSameOrDisjoint(a, b, n));
	ASSERT(wwIsDisjoint(b, mod, n));
	// умножение на 2
	for (i = 0; i < n; ++i)
		hi = a[i] >> (B_PER_W - 1),
		b[i] = a[i] << 1 | carry,
		carry = hi;
	// корректировка
	if (carry || wwCmp(b, mod, n) >= 0)
		zzSub2(b, mod, n);
	// очистка
	hi = carry = 0;
}

void zzHalfMod(word b[], const word a[], const word mod[], size_t n)
{
	register word carry = 0;
	register word lo;
	// pre
	ASSERT(wwIsSameOrDisjoint(a, b, n));
	ASSERT(wwIsDisjoint(mod, b, n));
	ASSERT(zzIsOdd(mod, n) && mod[n - 1] != 0);
	ASSERT(wwCmp(a, mod, n) < 0);
	// a -- нечетное? => b <- (a + p) / 2
	if (wwTestBit(b, 0))
	{
		carry = zzAdd(b, a, mod, n);
		while (n--)
			lo = b[n] & 1,
			b[n] = b[n] >> 1 | carry << (B_PER_W - 1),
			carry = lo;
	}
	// a -- четное? => b <- a / 2
	else
		while (n--)
			lo = a[n] & 1,
			b[n] = a[n] >> 1 | carry << (B_PER_W - 1),
			carry = lo;
	// очистка
	lo = carry = 0;
}

size_t zzAlmostInvMod(word b[], const word a[], const word mod[], size_t n,
	void* stack)
{
	register size_t k = 0;
	size_t nu, nv;
	// переменные в stack
	word* u = (word*)stack;
	word* v = u + n;
	word* da0 = v + n;
	word* da = da0 + n + 1;
	stack = da + n + 1;
	// pre
	ASSERT(!wwIsZero(a, n));
	ASSERT(wwCmp(a, mod, n) < 0);
	ASSERT(wwIsDisjoint(b, mod, n));
	ASSERT(zzIsOdd(mod, n) && mod[n - 1] != 0);
	// da0 <- 1, da <- 0
	wwSetW(da0, n + 1, 1);
	wwSetZero(da, n + 1);
	// u <- a, v <- mod
	wwCopy(u, a, n);
	wwCopy(v, mod, n);
	nu = wwWordSize(u, n);
	nv = n;
	// пока (u != 0)
	do
	{
		// v -- четное?
		if (zzIsEven(v, nv))
		{
			wwShLo(v, nv, 1);
			nv = wwWordSize(v, nv);
			wwShHi(da0, n + 1, 1);
		}
		// u -- четное?
		else if (zzIsEven(u, nu))
		{
			wwShLo(u, nu, 1);
			nu = wwWordSize(u, nu);
			wwShHi(da, n + 1, 1);
		}
		// v > u?
		else if (wwCmp2(v, nv, u, nu) > 0)
		{
			ASSERT(nv >= nu);
			zzSubW2(v + nu, nv - nu, zzSub2(v, u, nu));
			wwShLo(v, nv, 1); 
			nv = wwWordSize(v, nv);
			zzAdd2(da, da0, n + 1);
			wwShHi(da0, n + 1, 1);
		}
		// u >= v?
		else
		{
			ASSERT(nu >= nv);
			zzSubW2(u + nv, nu - nv, zzSub2(u, v, nv));
			wwShLo(u, nu, 1); 
			nu = wwWordSize(u, nu);
			zzAdd2(da0, da, n + 1);
			wwShHi(da, n + 1, 1);
		}
		// k <- k + 1
		k = k + 1;
	}
	while (!wwIsZero(u, nu));
	// здесь v == (a, mod)
	EXPECT(wwIsW(v, nv, 1));
	// \gcd(a, mod) != 1? b <- 0
	if (!wwIsW(v, nv, 1))
		wwSetZero(b, n);
	// da >= mod => da -= mod
	if (wwCmp2(da, n + 1, mod, n) >= 0)
		da[n] -= zzSub2(da, mod, n);
	ASSERT(wwCmp2(da, n + 1, mod, n) < 0);
	// b <- mod - da
	zzNegMod(b, da, mod, n);
	// возврат
	return k;
}

size_t zzAlmostInvMod_deep(size_t n)
{
	return O_OF_W(4 * n + 2);
}

bool_t zzRandMod(word a[], const word mod[], size_t n, gen_i rng, 
	void* rng_state)
{
	register size_t l;
	register size_t i;
	// pre
	ASSERT(wwIsDisjoint(a, mod, n));
	ASSERT(n > 0 && mod[n - 1] != 0);
	// генерировать
	l = wwBitSize(mod, n);
	i =  B_PER_IMPOSSIBLE;
	do
	{
		rng(a, O_OF_B(l), rng_state);
		wwFrom(a, a, O_OF_B(l));
		wwTrimHi(a, n, l);
	}
	while (wwCmp(a, mod, n) >= 0 && i--);
	// выход
	l = 0;
	return i != SIZE_MAX;
}

bool_t zzRandNZMod(word a[], const word mod[], size_t n, gen_i rng, 
	void* rng_state)
{
	register size_t l;
	register size_t i;
	// pre
	ASSERT(wwIsDisjoint(a, mod, n));
	ASSERT(n > 0 && mod[n - 1] != 0 && wwCmpW(mod, n, 1) > 0);
	// генерировать
	l = wwBitSize(mod, n);
	i = (l <= 16) ? 2 * B_PER_IMPOSSIBLE : B_PER_IMPOSSIBLE;
	do
	{
		rng(a, O_OF_B(l), rng_state);
		wwFrom(a, a, O_OF_B(l));
		wwTrimHi(a, n, l);
	}
	while ((wwIsZero(a, n) || wwCmp(a, mod, n) >= 0) && i--);
	// выход
	l = 0;
	return i != SIZE_MAX;
}

/*
*******************************************************************************
Специальные модули / специальные редукции

Редукция Крэндалла:
	[input]:	a = a1 B^n + a0,  mod = B^n - c
	[iter1]:	a <- a0 + a1 c
				a <= (B^n - 1) + (B^n - 1)(B - 1) <= B^n(B - 1) => a1 < B
	[iter2]:	a <- a0 + a1 c
				a <= (B^n - 1) + (B - 1)c => a < 2 (B^n - c) (n >= 2)
	[correct]:	if (a >= B^n - c)
					a <- (a + c) \mod B^n = a - (B^n - c) \mod B^n
Редукция Барретта:
	[pre]		\mu <- B^{2n} / mod
	[realtime]	q <- (a \div B^{n - 1} * \mu) \div B^{n + 1} (\approx a \div m)
				a <- a \mod B^{n + 1} - (q * mod) \mod B^{n + 1}
				if (a < 0)
					a <- a + B^n
				while (a >= mod) [не более 2 раз]
					a <- a - mod
Редукция Монтгомери (функция zzModMont(), алгоритм из работы
[Dusse S. R., Kaliski B. S. A cryptographic library for the Motorola
DSP56000. Advances in Cryptology -- EUROCRYPT 90, LNCS 473, 230–244. 1990]:
	[pre]		m* <- -mod[0]^{-1} \bmod B
	[realtime]	for (i = 0; i < n; ++i)
					t <- a[i] * m* \mod B
					a <- a + t * mod * B^i
				a <- a / B^n
				if (a >= mod)
					a <- a - mod

В алгоритме, реализованном в функции zzModMont(), на промежуточных шагах
вычислений получается число, не превосходящее 2 * mod * R. Для хранения
этого числа может потребоваться 2 * n + 1 машинных слов. Поэтому в функции
резервируется дополнительное машинное слово hi.

Редукция Монтгомери для модуля mod = B^n - c, 0 < c < B, n >= 2, упрощается:
	[pre]		m* <- c^{-1} \bmod B
	[realtime]	carry <- 0, borrow <- 0
				for (i = 0; i < n; ++i)
					t1 <- a[i] * m* \mod B
					t2 <- t1 * c \div B
					a[i + 1] <- a[i - 1] - t2 - borrow (зафикс. новый borrow)
					a[i + n] <- a[i + n] + t1 + carry (зафикс. новый carry)
				a <- a - borrow * B^{n + 1}
				a <- a + carry * B^{n + n}
				a <- a / B^n
				if (a >= mod)
					a <- a - mod
*******************************************************************************
*/

void zzRed(word a[], const word mod[], size_t n, void* stack)
{
	ASSERT(wwIsDisjoint2(a, 2 * n, mod, n));
	zzMod(a, a, 2 * n, mod, n, stack);
}

size_t zzRed_deep(size_t n)
{
	return zzMod_deep(2 * n, n);
}

void zzRedCrand(word a[], const word mod[], size_t n, void* stack)
{
	register word carry;
	register dword prod;
	// pre
	ASSERT(wwIsDisjoint2(a, 2 * n, mod, n));
	ASSERT(n >= 2 && mod[0] && wwIsRepW(mod + 1, n - 1, WORD_MAX));
	// iter1
	carry = zzAddMulW(a, a + n, n, WORD_0 - mod[0]);
	// iter2
	_MUL(prod, carry, WORD_0 - mod[0]);
	prod += a[0];
	a[0] = (word)prod;
	prod >>= B_PER_W;
	if (zzAddW2(a + 1, n - 1, (word)prod) || wwCmp(a, mod, n) >= 0)
		// correct
		zzAddW2(a, n, WORD_0 - mod[0]);
	// очистка
	prod = 0;
	carry = 0;
}

size_t zzRedCrand_deep(size_t n)
{
	return 0;
}

void zzCalcBarrParam(word barr_param[], const word mod[], size_t n, 
	void* stack)
{
	word* divident = (word*)stack;
	stack = divident + 2 * n + 1;
	// pre
	ASSERT(wwIsDisjoint2(barr_param, n + 2, mod, n));
	ASSERT(n > 0 && mod[n - 1] != 0);
	// divident <- B^{2n}
	wwSetZero(divident, 2 * n);
	divident[2 * n] = 1;
	// barr_param <- divident \div mod
	zzDiv(barr_param, divident, divident, 2 * n + 1, mod, n, stack);
}

size_t zzCalcBarrParam_deep(size_t n)
{
	return O_OF_W(2 * n + 1) + zzDiv_deep(2 * n + 1, n);
}

void zzRedBarr(word a[], const word mod[], size_t n, const word barr_param[],
	void* stack)
{
	// переменные в stack
	word* q = (word*)stack;
	word* qm = q + (n + 1) + (n + 2);
	stack = qm + (n + 2) + n;
	// pre
	ASSERT(wwIsDisjoint2(a, 2 * n, mod, n));
	ASSERT(wwIsDisjoint2(a, 2 * n, barr_param, n + 2));
	ASSERT(n > 0 && mod[n - 1] != 0);
	// q <- (a \div B^{n - 1}) * barr_param
	zzMul(q, a + n - 1, n + 1, barr_param, n + 2, stack);
	// qm <- (q \div B^{n + 1}) * mod
	zzMul(qm, q + n + 1, n + 2, mod, n, stack);
	// a <- [n + 1]a - [n + 1]qm
	zzSub2(a, qm, n + 1);
	// пока a >= m: a <- a - m
	while (wwCmp2(a, n + 1, mod, n) >= 0)
		a[n] -= zzSub2(a, mod, n);
}

size_t zzRedBarr_deep(size_t n)
{
	return O_OF_W(4 * n + 5) + 
		utilMax(2, 
			zzMul_deep(n + 1, n + 2), 
			zzMul_deep(n + 2, n));
}

void zzRedMont(word a[], const word mod[], size_t n, register word mont_param,
	void* stack)
{
	register word carry = 0;
	register word t;
	size_t i;
	// pre
	ASSERT(wwIsDisjoint2(a, 2 * n, mod, n));
	ASSERT(n > 0 && mod[n - 1] != 0 && mod[0] % 2);
	ASSERT((word)(mod[0] * mont_param + 1) == 0);
	// редукция в редакции Дуссе -- Калиски
	for (i = 0; i < n; ++i)
	{
		_MUL_LO(t, a[i], mont_param);
		carry += zzAddW2(a + i + n, n - i, zzAddMulW(a + i, mod, n, t));
	}
	ASSERT(wwIsZero(a, n));
	ASSERT(carry <= 1);
	// a <- a / B^n
	wwCopy(a, a + n, n);
	a[n] = carry;
	// a >= mod?
	if (wwCmp2(a, n + 1, mod, n) >= 0)
		// a <- a - mod
		a[n] -= zzSub2(a, mod, n);
	// очистка
	carry = t = 0;
}

size_t zzRedMont_deep(size_t n)
{
	return 0;
}

void zzRedCrandMont(word a[], const word mod[], size_t n, 
	register word mont_param, void* stack)
{
	register word carry = 0;
	register word borrow = 0;
	register dword prod;
	register word t;
	size_t i;
	// pre
	ASSERT(wwIsDisjoint2(a, 2 * n, mod, n));
	ASSERT(n >= 2 && mod[0] % 2  && wwIsRepW(mod + 1, n - 1, WORD_MAX));
	ASSERT((word)(mod[0] * mont_param + 1) == 0);
	// редукция
	for (i = 0; i < n; ++i)
	{
		_MUL_LO(t, a[i], mont_param);
		_MUL(prod, t, WORD_0 - mod[0]);
		t += carry;
		if (t >= carry)
			a[i + n] += t, carry = a[i + n] < t;
		t = (word)(prod >> B_PER_W);
		t += borrow;
		if (t >= borrow)
			borrow = a[i + 1] < t, a[i + 1] -= t;
	}
	// a <- a - borrow * B^{n + 1}
	carry -= zzSubW2(a + n + 1, n - 1, borrow);
	// a <- a / B^n
	wwCopy(a, a + n, n);
	a[n] = carry;
	// a >= mod?
	if (wwCmp2(a, n + 1, mod, n) >= 0)
		// a <- a - mod
		a[n] -= zzSub2(a, mod, n);
	// очистка
	prod = 0;
	carry = borrow = t = 0;
}

size_t zzRedCrandMont_deep(size_t n)
{
	return 0;
}

/*
*******************************************************************************
Возведение в степень
*******************************************************************************
*/

void zzPowerMod(word c[], const word a[], size_t n, const word b[], size_t m,
	const word mod[], void* stack)
{
	size_t no;
	// переменные в stack
	word* t;
	qr_o* r;
	// pre
	ASSERT(n > 0 && mod[n - 1] != 0);
	ASSERT(wwCmp(a, mod, n) < 0);
	// размерности
	no = wwOctetSize(mod, n);
	// раскладка stack
	t = (word*)stack;
	r = (qr_o*)(t + n);
	stack = (octet*)r + zmCreate_keep(no);
	// r <- Zm(mod)
	wwTo(t, no, mod);
	zmCreate(r, (octet*)t, no, stack);
	// t <- a
	wwTo(t, no, a);
	qrFrom(t, (octet*)t, r, stack);
	// t <- a^b
	qrPower(t, t, b, m, r, stack);
	// c <- t
	qrTo((octet*)t, t, r, stack);
	wwFrom(c, t, no);
}

size_t zzPowerMod_deep(size_t n, size_t m)
{
	const size_t no = O_OF_W(n);
	const size_t r_deep = zmCreate_deep(no);
	return no + 
		utilMax(2,
			r_deep,
			qrPower_deep(n, m, r_deep));
}

/*
*******************************************************************************
Возведение в степень по модулю машинного слова

Реализован метод скользящего окна. Длина окна w = 3.
*******************************************************************************
*/

word zzPowerModW(register word a, register word b, register word mod, 
	void* stack)
{
	register dword prod;
	register word slide;
	register size_t pos;
	register size_t slide_size;
	// переменные в stack
	word* powers;	/* [4]powers */
	// pre
	ASSERT(mod != 0);
	// b == 0?
	if (b == 0)
		return 1;
	// раскладка stack
	powers = (word*)stack;
	// powers <- малые нечетные степени a
	prod = a;
	prod *= a, prod %= mod, powers[0] = (word)prod;
	prod *= a, prod %= mod, powers[1] = (word)prod;
	prod *= powers[0], prod %= mod, powers[2] = (word)prod;
	prod *= powers[0], prod %= mod, powers[3] = (word)prod;
	powers[0] = a;
	// pos <- номер старшего единичного бита b
	pos = B_PER_W - 1 - wordCLZ(b);
	// slide <- старший слайд b
	slide_size = MIN2(pos + 1, 3);
	slide = b >> (pos + 1 - slide_size);
	slide &= WORD_BIT_POS(slide_size) - 1;
	for (; slide % 2 == 0; slide >>= 1, slide_size--);
	// a <- powers[slide / 2]
	a = powers[slide / 2];
	pos -= slide_size;
	// пробегаем биты b
	while (pos != SIZE_MAX)
	{
		prod = a;
		if ((b & WORD_BIT_POS(pos)) == 0)
		{
			// a <- a^2 \mod mod
			prod *= a, a = prod % mod;
			--pos;
		}
		else
		{
			// slide <- очередной слайд b
			slide_size = MIN2(pos + 1, 3);
			slide = b >> (pos + 1 - slide_size);
			slide &= WORD_BIT_POS(slide_size) - 1;
			for (; slide % 2 == 0; slide >>= 1, slide_size--);
			pos -= slide_size;
			// a <- a^2 \mod mod
			while (slide_size--)
				prod *= a, prod %= mod, a = (word)prod;
			// a <- a * powers[slide / 2] \mod mod
			prod *= powers[slide / 2];
			prod %= mod;
			a = (word)prod;
		}
	}
	// выход
	prod = 0, slide = b = mod = 0, pos = slide_size = 0;
	return a;
}

size_t zzPowerModW_deep()
{
	return O_OF_W(4);
}
