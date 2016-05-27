/*
*******************************************************************************
\file ww.c
\brief Arbitrary length words
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2012.04.18
\version 2016.05.27
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/mem.h"
#include "bee2/core/util.h"
#include "bee2/core/word.h"
#include "bee2/math/ww.h"

/*
*******************************************************************************
Копирование, логические операции
*******************************************************************************
*/

void wwCopy(word b[], const word a[], size_t n)
{
	ASSERT(wwIsSameOrDisjoint(a, b, n));
	while (n--)
		b[n] = a[n];
}

void wwSwap(word a[], word b[], size_t n)
{
	ASSERT(wwIsDisjoint(a, b, n));
	while (n--)
		SWAP(a[n], b[n]);
}

bool_t SAFE(wwEq)(const word a[], const word b[], size_t n)
{
	register word diff = 0;
	ASSERT(wwIsValid(a, n) && wwIsValid(b, n));
	while (n--)
		diff |= a[n] ^ b[n];
	return wordEq(diff, 0);
}

bool_t FAST(wwEq)(const word a[], const word b[], size_t n)
{
	ASSERT(wwIsValid(a, n) && wwIsValid(b, n));
	while (n--)
		if (a[n] != b[n])
			return FALSE;
	return TRUE;
}

int SAFE(wwCmp)(const word a[], const word b[], size_t n)
{
	register word less = 0;
	register word greater = 0;
	ASSERT(wwIsValid(a, n) && wwIsValid(b, n));
	while (n--)
	{
		less |= ~greater & wordLess01(a[n], b[n]);
		greater |= ~less & wordGreater01(a[n], b[n]);
	}
	return (wordEq(less, 0) - 1) | wordNeq(greater, 0);
}

int FAST(wwCmp)(const word a[], const word b[], size_t n)
{
	ASSERT(wwIsValid(a, n) && wwIsValid(b, n));
	while (n--)
		if (a[n] > b[n])
			return 1;
		else if (a[n] < b[n])
			return -1;
	return 0;
}

int SAFE(wwCmp2)(const word a[], size_t n, const word b[], size_t m)
{
	register int ret;
	ASSERT(wwIsValid(a, n) && wwIsValid(b, m));
	if (n > m)
	{
		register int z = wwIsZero(a + m, n - m);
		ret = wwCmp(a, b, m);
		ret = -z & ret | (z - 1) & 1;
		z = 0;
	}
	else if (n < m)
	{
		register int z = wwIsZero(b + n, m - n);
		ret = wwCmp(a, b, n);
		ret = -z & ret | (z - 1) & -1;
		z = 0;
	}
	else
		ret = wwCmp(a, b, n);
	return ret;
}

int FAST(wwCmp2)(const word a[], size_t n, const word b[], size_t m)
{
	ASSERT(wwIsValid(a, n) && wwIsValid(b, m));
	if (n > m)
		return FAST(wwIsZero)(a + m, n - m) ? FAST(wwCmp)(a, b, m) : 1;
	else if (n < m)
		return FAST(wwIsZero)(b + n, m - n) ? FAST(wwCmp)(a, b, n) : -1;
	return FAST(wwCmp)(a, b, m);
}

int SAFE(wwCmpW)(const word a[], size_t n, register word w)
{
	register int ret;
	ASSERT(wwIsValid(a, n));
	if (n == 0)
		ret = wordEq(w, 0) - 1;
	else
	{
		register int z = wwIsZero(a + 1, n - 1);
		ret = -wordLess(a[0], w) & -1 | -wordGreater(a[0], w) & 1;
		ret = -z & ret | (z - 1) & 1;
		z = 0;
	}
	w = 0;
	return ret;
}

int FAST(wwCmpW)(const word a[], size_t n, register word w)
{
	register int cmp;
	ASSERT(wwIsValid(a, n));
	if (n == 0)
		cmp = (w ? -1 : 0);
	else
	{
		cmp = 0;
		while (--n && cmp == 0)
			cmp = (a[n] == 0 ? 0 : 1);
		if (cmp == 0)
		{
			if (a[0] < w)
				cmp = -1;
			else if (a[0] > w)
				cmp = 1;
		}
	}
	w = 0;
	return cmp;
}

void wwXor(word c[], const word a[], const word b[], size_t n)
{
	ASSERT(wwIsSameOrDisjoint(a, c, n));
	ASSERT(wwIsSameOrDisjoint(b, c, n));
	while (n--)
		c[n] = a[n] ^ b[n];
}

void wwXor2(word b[], const word a[], size_t n)
{
	ASSERT(wwIsSameOrDisjoint(a, b, n));
	while (n--)
		b[n] ^= a[n];
}

void wwSetZero(word a[], size_t n)
{
	ASSERT(wwIsValid(a, n));
	while (n--)
		a[n] = 0;
}

void wwSetW(word a[], size_t n, register word w)
{
	ASSERT(wwIsValid(a, n));
	if (n)
		for (a[0] = w; --n; a[n] = 0);
	else
		ASSERT(w == 0);
	w = 0;
}

void wwRepW(word a[], size_t n, register word w)
{
	ASSERT(wwIsValid(a, n));
	if (n)
		for (; n--; a[n] = w);
	else
		ASSERT(w == 0);
	w = 0;
}

bool_t SAFE(wwIsZero)(const word a[], size_t n)
{
	register word diff = 0;
	ASSERT(wwIsValid(a, n));
	while (n--)
		diff |= a[n];
	return wordEq(diff, 0);
}

bool_t FAST(wwIsZero)(const word a[], size_t n)
{
	ASSERT(wwIsValid(a, n));
	while (n--)
		if (a[n])
			return FALSE;
	return TRUE;
}

bool_t SAFE(wwIsW)(const word a[], size_t n, register word w)
{
	register bool_t ret;
	ASSERT(wwIsValid(a, n));
	if (n == 0)
		ret = wordEq(w, 0);
	else
	{
		ret = wordEq(a[0], w);
		while (--n)
			ret &= wordEq(a[n], 0);
	}
	w = 0;
	return ret;
}

bool_t FAST(wwIsW)(const word a[], size_t n, register word w)
{
	register bool_t ret;
	ASSERT(wwIsValid(a, n));
	if (n == 0)
		ret = (w == 0);
	else
	{
		ret = (a[0] == w);
		while (ret && --n)
			ret = (a[n] == 0);
	}
	w = 0;
	return ret;
}

bool_t SAFE(wwIsRepW)(const word a[], size_t n, register word w)
{
	register bool_t ret;
	ASSERT(wwIsValid(a, n));
	if (n == 0)
		ret = wordEq(w, 0);
	else
	{
		ret = wordEq(a[0], w);
		while (--n)
			ret &= wordEq(a[n], w);
	}
	w = 0;
	return ret;
}

bool_t FAST(wwIsRepW)(const word a[], size_t n, register word w)
{
	register bool_t ret;
	ASSERT(wwIsValid(a, n));
	if (n == 0)
		ret = (w == 0);
	else
	{
		do
			ret = (a[--n] == w);
		while (ret && n);
	}
	w = 0;
	return ret;
}

size_t wwWordSize(const word a[], size_t n)
{
	ASSERT(wwIsValid(a, n));
	while (n-- && a[n] == 0);
	return n + 1;
}

size_t wwOctetSize(const word a[], size_t n)
{
	ASSERT(wwIsValid(a, n));
	while (n-- && a[n] == 0);
	if (n == SIZE_MAX)
		return 0;
	{
		size_t pos = O_PER_W - 1;
		word mask = (word)0xFF << 8 * pos;
		while ((a[n] & mask) == 0)
			--pos, mask >>= 8;
		return n * O_PER_W + pos + 1;
	}
}

/*
*******************************************************************************
Операции с отдельными битами, кодирование

\remark В wwSetBit() использован трюк из работы
	Andersen S.A. Bit Twidding Hacks. Avail. at:
	http://graphics.stanford.edu/~seander/bithacks.html, 1997-2005
[conditionally set or clear bits without branching].
*******************************************************************************
*/

bool_t wwTestBit(const word a[], size_t pos)
{
	ASSERT(wwIsValid(a, W_OF_B(pos + 1)));
	return (a[pos / B_PER_W] & WORD_BIT_POS(pos % B_PER_W)) != 0;
}

word wwGetBits(const word a[], size_t pos, size_t width)
{
	register word ret;
	size_t n = pos / B_PER_W;
	ASSERT(wwIsValid(a, W_OF_B(pos + width)));
	pos %= B_PER_W;
	// биты a[n]
	ret = a[n] >> pos;
	// биты a[n + 1]
	if (pos + width > B_PER_W)
		ret |= a[n + 1] << (B_PER_W - pos);
	// только width битов
	ASSERT(width <= B_PER_W);
	if (width < B_PER_W)
		ret &= WORD_BIT_POS(width) - 1;
	return ret;
}

void wwSetBit(word a[], size_t pos, register bool_t val)
{
	register word f;
	ASSERT(wwIsValid(a, W_OF_B(pos + 1)));
	ASSERT(val == TRUE || val == FALSE);
	f = WORD_0 - (word)val;
	a[pos / B_PER_W] ^= (f ^ a[pos / B_PER_W]) & WORD_BIT_POS(pos % B_PER_W);
	f = 0;
}

void wwSetBits(word a[], size_t pos, size_t width, register word val)
{
	word mask = WORD_MAX;
	size_t n = pos / B_PER_W;
	ASSERT(wwIsValid(a, W_OF_B(pos + width)));
	ASSERT(width <= B_PER_W);
	// маска
	if (width < B_PER_W)
	{
		mask <<= B_PER_W - width;
		mask >>= B_PER_W - width;
	}
	// биты a[n]
	pos %= B_PER_W;
	a[n] &= ~(mask << pos);
	a[n] ^= (val & mask) << pos;
	// биты a[n + 1]
	if (pos + width > B_PER_W)
	{
		a[n + 1] &= mask << pos;
		a[n + 1] ^= (val & mask) >> (B_PER_W - pos);
	}
}

void wwFlipBit(word a[], size_t pos)
{
	ASSERT(wwIsValid(a, W_OF_B(pos + 1)));
	a[pos / B_PER_W] ^= WORD_BIT_POS(pos % B_PER_W);
}

size_t wwLoZeroBits(const word a[], size_t n)
{
	register size_t i;
	ASSERT(wwIsValid(a, n));
	// поиск младшего ненулевого машинного слова
	for (i = 0; i < n && a[i] == 0; ++i);
	// нулевое слово?
	if (i == n)
		return n * B_PER_W;
	// ...ненулевое
	return i * B_PER_W + wordCTZ(a[i]);
}

size_t wwHiZeroBits(const word a[], size_t n)
{
	register size_t i = n;
	ASSERT(wwIsValid(a, n));
	// поиск старшего ненулевого машинного слова
	while (i-- && a[i] == 0);
	// нулевое слово?
	if (i == SIZE_MAX)
		return n * B_PER_W;
	// ... ненулевое
	return (n - i - 1) * B_PER_W + wordCLZ(a[i]);
}

size_t wwBitSize(const word a[], size_t n)
{
	ASSERT(wwIsValid(a, n));
	return n * B_PER_W - wwHiZeroBits(a, n);
}

size_t wwNAF(word naf[], const word a[], size_t n, size_t w)
{
	const word next_bit = WORD_BIT_POS(w);
	const word hi_bit = next_bit >> 1;
	const word mask = hi_bit - 1;
	register word window;
	register word digit;
	register size_t naf_len = 0;
	register size_t naf_size = 0;
	register size_t a_len = wwBitSize(a, n);
	size_t i;
	// pre
	ASSERT(wwIsDisjoint2(a, n, naf, 2 * n + 1));
	ASSERT(2 <= w && w < B_PER_W);
	// naf <- 0
	wwSetZero(naf, 2 * n + 1);
	// a == 0?
	if (wwIsZero(a, n))
		return 0;
	// window <- a mod 2^w
	window = wwGetBits(a, 0, w);
	// расчет NAF
	for (i = w; window || i < a_len; ++i)
	{
		// ненулевой символ?
		if (window & 1)
		{
			// кодирование отрицательного символа
			if (window & hi_bit)
			{
				// модифицировать отрицательный символ суффикса NAF...
				if (i >= a_len)
					// ...сделать его положительным
					digit = window & mask,
					// window <- window - digit
					window = hi_bit;
				else
					// digit <- |window|
					digit = (0 - window) & mask,
					// digit <- 1||digit
					digit ^= hi_bit,
					// window <- window - digit
					window = next_bit;
			}
			else
				// кодирование положительного символа
				digit = window,
				// window <- window - digit
				window = 0;
			// запись ненулевого символа
			wwShHi(naf, W_OF_B(naf_len + w), w);
			wwSetBits(naf, 0, w, digit);
			naf_len += w;
		}
		else
			// кодирование нулевого символа
			wwShHi(naf, W_OF_B(++naf_len), 1);
		// увеличить размер naf
		++naf_size;
		// сдвиг окна
		window >>= 1;
		if (i < a_len)
			window += hi_bit * wwTestBit(a, i);
	}
	digit = window = 0;
	naf_len = a_len = 0;
	return naf_size;
}

/*
*******************************************************************************
Сдвиги и очистка

\todo Функции wwShLoCarry(), wwShHiCarry() перегружены. Оценить их
востребованность. Для размышления. В архитектуре i386 при сдвиге регистра
более чем на 1 позицию флаг переноса формально не определен.

\todo Проверить wwTrimLo().
*******************************************************************************
*/

void wwShLo(word a[], size_t n, size_t shift)
{
	ASSERT(wwIsValid(a, n));
	if (shift < B_PER_W * n)
	{
		size_t wshift = shift / B_PER_W, pos;
		// величина сдвига не кратна длине слова?
		if (shift %= B_PER_W)
		{
			// сдвиг всех слов, кроме последнего
			for (pos = 0; pos + wshift + 1 < n; pos++)
				a[pos] = a[pos + wshift] >> shift |
					a[pos + wshift + 1] << (B_PER_W - shift);
			// последнее слово
			ASSERT(pos + wshift < n);
			a[pos] = a[pos + wshift] >> shift;
			++pos;
		}
		// величина сдвига кратна длине слова
		else for (pos = 0; pos + wshift < n; pos++)
			a[pos] = a[pos + wshift];
		// обнуление последних слов
		for (; pos < n; a[pos++] = 0);
	}
	else
		wwSetZero(a, n);
}

word wwShLoCarry(word a[], size_t n, size_t shift, word carry)
{
	register word ret = 0;
	ASSERT(wwIsValid(a, n));
	if (shift < B_PER_W * (n + 1))
	{
		size_t wshift = shift / B_PER_W, pos;
		shift %= B_PER_W;
		// сохраняем вытесняемые разряды
		if (wshift)
			ret = a[wshift - 1] >> shift;
		// величина сдвига не кратна длине слова?
		if (shift)
		{
			// дополнительные вытесняемые разряды
			if (wshift < n)
				ret |= a[wshift] << (B_PER_W - shift);
			else
				ret |= carry << (B_PER_W - shift);
			// сдвиг всех слов, кроме последнего
			for (pos = 0; pos + wshift + 1 < n; pos++)
				a[pos] = a[pos + wshift] >> shift |
					a[pos + wshift + 1] << (B_PER_W - shift);
			// предпоследнее слово
			if (pos + wshift < n)
			{
				a[pos] = a[pos + wshift] >> shift | carry << (B_PER_W - shift);
				++pos;
			}
		}
		// величина сдвига кратна длине слова
		else
		{
			for (pos = 0; pos + wshift < n; pos++)
				a[pos] = a[pos + wshift];
		}
		// последние слова
		if (pos < n)
			a[pos++] = carry >> shift;
		for (; pos < n; a[pos++] = 0);
	}
	else
	{
		wwSetZero(a, n);
		shift -= B_PER_W * (n + 1);
		if (shift < B_PER_W)
			ret = carry >> shift;
	}
	return ret;
}

void wwShHi(word a[], size_t n, size_t shift)
{
	ASSERT(wwIsValid(a, n));
	if (shift < B_PER_W * n)
	{
		size_t wshift = shift / B_PER_W, pos;
		// величина сдвига не кратна длине слова?
		if (shift %= B_PER_W)
		{
			// сдвиг всех слов, кроме первого
			for (pos = n - 1; pos > wshift; pos--)
				a[pos] = a[pos - wshift] << shift |
					a[pos - wshift - 1] >> (B_PER_W - shift);
			// первое слово
			a[pos] = a[pos - wshift] << shift;
			--pos;
		}
		// величина сдвига кратна длине слова
		else for (pos = n - 1; pos + 1 > wshift; pos--)
				a[pos] = a[pos - wshift];
		// обнуление первых слов
		for (; pos != SIZE_MAX; a[pos--] = 0);
	}
	else
		wwSetZero(a, n);
}

word wwShHiCarry(word a[], size_t n, size_t shift, word carry)
{
	register word ret = 0;
	ASSERT(wwIsValid(a, n));
	if (shift < B_PER_W * (n + 1))
	{
		size_t wshift = shift / B_PER_W;
		size_t pos;
		shift %= B_PER_W;
		// сохраняем вытесняемые разряды
		if (wshift)
			ret = a[n - wshift] << shift;
		// величина сдвига не кратна длине слова?
		if (shift)
		{
			// дополнительные вытесняемые разряды
			if (wshift < n)
				ret |= a[n - wshift - 1] >> (B_PER_W - shift);
			else
				ret |= carry >> (B_PER_W - shift);
			// сдвиг всех слов, кроме первого
			for (pos = n - 1; pos != SIZE_MAX && pos > wshift; pos--)
				a[pos] = a[pos - wshift] << shift | 
					a[pos - wshift - 1] >> (B_PER_W - shift);
			// второе слово
			if (pos != SIZE_MAX && pos + 1 > wshift)
			{
				a[pos] = a[pos - wshift] << shift | carry >> (B_PER_W - shift);
				--pos;
			}
		}
		// величина сдвига кратна длине слова
		else
		{
			for (pos = n - 1; pos != SIZE_MAX && pos + 1 > wshift; pos--)
				a[pos] = a[pos - wshift];
		}
		// первые слова
		if (pos != SIZE_MAX)
			a[pos--] = carry << shift;
		for (; pos != SIZE_MAX; a[pos--] = 0);
	}
	else
	{
		wwSetZero(a, n);
		shift -= B_PER_W * (n + 1);
		if (shift < B_PER_W)
			ret = carry << shift;

	}
	return ret;
}

void wwTrimLo(word a[], size_t n, size_t pos)
{
	size_t i = pos / B_PER_W;
	ASSERT(wwIsValid(a, n));
	if (i < n)
	{
		// очистить биты слова a[i]
		if (pos %= B_PER_W)
			a[i] >>= pos, a[i] <<= pos;
	}
	else if (i > n)
		i = n;
	// очистить остальные слова
	while (i)
		a[--i] = 0;
}

void wwTrimHi(word a[], size_t n, size_t pos)
{
	size_t i = pos / B_PER_W;
	ASSERT(wwIsValid(a, n));
	if (i < n)
	{
		pos = B_PER_W - pos % B_PER_W;
		// очистить биты слова a[i]
		if (pos == B_PER_W)
			a[i] = 0;
		else
			a[i] <<= pos, a[i] >>= pos;
		// очистить остальные слова
		while (++i < n)
			a[i] = 0;
	}
}
