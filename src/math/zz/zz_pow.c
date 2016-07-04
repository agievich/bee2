/*
*******************************************************************************
\file zz_pow.c
\brief Multiple-precision unsigned integers: modular exponentiation
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2012.04.22
\version 2016.07.01
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
