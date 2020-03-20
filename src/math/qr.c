/*
*******************************************************************************
\file qr.с
\brief Quotient rings
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2013.09.14
\version 2014.04.17
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/mem.h"
#include "bee2/core/util.h"
#include "bee2/math/qr.h"
#include "bee2/math/ww.h"

/*
*******************************************************************************
Усложнить интерфейс?

\todo Предусмотреть функцию сравнения (для избыточных представлений).
*******************************************************************************
*/

/*
*******************************************************************************
Управление кольцом
*******************************************************************************
*/

bool_t qrIsOperable(const qr_o* r)
{
	return objIsOperable(r) &&
		objKeep(r) >= sizeof(qr_o) &&
		objPCount(r) == 3 &&
		objOCount(r) == 0 &&
		r->n > 0 && r->no > 0 &&
		wwIsValid(r->unity, r->n) &&
		r->from != 0 &&	
		r->to != 0 &&	
		r->add != 0 &&	
		r->sub != 0 &&	
		r->neg != 0 &&	
		r->mul != 0 &&	
		r->sqr != 0 &&	
		r->inv != 0 &&	
		r->div != 0;
}

/*
*******************************************************************************
Возведение в степень

В функции qrPower() реализован скользящий оконный метод возведения 
в степень (c = a^b). Предварительно рассчитываются малые степени
	a^1, a^3,..., a^{2^w} - 1,
где w --- величина окна. Затем в b выделяются серии из нулей и слайды.
Слайд -- это битовый фрагмент, окаймленный единицами, длина которого не
превосходит w. Слайд интерпретируется как число (нечетное).

Обработка нуля серии состоит в возведении с в квадрат.
Обработка слайда длины slide_size состоит в slide_size возведениях c
в квадрат и последующем умножении c на малую степень a.

В начале вычислений выполняется присвоение c <- a^{старший_слайд_b}.

Скользящий оконный метод основан на представлении
	b = \sum {i=0}^{l - 1} b_i 2^i,	b_i \in {0, 1, 3,..., 2^w - 1}
Известно [Moller B. Improved Techniques for Fast Exponentiation,
ICISC 2002], что l = wwBitSize(b) и доля ненулевых b_i для случайного
показателя b равняется 1 / (w + 1).

Для расчета малых степеней a требуется 2^{w - 1} - 1 умножения.
Для расчета c в среднем требуется еще около (l - w) / (w + 1) умножений
(ср. [OpenSSL::crypto::bn::bn_lcl.h]). Число возведений в квадрат
зависит от l и не зависит от w.

В функции qrCalcSlideWidth() определяется w, которое доставляет
минимум целевой функции 2^{w - 1} + (l - w) / (w + 1).
*******************************************************************************
*/

static size_t qrCalcSlideWidth(size_t m)
{
	m = B_OF_W(m);
	if (m <= 79)
		return 3;
	if (m <= 239)
		return 4;
	if (m <= 671)
		return 5;
	if (m <= 1791)
		return 6;
	return 7;
}

void qrPower(word c[], const word a[], const word b[], size_t m, 
	const qr_o* r, void* stack)
{
	const size_t w = qrCalcSlideWidth(m);
	const size_t powers_count = SIZE_1 << (w - 1);
	register word slide;
	register size_t slide_size;
	size_t pos;
	// переменные в stack
	word* power;
	word* powers;
	// pre
	ASSERT(qrIsOperable(r));
	ASSERT(wwIsValid(a, r->n));
	ASSERT(wwIsValid(b, m));
	ASSERT(wwIsValid(c, r->n));
	// раскладка stack
	power = (word*)stack;
	powers = power + r->n;
	stack = powers + r->n * powers_count;
	// b == 0? => с <- unity
	if (wwIsZero(b, m))
	{
		wwCopy(c, r->unity, r->n);
		return;
	}
	// расчет малых степеней a
	ASSERT(w > 0);
	if (w == 1)
		wwCopy(powers, a, r->n);
	else
	{
		size_t i;
		// powers[0] <- a^2
		qrSqr(powers, a, r, stack);
		// powers[1] <- a^3
		qrMul(powers + r->n, a, powers, r, stack);
		// powers[i] <- a^{2i + 1} = powers[i - 1] * powers[0]
		for (i = 2; i < powers_count; ++i)
			qrMul(powers + r->n * i, powers + r->n * i - r->n, powers, r, 
				stack);
		// powers[0] <- a
		wwCopy(powers, a, r->n);
	}
	// pos <- l - 1
	pos = wwBitSize(b, m) - 1;
	ASSERT(pos != SIZE_MAX);
	// slide <- старший слайд b
	slide_size = MIN2(pos + 1, w);
	slide = wwGetBits(b, pos - slide_size + 1, slide_size);
	while (slide % 2 == 0)
		slide >>= 1, slide_size--;
	// power <- powers[slide / 2]
	wwCopy(power, powers + r->n * (slide / 2), r->n);
	pos -= slide_size;
	// пробегаем биты b
	while (pos != SIZE_MAX)
		if (!wwTestBit(b, pos))
		{
			// power <- power^2
			qrSqr(power, power, r, stack);
			--pos;
		}
		else
		{
			// slide <- очередной слайд b
			slide_size = MIN2(pos + 1, w);
			slide = wwGetBits(b, pos - slide_size + 1, slide_size);
			while (slide % 2 == 0)
				slide >>= 1, slide_size--;
			pos -= slide_size;
			// power <- power^2
			while (slide_size--)
				qrSqr(power, power, r, stack);
			// power <- power * powers[slide / 2]
			qrMul(power, power, powers + r->n * (slide / 2), r, stack);
		}
	// очистка и возврат
	slide_size = 0, slide = 0;
	wwCopy(c, power, r->n);
}

size_t qrPower_deep(size_t n, size_t m, size_t r_deep)
{
	const size_t powers_count = SIZE_1 << (qrCalcSlideWidth(m) - 1);
	return O_OF_W(n + n * powers_count) + r_deep;
}
