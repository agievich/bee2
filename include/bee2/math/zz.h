/*
*******************************************************************************
\file zz.h
\brief Multiple-precision unsigned integers
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2012.04.22
\version 2016.05.23
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

/*!
*******************************************************************************
\file zz.h
\brief Большие неотрицательные целые числа
*******************************************************************************
*/

#ifndef __ZZ_H
#define __ZZ_H

#include "bee2/defs.h"
#include "bee2/core/safe.h"

#ifdef __cplusplus
extern "C" {
#endif

/*!
*******************************************************************************
\file zz.h	

\section zz-common Общие положения

Реализованы операции с большими неотрицательными целыми числами.

Число задается массивом машинных слов: word w[n]. Машинное слово w[0] --
младшее, машинное слово w[n - 1] -- старшее.

Пустое число (n = 0) считается нулевым.

В описаниях функций B = 2^{B_PER_W} --- основание системы счисления.

Функция zzDoubleMod() совместно с функциями zzAddMod() и zzSubMod()
позволяет организовать быстрое модулярное умножение числа на малую
константу. Например, вычисление b <- 7 a \mod mod может быть организовано
следующим образом:
\code
	zzDoubleMod(b, a, mod, n);
	zzDoubleMod(b, b, mod, n);
	zzDoubleMod(b, b, mod, n);
	zzSubMod(b, a, mod, n);
\endcode
Аналогично, функция zzHalfMod() позволяет организовать быстрое модулярное
деление на определенные константы.

\pre Все входные указатели действительны.

\pre В функциях работы с числами по адресам памяти для чисел
зарезервировано ясное из конекста либо уточняемое в описаниях функций
число машинных слов.

\pre Вспомогательный буфер stack не пересекается с другими буферами.
*******************************************************************************
*/

/*
*******************************************************************************
Свойства
*******************************************************************************
*/

/*!	\brief Четное число?

	Проверяется, что число [n]a является четным.
	\return Признак четности.
*/
bool_t zzIsEven(
	const word a[],		/*!< [in] число */
	size_t n			/*!< [in] длина a в машинных словах */
);

/*!	\brief Нечетное число?

	Проверяется, что число [n]a является нечетным.
	\return Признак нечетности.
*/
bool_t zzIsOdd(
	const word a[],		/*!< [in] число */
	size_t n			/*!< [in] длина a в машинных словах */
);

/*
*******************************************************************************
Аддитивные операции
*******************************************************************************
*/

/*!	\brief Сложение чисел

	Определяется сумма [n]с чисел [n]a и [n]b:
	\code
		c <- (a + b) \mod B^n, carry <- (a + b) \div B^n,
		c + B^n * carry == a + b.
	\endcode
	\pre Буфер c либо не пересекается, либо совпадает с каждым из буферов a, b.
	\return Слово переноса carry.
*/
word zzAdd(
	word c[],			/*!< [out] сумма */
	const word a[],		/*!< [in] первое слагаемое */
	const word b[],		/*!< [in] второе слагаемое */
	size_t n			/*!< [in] длина a, b в машинных словах */
);

/*!	\brief Добавление числа

	К числу [n]b добавляется число [n]a:
	\code
		b <- (a + b) \mod B^n, carry <- (a + b) \div B^n.
	\endcode
	\pre Буфер b либо не пересекается, либо совпадает с буфером a.
	\return Слово переноса carry.
*/
word zzAdd2(
	word b[],			/*!< [in/out] первое слагаемое / сумма */
	const word a[],		/*!< [in] второе слагаемое */
	size_t n			/*!< [in] длина a, b в машинных словах */
);

/*!	\brief Сложение чисел проивольной длины

	Определяется сумма [max(n, m)]с чисел [n]a и [m]b:
	\code
		c <- (a + b) \mod B^{max(n,m)}, carry <- (a + b) \div B^{max(n,m)}.
	\endcode
	\pre Буфер c либо не пересекается, либо совпадает с каждым из буферов a, b.
	\return Слово переноса carry.
*/
word zzAdd3(
	word c[],			/*!< [out] сумма */
	const word a[],		/*!< [in] первое слагаемое */
	size_t n,			/*!< [in] длина a в машинных словах */
	const word b[],		/*!< [in] второе слагаемое */
	size_t m			/*!< [in] длина b в машинных словах */
);

/*!	\brief Сложение числа со словом

	Определяется сумма [n]b числа [n]a и слова w:
	\code
		b <- (a + w) \mod B^n, carry <- (a + w) \div B^n.
	\endcode
	\pre Буфер b либо не пересекается, либо совпадает с буфером a.
	\return Слово переноса carry.
*/
word zzAddW(
	word b[],			/*!< [out] сумма */
	const word a[],		/*!< [in] первое слагаемое */
	size_t n,			/*!< [in] длина a в машинных словах */
	register word w		/*!< [in] второе слагаемое */
);

/*!	\brief Добавление слова

	К числу [n]a добавляется слово w:
	\code
		a <- (a + w) \mod B^n, carry <- (a + w) \div B^n.
	\endcode
	\return Слово переноса carry.
*/
word zzAddW2(
	word a[],			/*!< [in/out] слагаемое / сумма */
	size_t n,			/*!< [in] длина a в машинных словах */
	register word w		/*!< [in] второе слагаемое */
);

/*!	\brief Сумма чисел равняется числу?

	Проверяется, что сумма чисел [n]a и [n]b равняется числу [n]c:
	\code
		a + b == c?
	\endcode
	\remark Переставляя операнды, можно проверять не только суммы,
	но и разности.
	\return Признак равенства.
	\safe Имеется ускоренная нерегулярная редакция.
*/
bool_t zzIsSumEq(
	const word c[],		/*!< [in] сумма */
	const word a[],		/*!< [in] первое слагаемое */
	const word b[],		/*!< [in] второе слагаемое */
	size_t n			/*!< [in] длина a, b, c в машинных словах */
);

bool_t FAST(zzIsSumEq)(const word c[], const word a[], const word b[], 
	size_t n);

/*!	\brief Сумма числа и слова равняется числу?

	Проверяется, что сумма числа [n]a и слова w равняется числу [n]b:
	\code
		a + w == b?
	\endcode
	\return Признак равенства.
	\safe Имеется ускоренная нерегулярная редакция.
*/
bool_t zzIsSumWEq(
	const word b[],		/*!< [in] сумма */
	const word a[],		/*!< [in] первое слагаемое */
	size_t n,			/*!< [in] длина a, b в машинных словах */
	register word w		/*!< [in] второе слагаемое */
);

bool_t FAST(zzIsSumWEq)(const word b[], const word a[], size_t n, 
	register word w);

/*!	\brief Вычитание чисел

	Определяется разность [n]c чисел [n]a и [n]b:
	\code
		c <- (a - b) \mod B^n, borrow <- (a < b),
		c - B^n * borrow == a - b.
	\endcode
	\pre Буфер c либо не пересекается, либо совпадает с каждым из буферов a, b.
	\return Слово заема borrow.
*/
word zzSub(
	word c[],			/*!< [out] разность */
	const word a[],		/*!< [in] уменьшаемое */
	const word b[],		/*!< [in] вычитаемое */
	size_t n			/*!< [in] длина a, b в машинных словах */
);

/*!	\brief Уменьшение числа

	Число [n]b уменьшается на число [n]a:
	\code
		b <- (b - a) \mod B^n, borrow <- (b < a).
	\endcode
	\pre Буфер c либо не пересекается, либо совпадает с каждым из буферов a, b.
	\return Слово заема borrow.
*/
word zzSub2(
	word b[],			/*!< [in/out] уменьшаемое / разность */
	const word a[],		/*!< [in] вычитаемое */
	size_t n			/*!< [in] длина a, b в машинных словах */
);

/*!	\brief Вычитание из числа слова

	Определяется разность [n]b числа [n]a и слова w:
	\code
		b <- (a - w) \mod B^n, borrow <- (a < w).
	\endcode
	\pre Буфер b либо не пересекается, либо совпадает с буфером a.
	\return Слово заема borrow.
*/
word zzSubW(
	word b[],			/*!< [out] разность */
	const word a[],		/*!< [in] уменьшаемое */
	size_t n,			/*!< [in] длина a в машинных словах */
	register word w		/*!< [in] вычитаемое */
);

/*!	\brief Уменьшение числа на слова

	Число [n]a уменьшается на слово w:
	\code
		a <- (a - w) \mod B^n, borrow <- (a < w).
	\endcode
	\return Слово заема borrow.
*/
word zzSubW2(
	word a[],			/*!< [in/out] уменьшаемое / разность */
	size_t n,			/*!< [in] длина a в машинных словах */
	register word w		/*!< [in] вычитаемое */
);

/*!	\brief Минус

	Определяется число [n]b, отрицательное к [n]a по модулю B^n:
	\code
		b <- B^n - a.
	\endcode
	\pre Буфер b либо не пересекается, либо совпадает с буфером a.
*/
void zzNeg(
	word b[],			/*!< [out] отрицательное число */
	const word a[],		/*!< [in] число */
	size_t n			/*!< [in] длина a в машинных словах */
);

/*
*******************************************************************************
Мультипликативные операции
*******************************************************************************
*/

/*!	\brief Умножение числа на слово

	Определяется произведение [n]b числа [n]a на слово w:
	\code
		b <- (a * w) \mod B^n, carry <- (a * w) \div B^n.
	\endcode
	\pre Буфер b либо не пересекается, либо совпадает с буфером a.
	\return Слово переноса carry.
*/
word zzMulW(
	word b[],			/*!< [out] произведение */
	const word a[],		/*!< [in] первый множитель */
	size_t n,			/*!< [in] длина a, b в машинных словах */
	register word w		/*!< [in] второй множитель */
);

/*!	\brief Сложение с произведением числа на слово

	К числу [n]b добавляется произведение числа [n]a на машинное слово w:
	\code
		b <- (b + a * w) \mod B^n, carry <- (b + a * w) \div B^n.
	\endcode
	\pre Буфер b либо не пересекается, либо совпадает с буфером a.
	\return Слово переноса carry.
*/
word zzAddMulW(
	word b[],			/*!< [in/out] слагаемое / сумма */
	const word a[],		/*!< [in] первый множитель */
	size_t n,			/*!< [in] длина a, b в машинных словах */
	register word w		/*!< [in] второй множитель */
);

/*!	\brief Вычитание произведения числа на слово

	Из числа [n]b вычитается произведение числа [n]a на машинное слово w:
	\code
		b <- (b - a * w) \mod B^n, carry <- (b < a * w).
	\endcode
	\pre Буфер b либо не пересекается, либо совпадает с буфером a.
	\return Слово заема borrow.
*/
word zzSubMulW(
	word b[],			/*!< [in/out] вычитаемое / разность */
	const word a[],		/*!< [in] первый множитель */
	size_t n,			/*!< [in] длина a, b в машинных словах */
	register word w		/*!< [in] второй множитель */
);

/*!	\brief Умножение чисел

	Определяется произведение [n + m]c чисел [n]a на [m]b:
	\code
		c <- a * b.
	\endcode
	\pre Буфер c не пересекается с буферами a и b.
	\deep{stack} zzMul_deep(n, m).
*/
void zzMul(
	word c[],			/*!< [out] произведение */
	const word a[],		/*!< [in] первый множитель */
	size_t n,			/*!< [in] длина a в машинных словах */
	const word b[],		/*!< [in] второй множитель */
	size_t m,			/*!< [in] длина b в машинных словах */
	void* stack			/*!< [in] вспомогательная память */
);

size_t zzMul_deep(size_t n, size_t m);

/*!	\brief Возведение числа в квадрат

	Определяется квадрат [2n]b числа [n]a:
	\code
		b <- a * a.
	\endcode
	\pre Буфер b не пересекается с буфером a.
	\deep{stack} zzSqr_deep(n).
*/
void zzSqr(
	word b[],			/*!< [out] квадрат */
	const word a[],		/*!< [in] множитель */
	size_t n,			/*!< [in] длина a в машинных словах */
	void* stack			/*!< [in] вспомогательная память */
);

size_t zzSqr_deep(size_t n);

/*!	\brief Извлечение квадратного корня

	Определяется максимальное целое [(n + 1) / 2]b, квадрат которого 
	не превосходит [n]a:
	\code
		b <- \floor(\sqrt(a)).
	\endcode
	\return Признак того, что a является полным квадратом (a == b * b).
	\pre Буфер b не пересекается с буфером a.
	\deep{stack} zzSqrt_deep(n).
	\safe Функция нерегулярна: условные переходы, нерегулярные блоки.
*/
bool_t zzSqrt(
	word b[],			/*!< [out] квадратный корень */
	const word a[],		/*!< [in] число */
	size_t n,			/*!< [in] длина a в машинных словах */
	void* stack			/*!< [in] вспомогательная память */
);

size_t zzSqrt_deep(size_t n);

/*!	\brief Деление числа на машинное слово

	Определяется частное [n]q от деления числа [n]a на машинное слово w:
	\code
		q <- a \div w.
	\endcode
	\pre w != 0.
	\pre Буфер q либо не пересекается, либо совпадает с буфером a.
	\return Остаток от деления.
*/
word zzDivW(
	word q[],			/*!< [out] частное */
	const word a[],		/*!< [in] делимое */
	size_t n,			/*!< [in] длина a в машинных словах */
	register word w		/*!< [in] делитель */
);

/*!	\brief Остаток от деления числа на машинное слово

	Определяется остаток от деления числа [n]a на машинное слово w:
	\code
		r <- a \mod w.
	\endcode
	\pre w != 0.
	\return Остаток от деления r.
*/
word zzModW(
	const word a[],		/*!< [in] делимое */
	size_t n,			/*!< [in] длина a в машинных словах */
	register word w		/*!< [in] делитель */
);

/*!	\brief Остаток от деления числа на малое машинное слово

	Определяется остаток от деления числа [n]a на малое машинное слово w:
	\code
		r <- a \mod w.
	\endcode
	\pre w != 0 && w^2 <= B.
	\return Остаток от деления r.
	\remark Функция zzModW2() работает быстрее zzModW() на тех платформах,
	где деление не менее чем в 2 раза медленнее умножения.
	\safe todo
*/
word zzModW2(
	const word a[],		/*!< [in] делимое */
	size_t n,			/*!< [in] длина a в машинных словах */
	register word w		/*!< [in] делитель */
);

/*!	\brief Деление чисел

	Определяются частное [n - m + 1]q и остаток [m]r от деления числа [n]a
	на число [m]b:
	\code
		q <- a \div b, r <- r \mod b,
		a == q * b + r, r < b.
	\endcode
	\pre n >= m.
	\pre m > 0 && b[m - 1] != 0.
	\pre Буферы q и r не пересекаются.
	\pre Буфер r либо не пересекается с буфером a, либо r == a.
	\deep{stack} zzDiv_deep(n, m).
	\safe todo
*/
void zzDiv(
	word q[],			/*!< [out] частное */
	word r[],			/*!< [out] остаток */
	const word a[],		/*!< [in] делимое */
	size_t n,			/*!< [in] длина a в машинных словах */
	const word b[],		/*!< [in] делитель */
	size_t m,			/*!< [in] длина b в машинных словах */
	void* stack			/*!< [in] вспомогательная память */
);

size_t zzDiv_deep(size_t n, size_t m);

/*!	\brief Остаток от деления чисел

	Определяется остаток [m]r от деления числа [n]a на число [m]b:
	\code
		a <- a \mod b.
	\endcode
	\pre m > 0 && b[m - 1] != 0.
	\pre Буфер r либо не пересекается с буфером a, либо r == a.
	\deep{stack} zzMod_deep(n, m).
	\safe todo
*/
void zzMod(
	word r[],			/*!< [out] остаток */
	const word a[],		/*!< [in] делимое */
	size_t n,			/*!< [in] длина a в машинных словах */
	const word b[],		/*!< [in] делитель */
	size_t m,			/*!< [in] длина b в машинных словах */
	void* stack			/*!< [in] вспомогательная память */
);

size_t zzMod_deep(size_t n, size_t m);

/*
*******************************************************************************
Алгоритм Евклида
*******************************************************************************
*/

/*!	\brief Наибольший общий делитель

	Определяется наибольший общий делитель [min(n, m)]d чисел [n]a и [m]b:
	\code
		d <- \gcd(a, b).
	\endcode
	\pre a != 0 && b != 0.
	\pre Буфер d не пересекается с буферами a и b.
	\remark Использование нулевых a и b запрещается для того, чтобы
	наибольший общий делитель d укладывался в [min(n, m)] слов.
	\remark Считается, что \gcd(0, b) = b, в частности, \gcd(0, 0) = 0.
	\deep{stack} zzGCD_deep(n, m).
	\safe Функция нерегулярна.
*/
void zzGCD(
	word d[],			/*!< [out] н.о.д. */
	const word a[],		/*!< [in] первое число */
	size_t n,			/*!< [in] длина a в машинных словах */
	const word b[],		/*!< [in] второе число */
	size_t m,			/*!< [in] длина b в машинных словах */
	void* stack			/*!< [in] вспомогательная память */
);

size_t zzGCD_deep(size_t n, size_t m);

/*!	\brief Взаимная простота

	Проверяется, что числа [n]a и [m]b взаимно просты:
	\code
		\gcd(a, b) == 1?
	\endcode
	\return Признак взаимной простоты a и b.
	\deep{stack} zzIsCoprime_deep(n, m).
	\safe Функция нерегулярна.
*/
bool_t zzIsCoprime(
	const word a[],		/*!< [in] первое число */
	size_t n,			/*!< [in] длина a в машинных словах */
	const word b[],		/*!< [in] второе число */
	size_t m,			/*!< [in] длина b в машинных словах */
	void* stack			/*!< [in] вспомогательная память */
);

size_t zzIsCoprime_deep(size_t n, size_t m);

/*!	\brief Наименьшее общее кратное

	Определяется наименьшее общее кратное [max(n, m)]d чисел [n]a и [m]b:
	\code
		d <- \lcm[a, b].
	\endcode
	\pre a != 0 && b != 0.
	\pre Буфер d не пересекается с буферами a и b.
	\remark Использование нулевых a и b запрещается для согласованости с
	zzGCD() и избежания разбора редких, неиспользуемых на практике случаев.
	\deep{stack} zzLCM_deep(n, m).
	\safe Функция нерегулярна.
*/
void zzLCM(
	word d[],			/*!< [out] н.о.к. */
	const word a[],		/*!< [in] первое число */
	size_t n,			/*!< [in] длина a в машинных словах */
	const word b[],		/*!< [in] второе число */
	size_t m,			/*!< [in] длина b в машинных словах */
	void* stack			/*!< [in] вспомогательная память */
);

size_t zzLCM_deep(size_t n, size_t m);

/*!	\brief Расширенный алгоритм Евклида

	Определяется наибольший общий делитель [min(n, m)]d чисел [n]a и [m]b:
	\code
		d <- \gcd(a, b),
	\endcode
	а также sign \in {0, 1} и положительные числа [m]da и [n]db такие, что
	\code
		a * da - b * db == (-1)^sign d
	\endcode
	(коэффициенты Безу).
	\pre a != 0 && b != 0.
	\pre Буферы d, da, db не пересекаются между собой и с буферами a, b.
	\return sign (0, если a * da - b * db = d, и 1, если b * db - a * da = d).
	\deep{stack} zzExGCD_deep(n, m).
	\safe Функция нерегулярна.
*/
int zzExGCD(
	word d[],			/*!< [out] н.о.д. */
	word da[],			/*!< [out] первый коэффициент Безу */
	word db[],			/*!< [out] второй коэффициент Безу */
	const word a[],		/*!< [in] первое число */
	size_t n,			/*!< [in] длина a в машинных словах */
	const word b[],		/*!< [in] второе число */
	size_t m,			/*!< [in] длина b в машинных словах */
	void* stack			/*!< [in] вспомогательная память */
);

size_t zzExGCD_deep(size_t n, size_t m);

/*
*******************************************************************************
Квадратичные вычеты
*******************************************************************************
*/

/*!	\brief Символ Якоби

	Определяется символ Якоби (a / b) чисел [n]a и [m]b.
	\pre b -- нечетное.
	\remark Если b является произведением простых p_1, p_2,.., p_k, то
	(a / b) = (a / p_1) * (a / p_2) *... * (a / p_k).
	Здесь (a / p_i) --- символ Лежандра: (a / p) равняется 0,
	если a делится на p, равняется 1, если a -- квадратичный вычет \mod p,
	и равняется -1 в остальных случаях.
	\return Символ Якоби (a / b): 0, 1 или -1.
	\deep{stack} zzJacobi_deep(n, m).
	\safe Функция нерегулярна.
*/
int zzJacobi(
	const word a[],		/*!< [in] первое число */
	size_t n,			/*!< [in] длина a в машинных словах */
	const word b[],		/*!< [in] второе число */
	size_t m,			/*!< [in] длина b в машинных словах */
	void* stack			/*!< [in] вспомогательная память */
);

size_t zzJacobi_deep(size_t n, size_t m);

/*
*******************************************************************************
Модулярная арифметика
*******************************************************************************
*/

/*!	\brief Сложение чисел по модулю

	Определяется сумма [n]c чисел [n]a и [n]b по модулю [n]mod:
	\code
		с <- (b + a) \mod mod.
	\endcode
	\pre a < mod && b < mod.
	\pre Буфер c либо не пересекается, либо совпадает с каждым из буферов a, b.
	\pre Буфер с не пересекается с буфером mod.
	\safe Имеется ускоренная нерегулярная редакция.
*/
void zzAddMod(
	word c[],			/*!< [out] сумма */
	const word a[],		/*!< [in] первое слагаемое */
	const word b[],		/*!< [in] второе слагаемое */
	const word mod[],	/*!< [in] модуль */
	size_t n			/*!< [in] длина чисел в машинных словах */
);

void FAST(zzAddMod)(word c[], const word a[], const word b[], const word mod[], 
	size_t n);

/*!	\brief Сложение числа со словом по модулю

	Определяется сумма [n]b числа [n]a и слова w по модулю [n]mod:
	\code
		b <- (a + w) \mod mod.
	\endcode
	\pre a < mod && w < mod.
	\pre Буфер b либо не пересекается, либо совпадает с буфером a.
	\pre Буфер b не пересекается с буфером mod.
	\safe todo
*/
void zzAddWMod(
	word b[],			/*!< [out] сумма */
	const word a[],		/*!< [in] первое слагаемое */
	register word w,	/*!< [in] второе слагаемое */
	const word mod[],	/*!< [in] модуль */
	size_t n			/*!< [in] длина чисел в машинных словах */
);

/*!	\brief Вычитание чисел по модулю

	Определяется разность [n]с чисел [n]a и [n]b по модулю [n]mod:
	\code
		c <- (a - b) \mod mod.
	\endcode
	\pre n > 0 && mod[n - 1] != 0.
	\pre a < mod && b < mod.
	\pre Буфер c либо не пересекается, либо совпадает с каждым из буферов a, b.
	\pre Буфер с не пересекается с буфером mod.
	\safe todo
*/
void zzSubMod(
	word c[],			/*!< [out] разность */
	const word a[],		/*!< [in] уменьшаемое */
	const word b[],		/*!< [in] вычитаемое */
	const word mod[],	/*!< [in] модуль */
	size_t n			/*!< [in] длина чисел в машинных словах */
);

/*!	\brief Вычитание из числа слова по модулю

	Определяется разность [n]b числа [n]a и слова w по модулю [n]mod:
	\code
		b <- (a - w) \mod mod.
	\endcode
	\pre a < mod && w < mod.
	\pre Буфер b либо не пересекается, либо совпадает с буфером a.
	\pre Буфер b не пересекается с буфером mod.
	\safe todo
*/
void zzSubWMod(
	word b[],			/*!< [out] разность */
	const word a[],		/*!< [in] уменьшаемое */
	register word w,	/*!< [in] вычитаемое */
	const word mod[],	/*!< [in] модуль */
	size_t n			/*!< [in] длина чисел в машинных словах */
);

/*!	\brief Аддитивное обращение чисел по модулю

	Определяется число [n]b, аддитивно обратное к [n]a по модулю [n]mod:
	\code
		b <- -a \mod mod.
	\endcode
	\pre n > 0 && mod[n - 1] != 0.
	\pre a < mod.
	\pre Буфер b либо не пересекается, либо совпадает с буфером a.
	\pre Буфер b не пересекается с буфером mod.
	\safe todo
*/
void zzNegMod(
	word b[],			/*!< [in/out] обратное число */
	const word a[],		/*!< [in] число */
	const word mod[],	/*!< [in] модуль */
	size_t n			/*!< [in] длина чисел в машинных словах */
);

/*!	\brief Умножение чисел по модулю

	Определяется произведение [n]c чисел [n]a и [n]b по модулю [n]mod:
	\code
		c <- a * b \mod mod.
	\endcode
	\pre n > 0 && mod[n - 1] != 0.
	\pre a < mod && b < mod.
	\deep{stack} zzMulMod_deep(n).
*/
void zzMulMod(
	word c[],			/*!< [out] произведение */
	const word a[],		/*!< [in] первый множитель */
	const word b[],		/*!< [in] второй множитель */
	const word mod[],	/*!< [in] модуль */
	size_t n,			/*!< [in] длина чисел в машинных словах */
	void* stack			/*!< [in] вспомогательная память */
);

size_t zzMulMod_deep(size_t n);

/*!	\brief Возведение чисел в квадрат по модулю

	Определяется квадрат [n]b числа [n]a по модулю [n]mod:
	\code
		b <- a * a \mod mod.
	\endcode
	\pre n > 0 && mod[n - 1] != 0.
	\pre a < mod.
	\deep{stack} zzSqrMod_deep(n).
*/
void zzSqrMod(
	word b[],			/*!< [out] квадрат */
	const word a[],		/*!< [in] множитель */
	const word mod[],	/*!< [in] модуль */
	size_t n,			/*!< [in] длина чисел в машинных словах */
	void* stack			/*!< [in] вспомогательная память */
);

size_t zzSqrMod_deep(size_t n);

/*!	\brief Обращение по модулю

	Определяется число [n]b, мультипликативно обратное к [n]a по модулю [n]mod:
	\code
		b <- a^{-1} \mod mod.
	\endcode
	\pre mod -- нечетное && mod[n - 1] != 0.
	\pre a < mod.
	\pre Буфер b не пересекается с буфером mod.
	\expect \gcd(a, mod) == 1.
	\remark Если \gcd(a, mod) != 1, то b <- 0.
	\deep{stack} zzInvMod_deep(n).
	\safe Функция нерегулярна.
*/
void zzInvMod(
	word b[],			/*!< [out] обратное число */
	const word a[],		/*!< [in] обращаемое число */
	const word mod[],	/*!< [in] модуль */
	size_t n,			/*!< [in] длина чисел в машинных словах */
	void* stack			/*!< [in] вспомогательная память */
);

size_t zzInvMod_deep(size_t n);

/*!	\brief Деление по модулю

	Определяется частное [n]b от деления числа [n]divident на число [n]a по
	модулю [n]mod:
	\code
		b <- divident * a^{-1} \mod mod.
	\endcode
	\pre mod -- нечетное && mod[n - 1] != 0.
	\pre a, divident < mod.
	\pre Буфер b не пересекается с буфером mod.
	\expect \gcd(a, mod) = 1.
	\remark Если \gcd(a, mod) != 1, то b <- 0.
	\deep{stack} zzDivMod_deep(n).
	\safe Функция нерегулярна.
*/
void zzDivMod(
	word b[],				/*!< [out] частное */
	const word divident[],	/*!< [in] делимое */
	const word a[],			/*!< [in] делитель */
	const word mod[],		/*!< [in] модуль */
	size_t n,				/*!< [in] длина чисел в машинных словах */
	void* stack				/*!< [in] вспомогательная память */
);

size_t zzDivMod_deep(size_t n);

/*!	\brief Удвоение числа по модулю

	Определяется произведение [n]b числа [n]a на число 2 по модулю [n]mod:
	\code
		b <- 2 * a \mod mod.
	\endcode
	\pre a < mod.
	\pre Буфер b либо не пересекается, либо совпадает с буфером a.
	\pre Буфер b не пересекается с буфером mod.
	\safe todo
*/
void zzDoubleMod(
	word b[],			/*!< [out] произведение */
	const word a[],		/*!< [in] множитель */
	const word mod[],	/*!< [in] модуль */
	size_t n			/*!< [in] длина чисел в машинных словах */
);

/*!	\brief Половина числа по модулю

	Определяется частное [n]b от деления числа [n]a на число 2 по модулю [n]mod:
	\code
		b <- a * 2^{-1} \mod mod.
	\endcode
	\pre mod -- нечетное && mod[n - 1] != 0.
	\pre a < mod.
	\pre Буфер b либо не пересекается, либо совпадает с буфером a.
	\pre Буфер b не пересекается с буфером mod.
	\safe todo
*/
void zzHalfMod(
	word b[],			/*!< [out] частное */
	const word a[],		/*!< [in] делимое */
	const word mod[],	/*!< [in] модуль */
	size_t n			/*!< [in] длина чисел в машинных словах */
);

/*!	\brief Почти-обращение по модулю

	Определяется число [n]b, почти-мультипликативно обратное к [n]a 
	по модулю [n]mod:
	\code
		b <- a^{-1} * 2^k \mod mod,
	\endcode
	где wwBitSize(mod) <= k <= 2 * wwBitSize(mod).
	\pre mod -- нечетное && mod[n - 1] != 0.
	\pre 0 < a < mod.
	\pre Буфер b не пересекается с буфером mod.
	\expect \gcd(a, mod) == 1.
	\return Параметр k.
	\remark Если \gcd(a, mod) != 1, то b <- 0.
	\remark Применяя k раз zzHalfMod(), можно определить по b обычный обратный 
	элемент. Применяя n * B_PER_W - k раз zzDoubleMod(), можно определить по b
	обратный элемент относительно умножения Монтгомери.
	\deep{stack} zzAlmostInvMod_deep(n).
	\safe Функция нерегулярна.
*/
size_t zzAlmostInvMod(
	word b[],			/*!< [out] обратное число */
	const word a[],		/*!< [in] обращаемое число */
	const word mod[],	/*!< [in] модуль */
	size_t n,			/*!< [in] длина чисел в машинных словах */
	void* stack			/*!< [in] вспомогательная память */
);

size_t zzAlmostInvMod_deep(size_t n);

/*!	\brief Случайный вычет по модулю

	С помощью генератора rng с состоянием rng_state
	определяется случайный вычет [n]a по модулю [n]mod:
	\code
		a <-R {0, 1,..., mod - 1}.
	\endcode
	\pre n > 0 && mod[n - 1] != 0.
	\pre Буфер a не пересекается с буфером mod.
	\return Признак успеха.
	\remark Если 2^{l - 1} <= mod < 2^l, то для генерации a потребуется
		O_OF_B(l) * 2^l / mod <= 2 * O_OF_B(l)
	случайных октетов rng в среднем. 
	\remark Если rng выдает данные низкого статистического качества, 
	то для генерации может потребоваться больше октетов, чем указано
	выше. Более того, как только количество потребовавшихся октетов превысит
	определенный порог d, будет возвращен отрицательный результат. Порог d 
	выбирается так, что вероятность события "для генерации потребуется d 
	истинно случайных октетов" не превосходит 2^{-B_PER_IMPOSSIBLE}.
	\safe todo
*/
bool_t zzRandMod(
	word a[],			/*!< [out] случайное число */
	const word mod[],	/*!< [in] модуль */
	size_t n,			/*!< [in] длина a и mod в машинных словах */
	gen_i rng,			/*!< [in] генератор случайных чисел */
	void* rng_state		/*!< [in/out] состояние генератора */
);

/*!	\brief Случайный ненулевой вычет по модулю

	С помощью генератора rng с состоянием rng_state
	определяется случайный ненулевой вычет [n]a по модулю [n]mod:
	\code
		a <-R {1, 2,..., mod - 1}.
	\endcode
	\pre n > 0 && mod[n - 1] != 0 && mod != 1.
	\pre Буфер a не пересекается с буфером mod.
	\return Признак успеха.
	\remark Если 2^{l - 1} <= mod < 2^l, то для генерации a потребуется
		O_OF_B(l) * 2^l / (mod - 1) \leq 2^l / (2^{l - 1} - 1) O_OF_B(l)
	случайных октетов rng в среднем. 
	\remark Повторяется последнее замечание по функции zzRandMod().
	\safe todo
*/
bool_t zzRandNZMod(
	word a[],			/*!< [out] случайное число */
	const word mod[],	/*!< [in] модуль */
	size_t n,			/*!< [in] длина a и mod в машинных словах */
	gen_i rng,			/*!< [in] генератор случайных чисел */
	void* rng_state		/*!< [in/out] состояние генератора */
);

/*!
*******************************************************************************
\file zz.h

\section zz-red Редукция

Редукция состоит в определении вычета числа [2n]a по модулю [n]mod.
Обрабатываемое число всегда состоит из 2n машинных слов и результат всегда 
возвращается на месте а (ср. с zzMod()). Чтобы подчеркнуть данные соглашения 
вместо Mod (остаток от деления) пишется Red (редукция).

Кроме обычной редукции реализованы быстрые редукции по специальным модулям.
*******************************************************************************
*/

/*!	\brief Стандартная редукция

	Определяется остаток [n]a от деления числа [2n]a на модуль [n]mod.
	\pre n >= 1 && mod[n - 1] != 0.
	\pre Буферы a и mod не пересекаются.
	\deep{stack} zzRed_deep(n).
	\safe Функция нерегулярна.
*/
void zzRed(
	word a[],					/*!< [in/out] делимое / остаток */
	const word mod[],			/*!< [in] модуль */
	size_t n,					/*!< [in] длина mod в машинных словах */
	void* stack					/*!< [in] вспомогательная память */
);

size_t zzRed_deep(size_t n);

/*!	\brief Редукция Крэндалла

	Определяется остаток  [n]a от деления числа [2n]a на модуль [n]mod,
	который близок снизу к B^n.
	\pre n >= 2 && mod[n - 1] != 0.
	\pre Модуль mod имеет вид B^n - c, где 0 < c < B.
	\pre Буферы a и mod не пересекаются.
	\deep{stack} zzRedCrand_deep(n).
	\safe todo
*/
void zzRedCrand(
	word a[],					/*!< [in/out] делимое / остаток */
	const word mod[],			/*!< [in] модуль Крэндалла */
	size_t n,					/*!< [in] длина mod в машинных словах */
	void* stack					/*!< [in] вспомогательная память (не исп.) */
);

size_t zzRedCrand_deep(size_t n);

/*!	\brief Параметр Барретта

	По модулю [n]mod определяется параметр [n + 2]barr_param:
	\code
		barr_param <- B^{2n} \div mod.
	\endcode
	Этот параметр используется в редукции Барретта.
	\pre n > 0 && mod[n] != 0.
	\pre Буферы barr_param и mod не пересекаются.
	\deep{stack} zzCalcBarrParam_deep(n).
*/
void zzCalcBarrParam(
	word barr_param[],			/*!< [out] параметр Барретта */
	const word mod[],			/*!< [in] модуль */
	size_t n,					/*!< [in] длина mod в машинных словах */
	void* stack					/*!< [in] вспомогательная память */
);

size_t zzCalcBarrParam_deep(size_t n);

/*!	\brief Редукция Барретта

	Определяется остаток [n]a от деления числа [2n]a на модуль [n]mod.
	При вычислениях используется параметр Барретта [n + 2]barr_param.
	\pre n > 0 && mod[n - 1] != 0.
	\pre Буфер a не пересекается с буфером mod.
	\expect barr_param рассчитан с помощью функции zzCalcBarrParam().
	\deep{stack} zzRedBarr_deep(n).
	\safe todo
*/
void zzRedBarr(
	word a[],					/*!< [in/out] делимое / остаток */
	const word mod[],			/*!< [in] модуль */
	size_t n,					/*!< [in] длина mod в машинных словах */
	const word barr_param[],	/*!< [in] параметр Барретта */
	void* stack					/*!< [in] вспомогательная память */
);

size_t zzRedBarr_deep(size_t n);

/*!	\brief Редукция Монтгомери

	Определяется результат [n]a редукции Монтгомери числа [2n]a по
	модулю [n]mod:
	\code
		a <- a * R^{-1} \mod mod, R == B^n.
	\endcode
	При вычислениях используется параметр Монтгомери mont_param.
	\pre mod -- нечетное && mod[n - 1] != 0.
	\pre a < mod * R.
	\pre mont_param рассчитан с помощью функции wordNegInv().
	\pre Буфер a не пересекается с буфером mod.
	\remark Редукция предложена в статье [Montgomery P. L. Modular
	multiplication without trial division. Mathematics of Computation,
	44(170): 519–521, 1985].
	\deep{stack} zzRedMont_deep(n).
	\safe todo
*/
void zzRedMont(
	word a[],					/*!< [in/out] входное число / результат */
	const word mod[],			/*!< [in] модуль */
	size_t n,					/*!< [in] длина mod в машинных словах */
	register word mont_param,	/*!< [in] параметр Монтгомери */
	void* stack					/*!< [in] вспомогательная память */
);

size_t zzRedMont_deep(size_t n);

/*!	\brief Редукция Монтгомери по модулю Крэндалла

	Определяется результат [n]a редукции Монтгомери числа [2n]a по
	модулю [n]mod, который близок снизу к B^n:
	\code
		a <- a * R^{-1} \mod mod, R == B^n.
	\endcode
	При вычислениях используется параметр Монтгомери mont_param.
	\pre n >= 2 && mod -- нечетное && mod имеет вид B^n - c, где 0 < c < B.
	\pre a < mod * R.
	\pre mont_param рассчитан с помощью функции zzCalcMontParam().
	\pre Буфер a не пересекается с буфером mod.
	\deep{stack} zzRedCrandMont_deep(n).
	\safe todo
*/
void zzRedCrandMont(
	word a[],					/*!< [in/out] входное число / результат */
	const word mod[],			/*!< [in] модуль */
	size_t n,					/*!< [in] длина mod в машинных словах */
	register word mont_param,	/*!< [in] параметр Монтгомери */
	void* stack					/*!< [in] вспомогательная память */
);

size_t zzRedCrandMont_deep(size_t n);

/*
*******************************************************************************
Возведение в степень
*******************************************************************************
*/

/*!	\brief Возведение в степень по модулю

	Определяется число [n]c, которое является [m]b-ой степенью числа [n]a
	по модулю [n]mod:
	\code
		c <- a^b \mod mod.
	\endcode
	\pre n > 0 && mod[n - 1] != 0.
	\pre a < mod.
	\remark 0^0 == 1.
	\deep{stack} zzPowerMod_deep(n, m).
	\safe todo
*/
void zzPowerMod(
	word c[],				/*!< [out] степень */
	const word a[],			/*!< [in] основание */
	size_t n,				/*!< [in] длина a, mod в машинных словах */
	const word b[],			/*!< [in] показатель */
	size_t m,				/*!< [in] длина b в машинных словах */
	const word mod[],		/*!< [in] модуль */
	void* stack				/*!< [in] вспомогательная память */
);

size_t zzPowerMod_deep(size_t n, size_t m);

/*!	\brief Возведение в степень по модулю машинного слова

	Определяется b-ая степень числа a по модулю машинного слова mod.
	\pre mod != 0.
	\return Степень.
	\deep{stack} zzPowerModW_deep().
	\safe todo
*/
word zzPowerModW(
	register word a,		/*!< [in] основание */
	register word b,		/*!< [in] показатель */
	register word mod,		/*!< [in] модуль */
	void* stack				/*!< [in] вспомогательная память */
);

size_t zzPowerModW_deep();


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __ZZ_H */
