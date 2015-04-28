/*
*******************************************************************************
\file pri.c
\brief Prime numbers
\project bee2 [cryptographic library]
\author (С) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2012.08.13
\version 2015.02.03
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/mem.h"
#include "bee2/core/prng.h"
#include "bee2/core/util.h"
#include "bee2/math/pri.h"
#include "bee2/math/ww.h"
#include "bee2/math/zm.h"

/*
*******************************************************************************
Факторная база: первые 1024 нечетных простых

Построены в Mathematica: Table[Prime[i], {i, 2, 1025}]
*******************************************************************************
*/

static const word _base[] =
{
	3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
	71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139,
	149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223,
	227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293,
	307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383,
	389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463,
	467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569,
	571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647,
	653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743,
	751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839,
	853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941,
	947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021, 1031,
	1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097,
	1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163, 1171, 1181, 1187,
	1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277,
	1279, 1283, 1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327,
	1361, 1367, 1373, 1381, 1399, 1409, 1423, 1427, 1429, 1433, 1439,
	1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499,
	1511, 1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583,
	1597, 1601, 1607, 1609, 1613, 1619, 1621, 1627, 1637, 1657, 1663,
	1667, 1669, 1693, 1697, 1699, 1709, 1721, 1723, 1733, 1741, 1747,
	1753, 1759, 1777, 1783, 1787, 1789, 1801, 1811, 1823, 1831, 1847,
	1861, 1867, 1871, 1873, 1877, 1879, 1889, 1901, 1907, 1913, 1931,
	1933, 1949, 1951, 1973, 1979, 1987, 1993, 1997, 1999, 2003, 2011,
	2017, 2027, 2029, 2039, 2053, 2063, 2069, 2081, 2083, 2087, 2089,
	2099, 2111, 2113, 2129, 2131, 2137, 2141, 2143, 2153, 2161, 2179,
	2203, 2207, 2213, 2221, 2237, 2239, 2243, 2251, 2267, 2269, 2273,
	2281, 2287, 2293, 2297, 2309, 2311, 2333, 2339, 2341, 2347, 2351,
	2357, 2371, 2377, 2381, 2383, 2389, 2393, 2399, 2411, 2417, 2423,
	2437, 2441, 2447, 2459, 2467, 2473, 2477, 2503, 2521, 2531, 2539,
	2543, 2549, 2551, 2557, 2579, 2591, 2593, 2609, 2617, 2621, 2633,
	2647, 2657, 2659, 2663, 2671, 2677, 2683, 2687, 2689, 2693, 2699,
	2707, 2711, 2713, 2719, 2729, 2731, 2741, 2749, 2753, 2767, 2777,
	2789, 2791, 2797, 2801, 2803, 2819, 2833, 2837, 2843, 2851, 2857,
	2861, 2879, 2887, 2897, 2903, 2909, 2917, 2927, 2939, 2953, 2957,
	2963, 2969, 2971, 2999, 3001, 3011, 3019, 3023, 3037, 3041, 3049,
	3061, 3067, 3079, 3083, 3089, 3109, 3119, 3121, 3137, 3163, 3167,
	3169, 3181, 3187, 3191, 3203, 3209, 3217, 3221, 3229, 3251, 3253,
	3257, 3259, 3271, 3299, 3301, 3307, 3313, 3319, 3323, 3329, 3331,
	3343, 3347, 3359, 3361, 3371, 3373, 3389, 3391, 3407, 3413, 3433,
	3449, 3457, 3461, 3463, 3467, 3469, 3491, 3499, 3511, 3517, 3527,
	3529, 3533, 3539, 3541, 3547, 3557, 3559, 3571, 3581, 3583, 3593,
	3607, 3613, 3617, 3623, 3631, 3637, 3643, 3659, 3671, 3673, 3677,
	3691, 3697, 3701, 3709, 3719, 3727, 3733, 3739, 3761, 3767, 3769,
	3779, 3793, 3797, 3803, 3821, 3823, 3833, 3847, 3851, 3853, 3863,
	3877, 3881, 3889, 3907, 3911, 3917, 3919, 3923, 3929, 3931, 3943,
	3947, 3967, 3989, 4001, 4003, 4007, 4013, 4019, 4021, 4027, 4049,
	4051, 4057, 4073, 4079, 4091, 4093, 4099, 4111, 4127, 4129, 4133,
	4139, 4153, 4157, 4159, 4177, 4201, 4211, 4217, 4219, 4229, 4231,
	4241, 4243, 4253, 4259, 4261, 4271, 4273, 4283, 4289, 4297, 4327,
	4337, 4339, 4349, 4357, 4363, 4373, 4391, 4397, 4409, 4421, 4423,
	4441, 4447, 4451, 4457, 4463, 4481, 4483, 4493, 4507, 4513, 4517,
	4519, 4523, 4547, 4549, 4561, 4567, 4583, 4591, 4597, 4603, 4621,
	4637, 4639, 4643, 4649, 4651, 4657, 4663, 4673, 4679, 4691, 4703,
	4721, 4723, 4729, 4733, 4751, 4759, 4783, 4787, 4789, 4793, 4799,
	4801, 4813, 4817, 4831, 4861, 4871, 4877, 4889, 4903, 4909, 4919,
	4931, 4933, 4937, 4943, 4951, 4957, 4967, 4969, 4973, 4987, 4993,
	4999, 5003, 5009, 5011, 5021, 5023, 5039, 5051, 5059, 5077, 5081,
	5087, 5099, 5101, 5107, 5113, 5119, 5147, 5153, 5167, 5171, 5179,
	5189, 5197, 5209, 5227, 5231, 5233, 5237, 5261, 5273, 5279, 5281,
	5297, 5303, 5309, 5323, 5333, 5347, 5351, 5381, 5387, 5393, 5399,
	5407, 5413, 5417, 5419, 5431, 5437, 5441, 5443, 5449, 5471, 5477,
	5479, 5483, 5501, 5503, 5507, 5519, 5521, 5527, 5531, 5557, 5563,
	5569, 5573, 5581, 5591, 5623, 5639, 5641, 5647, 5651, 5653, 5657,
	5659, 5669, 5683, 5689, 5693, 5701, 5711, 5717, 5737, 5741, 5743,
	5749, 5779, 5783, 5791, 5801, 5807, 5813, 5821, 5827, 5839, 5843,
	5849, 5851, 5857, 5861, 5867, 5869, 5879, 5881, 5897, 5903, 5923,
	5927, 5939, 5953, 5981, 5987, 6007, 6011, 6029, 6037, 6043, 6047,
	6053, 6067, 6073, 6079, 6089, 6091, 6101, 6113, 6121, 6131, 6133,
	6143, 6151, 6163, 6173, 6197, 6199, 6203, 6211, 6217, 6221, 6229,
	6247, 6257, 6263, 6269, 6271, 6277, 6287, 6299, 6301, 6311, 6317,
	6323, 6329, 6337, 6343, 6353, 6359, 6361, 6367, 6373, 6379, 6389,
	6397, 6421, 6427, 6449, 6451, 6469, 6473, 6481, 6491, 6521, 6529,
	6547, 6551, 6553, 6563, 6569, 6571, 6577, 6581, 6599, 6607, 6619,
	6637, 6653, 6659, 6661, 6673, 6679, 6689, 6691, 6701, 6703, 6709,
	6719, 6733, 6737, 6761, 6763, 6779, 6781, 6791, 6793, 6803, 6823,
	6827, 6829, 6833, 6841, 6857, 6863, 6869, 6871, 6883, 6899, 6907,
	6911, 6917, 6947, 6949, 6959, 6961, 6967, 6971, 6977, 6983, 6991,
	6997, 7001, 7013, 7019, 7027, 7039, 7043, 7057, 7069, 7079, 7103,
	7109, 7121, 7127, 7129, 7151, 7159, 7177, 7187, 7193, 7207, 7211,
	7213, 7219, 7229, 7237, 7243, 7247, 7253, 7283, 7297, 7307, 7309,
	7321, 7331, 7333, 7349, 7351, 7369, 7393, 7411, 7417, 7433, 7451,
	7457, 7459, 7477, 7481, 7487, 7489, 7499, 7507, 7517, 7523, 7529,
	7537, 7541, 7547, 7549, 7559, 7561, 7573, 7577, 7583, 7589, 7591,
	7603, 7607, 7621, 7639, 7643, 7649, 7669, 7673, 7681, 7687, 7691,
	7699, 7703, 7717, 7723, 7727, 7741, 7753, 7757, 7759, 7789, 7793,
	7817, 7823, 7829, 7841, 7853, 7867, 7873, 7877, 7879, 7883, 7901,
	7907, 7919, 7927, 7933, 7937, 7949, 7951, 7963, 7993, 8009, 8011,
	8017, 8039, 8053, 8059, 8069, 8081, 8087, 8089, 8093, 8101, 8111,
	8117, 8123, 8147, 8161, 8167, 
};

size_t priBaseSize()
{
	ASSERT(LAST_OF(_base) < WORD_BIT_HALF);
	return COUNT_OF(_base);
}

word priBasePrime(size_t i)
{
	ASSERT(LAST_OF(_base) < WORD_BIT_HALF);
	ASSERT(i < priBaseSize());
	return _base[i];
}

void priBaseMod(word mods[], const word a[], size_t n, size_t count)
{
	size_t i;
	// pre
	ASSERT(wwIsValid(a, n));
	ASSERT(count <= priBaseSize());
	ASSERT(memIsValid(mods, count * O_PER_W));
	// пробегаем простые из факторной базы
	for (i = 0; i < count;)
	{
		// простое укладывается в половину машинного слова?
		if (_base[i] < WORD_BIT_HALF)
		{
			word t, t1;
			size_t len, j;
			// составляем максимальное произведение последовательных простых,
			// которое укладывается в половину машинного слова
			t = _base[i], len = 1;
			while (i + len < count &&
				_base[i + len] < WORD_BIT_HALF &&
				(t1 = t * _base[i + len]) < WORD_BIT_HALF)
				t = t1, ++len;
			// t <- a % t
			t = zzModW2(a, n, t);
			// mods[j] <- t % _base[j]
			for (j = i; j < i + len; ++j)
				mods[j] = t % _base[j];
			// к новому произведению
			i = j;
		}
		// ...не укладывается, просто делим
		else
			mods[i] = zzModW(a, n, _base[i]), ++i;
	}
}

/*
*******************************************************************************
Использование факторной базы

\todo Алгоритм Бернштейна выделения гладкой части 
[http://cr.yp.to/factorization/smoothparts-20040510.pdf]:
	z <- p1 p2 .... pm \mod a
	y <- z^{2^e} \mod a (e --- минимальное натуральное т.ч. 3^{2^e} > a)
	return \gcd(x, y)
*******************************************************************************
*/

bool_t priIsSieved(const word a[], size_t n, size_t base_count, void* stack)
{
	// переменные в stack
	word* mods;
	// pre
	ASSERT(base_count <= priBaseSize());
	// четное?
	n = wwWordSize(a, n);
	if (zzIsEven(a, n))
		return FALSE;
	// малое a?
	if (n == 1)
		// при необходимости скоррректировать факторную базу
		while (base_count > 0 && priBasePrime(base_count - 1) > a[0])
			--base_count;
	// раскладка stack
	mods = (word*)stack;
	stack = mods + base_count;
	// найти остатки
	priBaseMod(mods, a, n, base_count);
	// есть нулевые остатки?
	while (base_count--)
		if (mods[base_count] == 0)
			return FALSE;
	// нет
	return TRUE;
}

size_t priIsSieved_deep(size_t base_count)
{
	return O_OF_W(base_count);
}

bool_t priIsSmooth(const word a[], size_t n, size_t base_count, void* stack)
{
	register size_t i;
	register word mod;
	// переменные в stack
	word* t = (word*)stack;
	stack = t + n;
	// pre
	ASSERT(base_count <= priBaseSize());
	// t <- a 
	wwCopy(t, a, n);
	// разделить t на степень 2
	i = wwLoZeroBits(t, n);
	wwShLo(t, n, i);
	n = wwWordSize(t, n);
	if (wwIsZero(t, n))
	{
		i = 0;
		return TRUE;
	}
	// цикл по простым из факторной базы
	for (i = 0; i < base_count;)
	{
		mod = _base[i] < WORD_BIT_HALF ? 
			zzModW2(t, n, _base[i]) : zzModW(t, n, _base[i]);
		// делится на простое?
		if (mod == 0)
		{
			zzDivW(t, t, n, _base[i]);
			n = wwWordSize(t, n);
			if (wwIsZero(t, n))
			{
				i = 0, mod = 0;
				return TRUE;
			}
		}
		// .. не делится
		else 
			++i;
	}
	i = 0, mod = 0;
	return FALSE;
}

size_t priIsSmooth_deep(size_t n)
{
	return O_OF_W(n);
}

/*
*******************************************************************************
Проверка простоты малых чисел

Применяется тест Миллера --- Рабина со специально подобранными основаниями.
Успешное завершение теста на всех основаниях из списка _base16 гарантирует
простоту чисел вплоть до 1373653, из списка _base32 --- вплоть
до 4759123141, из списка _base64 --- для всех 64-разрядных чисел.

Список оснований: http://miller-rabin.appspot.com (список обновляется).

\todo Проверка на малые делители позволит уменьшить число оснований / 
сократить время проверки?
*******************************************************************************
*/

const word _bases16[] = {2, 3};
const word _bases32[] = {2, 7, 61};
#if (B_PER_W == 64)
const word _bases64[] = {2, 325, 9375, 28178, 450775, 9780504, 1795265022};
#endif

bool_t priIsPrimeW(register word a, void* stack)
{
	const word* bases;
	register word r;
	register size_t s;
	register size_t iter;
	register size_t i;
	register word base;
	register dword prod;
	// маленькое или четное?
	if (a <= 3 || a % 2 == 0)
		return a == 2 || a == 3;
	// a - 1 = 2^s r (r -- нечетное)
	for (r = a - 1, s = 0; r % 2 == 0; r >>= 1, ++s);
	ASSERT(s > 0 && WORD_BIT_POS(s) * r + 1 == a);
	// выбираем базис
#if (B_PER_W == 16)
	bases = _bases16, iter = COUNT_OF(_bases16);
#elif (B_PER_W == 32)
	if (a < 1373653)
		bases = _bases16, iter = COUNT_OF(_bases16);
	else
		bases = _bases32, iter = COUNT_OF(_bases32);
#elif (B_PER_W == 64)
	if (a < 1373653)
		bases = _bases16, iter = COUNT_OF(_bases16);
	else if (a < 4759123141)
		bases = _bases32, iter = COUNT_OF(_bases32);
	else
		bases = _bases64, iter = COUNT_OF(_bases64);
#endif
	// итерации
	while (iter--)
	{
		// _bases[iter]^r \equiv \pm 1 \mod a?
		base = zzPowerModW(bases[iter], r, a, stack);
		if (base == 1 || base == a - 1)
			continue;
		// base^{2^i} \equiv - 1\mod a?
		for (i = s - 1; i--;)
		{
			prod = base;
			prod *= base, base = prod % a;
			if (base == a - 1)
				break;
			if (base == 1)
			{
				r = base = 0, s = iter = i = 0, prod = 0;
				return FALSE;
			}
		}
		if (i == SIZE_MAX)
		{
			r = base = 0, s = iter = i = 0, prod = 0;
			return FALSE;
		}
	}
	r = base = 0, s = iter = i = 0, prod = 0;
	return TRUE;
}

size_t priIsPrimeW_deep()
{
	return zzPowerModW_deep();
}

/*
*******************************************************************************
Тест Рабина -- Миллера

При операциях \mod a может использоваться умножение Монтгомери. При этом
случайное основание выбирается отличным от R \mod a, -R \mod a (R = B^n),
а получаемые степени сравниваются не с \pm 1 \mod a, а с \pm R \mod a.

\warning Ошибка при вызове zzRandMod() интерпретируется как то, что число
является составным.

\todo Цикл do-while может выполняться бесконечно долго, если все время 
получается нулевое число.
*******************************************************************************
*/

bool_t priRMTest(const word a[], size_t n, size_t iter, void* stack)
{
	register size_t s;
	register size_t m;
	register size_t i;
	// переменные в stack
	word* r = (word*)stack;
	word* base = r + n;
	qr_o* qr = (qr_o*)(base + n);
	octet* combo_state = (octet*)qr + zmCreate_keep(O_OF_W(n));
	stack = combo_state + prngCOMBO_keep();
	// pre
	ASSERT(wwIsValid(a, n));
	// нормализация
	n = wwWordSize(a, n);
	// четное?
	if (zzIsEven(a, n))
		return wwCmpW(a, n, 2) == 0;
	// маленькое?
	if (n == 1 && a[0] <= 7)
		return a[0] != 1;
	// подготовить генератор
	prngCOMBOStart(combo_state, utilNonce32());
	// создать кольцо
	wwToMem(base, a, n);
	zmCreate(qr, (octet*)base, memNonZeroSize(base, O_OF_W(n)), stack);
	// a - 1 = r 2^s (r -- нечетное)
	wwCopy(r, a, n);
	zzSubW2(r, n, 1);
	s = wwLoZeroBits(r, n);
	wwShLo(r, n, s);
	m = wwWordSize(r, n);
	// итерации
	while (iter--)
	{
		// base <-R {1, \ldots, a - 1} \ {\pm one}
		do
			if (!zzRandMod(base, a, n, prngCOMBOStepG, combo_state))
			{
				s = m = 0;
				return FALSE;
			}
		while (wwIsZero(base, n) ||
			wwEq(base, qr->unity, n) ||
			zzIsSumEq(a, base, qr->unity, n));
		// base <- base^r \mod a
		qrPower(base, base, r, m, qr, stack);
		// base == \pm one => тест пройден
		if (wwEq(base, qr->unity, n) ||
			zzIsSumEq(a, base, qr->unity, n))
			continue;
		// base^{2^i} \equiv -1 \mod a?
		for (i = s; i--;)
		{
			qrSqr(base, base, qr, stack);
			if (wwEq(base, qr->unity, n))
			{
				s = m = i = 0;
				return FALSE;
			}
			if (zzIsSumEq(a, base, qr->unity, n))
				break;
		}
		if (i == SIZE_MAX)
		{
			s = m = i = 0;
			return FALSE;
		}
	}
	s = m = i = 0;
	// простое
	return TRUE;
}

size_t priRMTest_deep(size_t n)
{
	size_t qr_deep = zmCreate_deep(O_OF_W(n));
	return O_OF_W(2 * n) + zmCreate_keep(O_OF_W(n)) + prngCOMBO_keep() +
		utilMax(2,
			qr_deep,
			qrPower_deep(n, n, qr_deep));
}

bool_t priIsPrime(const word a[], size_t n, void* stack)
{
	return priRMTest(a, n, (B_PER_IMPOSSIBLE + 1) / 2, stack);
}

size_t priIsPrime_deep(size_t n)
{
	return priRMTest_deep(n);
}

/*
*******************************************************************************
Простое Софи Жермен

q -- нечетное простое => p = 2q + 1 -- простое <=> [теорема Демитко]
1) 2^2 \not\equiv 1 \mod p;
2) 2^2q \equiv 1 \mod p.
*******************************************************************************
*/

bool_t priIsSGPrime(const word q[], size_t n, void* stack)
{
	size_t no = O_OF_W(n + 1);
	// переменные в stack
	word* p;
	qr_o* qr;
	// pre
	ASSERT(zzIsOdd(q, n) && wwCmpW(q, n, 1) > 0);
	// раскладка стек
	p = (word*)stack;
	qr = (qr_o*)(p + n + 1);
	stack = (octet*)qr + zmCreate_keep(no);
	// p <- 2q + 1
	wwCopy(p, q, n);
	p[n] = 0;
	wwShHi(p, n + 1, 1);
	++p[0];
	// создать кольцо \mod p
	no = wwOctetSize(p, n + 1);
	wwToMem(p, p, n + 1);
	zmCreate(qr, (octet*)p, no, stack);
	// p <- 4^q (в кольце qr)
	qrAdd(p, qr->unity, qr->unity, qr);
	qrAdd(p, p, p, qr);
	qrPower(p, p, q, n, qr, stack);
	// 4^q == 1 (в кольце qr)?
	return qrCmp(p, qr->unity, qr) == 0;
}

size_t priIsSGPrime_deep(size_t n)
{
	const size_t no = O_OF_W(n + 1);
	const size_t qr_deep = zmCreate_deep(no);
	return no + zmCreate_keep(no) +
		utilMax(2,
			qr_deep,
			qrPower_deep(n + 1, n, qr_deep));
}

/*
*******************************************************************************
Следующее простое
*******************************************************************************
*/

bool_t priNextPrimeW(word p[1], register word a, void* stack)
{
	register size_t l;
	// p <- a, l <- битовая длина a
	p[0] = a, l = wwBitSize(p, 1);
	// 0-битовых и 1-битовых простых не существует
	if (l <= 1)
		return FALSE;
	// сделать p нечетным
	p[0] |= 1;
	// поиск
	while (!priIsPrimeW(p[0], stack))
	{
		p[0] += 2;
		if (wwBitSize(p, 1) != l)
		{
			l = 0;
			return FALSE;
		}
	}
	l = 0;
	return TRUE;
}

size_t priNextPrimeW_deep()
{
	return priIsPrimeW_deep();
}

bool_t priNextPrime(word p[], const word a[], size_t n, size_t trials,
	size_t base_count, size_t iter, void* stack)
{
	size_t l;
	size_t i;
	bool_t base_success;
	// переменные в stack
	word* mods;
	// pre
	ASSERT(wwIsSameOrDisjoint(a, p, n));
	ASSERT(base_count <= priBaseSize());
	// раскладка stack
	mods = (word*)stack;
	stack = mods + base_count;
	// l <- битовая длина a
	l = wwBitSize(a, n);
	// 0-битовых и 1-битовых простых не существует
	if (l <= 1)
		return FALSE;
	// p <- минимальное нечетное >= a
	wwCopy(p, a, n);
	p[0] |= 1;
	// малое p?
	if (n == 1)
		// при необходимости скоррректировать факторную базу
		while (base_count > 0 && priBasePrime(base_count - 1) >= p[0])
			--base_count;
	// рассчитать остатки от деления на малые простые
	priBaseMod(mods, p, n, base_count);
	for (i = 0, base_success = TRUE; i < base_count; ++i)
		if (mods[i] == 0)
		{
			base_success = FALSE;
			break;
		}
	// попытки
	while (trials == SIZE_MAX || trials--)
	{
		// проверка простоты
		if (base_success && priRMTest(p, n, iter, stack))
			return TRUE;
		// к следующему кандидату
		if (zzAddW2(p, n, 2) || wwBitSize(p, n) > l)
			return FALSE;
		for (i = 0, base_success = TRUE; i < base_count; ++i)
		{
			if (mods[i] < _base[i] - 2)
				mods[i] += 2;
			else if (mods[i] == _base[i] - 1)
				mods[i] = 1;
			else
				mods[i] = 0, base_success = FALSE;
		}
	}
	return FALSE;
}

size_t priNextPrime_deep(size_t n, size_t base_count)
{
	return base_count * O_PER_W + priRMTest_deep(n);
}

/*
*******************************************************************************
Расширение простого

Теорема Демитко. Если q -- нечетное простое, p = 2qr + 1, где 2r < 4q + 1,
и выполнены условия:
1) 2^{2qr} \equiv 1 \mod p;
2) 2^{2r} \not\equiv 1 \mod p,
то p -- простое.

\remark Если l <= 2 * lq, где lq = bitlen(q), то условие 2r < 4q + 1 будет
выполнено:
2r = (p - 1) / q < 2^l / (2^{lq - 1}} = 2^{l - lq + 1} <= 2^{lq + 2} < 4q.

Построение p:
1) t <-R {2^{l - 2} + 1,..., 2^{l - 1} - 1};
2) t <- t + 2^{l - 1};
3) r <- ceil(t / q);
4) p <- 2qr + 1;
5) если bitlen(p) != l, то вернуться к шагу 1.

\remark Если t укладывается в m слов, q -- в n слов, то r на шаге 3)
укладывается в m - n + 1 слов. Действительно, максимальное r получается
при t = B^m - 1, q = B^{n - 1} и равняется B^{m - n + 1} - 1.
*******************************************************************************
*/

bool_t priExtendPrime(word p[], size_t l, const word q[], size_t n,
	size_t trials, size_t base_count, gen_i rng, void* rng_state, void* stack)
{
	const size_t m = W_OF_B(l);
	const size_t mo = O_OF_B(l);
	size_t i;
	// переменные в stack
	word* r;
	word* t;
	word* four;
	word* mods;
	word* mods1;
	qr_o* qr;
	// pre
	ASSERT(wwIsDisjoint2(q, n, p, m));
	ASSERT(zzIsOdd(q, n) && wwCmpW(q, n, 3) >= 0);
	ASSERT(wwBitSize(q, n) + 1 <= l && l <= 2 * wwBitSize(q, n));
	ASSERT(base_count <= priBaseSize());
	ASSERT(rng != 0);
	// подкорректировать n
	n = wwWordSize(q, n);
	// раскладка stack
	r = (word*)stack;
	t = r + m - n + 1;
	four = t + m + 1;
	mods = four + m;
	mods1 = mods + base_count;
	qr = (qr_o*)(mods1 + base_count);
	stack = (octet*)qr + zmCreate_keep(mo);
	// малое p?
	if (l < B_PER_W)
		// при необходимости уменьшить факторную базу
		while (base_count > 0 && 
			priBasePrime(base_count - 1) > WORD_BIT_POS(l - 1))
			--base_count;
	// попытки
	while (trials == SIZE_MAX || trials--)
	{
		// t <-R [2^{l - 2}, 2^{l - 1})
		rng(t, mo, rng_state);
		memToWord(t, t, mo);
		wwTrimHi(t, m, l - 2);
		wwSetBit(t, l - 2, 1);
		// r <- t \div q
		zzDiv(r, t, t, m, q, n, stack);
		if (!wwIsZero(t, m))
			VERIFY(zzAddW2(r, m - n + 1, 1) == 0);
		// t <- q * r
		zzMul(t, q, n, r, m - n + 1, stack);
		if (wwBitSize(t, m) > l - 1)
			continue;
		// p <- 2 * t + 1
		wwCopy(p, t, m);
		wwShHi(p, m, 1);
		++p[0];
		ASSERT(wwBitSize(p, m) == l);
		// рассчитать вычеты p, 2q по малым модулям
		priBaseMod(mods, p, m, base_count);
		priBaseMod(mods1, q, n, base_count);
		for (i = 0; i < base_count; ++i)
			if ((mods1[i] += mods1[i]) >= _base[i])
				mods1[i] -= _base[i];
		// проверка простоты
		while (1)
		{
			// p делится на малые простые?
			for (i = 0; i < base_count; ++i)
				if (mods[i] == 0)
					break;
			// не делится: тест Демитко
			if (i == base_count)
			{
				// создать кольцо вычетов \mod p
				wwToMem(t, p, m);
				zmCreate(qr, (octet*)t, mo, stack);
				// four <- 4 [в кольце qr]
				qrAdd(four, qr->unity, qr->unity, qr);
				qrAdd(four, four, four, qr);
				// 4^r \mod p != 1?
				qrPower(t, four, r, m - n + 1, qr, stack);
				if (qrCmp(t, qr->unity, qr) != 0)
				{
					// (4^r)^q \mod p == 1?
					qrPower(t, t, q, n, qr, stack);
					if (qrCmp(t, qr->unity, qr) == 0)
						return TRUE;
				}
			}
			// p <- p + 2q, переполнение?
			if (zzAddW2(p + n, m - n, zzAdd2(p, q, n)) ||
				zzAddW2(p + n, m - n, zzAdd2(p, q, n)) ||
				wwBitSize(p, m) > l)
				break;
			// r <- r + 1, t <- t + q, пересчитать mods
			zzAddW2(r, m - n + 1, 1);
			zzAddW2(t + n, m - n, zzAdd2(t, q, n));
			for (i = 0; i < base_count; ++i)
				if ((mods[i] += mods1[i]) >= _base[i])
					mods[i] -= _base[i];
			// к следующей попытке
			if (trials != SIZE_MAX && trials-- == 0)
				return FALSE;
		}
	}
	return FALSE;
}

size_t priExtendPrime_deep(size_t l, size_t n, size_t base_count)
{
	const size_t m = W_OF_B(l);
	const size_t mo = O_OF_B(l);
	const size_t qr_deep = zmCreate_deep(mo);
	ASSERT(m >= n);
	return O_OF_W(m - n + 1 + m + 1 + m + 2 * base_count) + zmCreate_keep(mo) +
		utilMax(4,
			zzDiv_deep(m, n),
			zzMul_deep(n, m - n + 1),
			qr_deep,
			qrPower_deep(m, m, qr_deep));
}
