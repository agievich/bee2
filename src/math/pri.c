/*
*******************************************************************************
\file pri.c
\brief Prime numbers
\project bee2 [cryptographic library]
\created 2012.08.13
\version 2024.02.28
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/core/mem.h"
#include "bee2/core/prng.h"
#include "bee2/core/util.h"
#include "bee2/core/word.h"
#include "bee2/math/pri.h"
#include "bee2/math/ww.h"
#include "bee2/math/zm.h"

/*
*******************************************************************************
Факторная база: первые 1024 нечетных простых

Построены в Mathematica: 
\code
	n = 1024;
	Table[Prime[i], {i, 2, n + 1}]
\endcode
*******************************************************************************
*/

static const word _base[] =
{
	3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 
	73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 
	157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 
	239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 
	331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 
	421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 
	509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 
	613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 
	709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 
	821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 
	919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 
	1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091, 
	1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163, 1171, 1181, 
	1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 
	1279, 1283, 1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 
	1367, 1373, 1381, 1399, 1409, 1423, 1427, 1429, 1433, 1439, 1447, 1451, 
	1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511, 1523, 1531, 
	1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609, 
	1613, 1619, 1621, 1627, 1637, 1657, 1663, 1667, 1669, 1693, 1697, 1699, 
	1709, 1721, 1723, 1733, 1741, 1747, 1753, 1759, 1777, 1783, 1787, 1789, 
	1801, 1811, 1823, 1831, 1847, 1861, 1867, 1871, 1873, 1877, 1879, 1889, 
	1901, 1907, 1913, 1931, 1933, 1949, 1951, 1973, 1979, 1987, 1993, 1997, 
	1999, 2003, 2011, 2017, 2027, 2029, 2039, 2053, 2063, 2069, 2081, 2083, 
	2087, 2089, 2099, 2111, 2113, 2129, 2131, 2137, 2141, 2143, 2153, 2161, 
	2179, 2203, 2207, 2213, 2221, 2237, 2239, 2243, 2251, 2267, 2269, 2273, 
	2281, 2287, 2293, 2297, 2309, 2311, 2333, 2339, 2341, 2347, 2351, 2357, 
	2371, 2377, 2381, 2383, 2389, 2393, 2399, 2411, 2417, 2423, 2437, 2441, 
	2447, 2459, 2467, 2473, 2477, 2503, 2521, 2531, 2539, 2543, 2549, 2551, 
	2557, 2579, 2591, 2593, 2609, 2617, 2621, 2633, 2647, 2657, 2659, 2663, 
	2671, 2677, 2683, 2687, 2689, 2693, 2699, 2707, 2711, 2713, 2719, 2729, 
	2731, 2741, 2749, 2753, 2767, 2777, 2789, 2791, 2797, 2801, 2803, 2819, 
	2833, 2837, 2843, 2851, 2857, 2861, 2879, 2887, 2897, 2903, 2909, 2917, 
	2927, 2939, 2953, 2957, 2963, 2969, 2971, 2999, 3001, 3011, 3019, 3023, 
	3037, 3041, 3049, 3061, 3067, 3079, 3083, 3089, 3109, 3119, 3121, 3137, 
	3163, 3167, 3169, 3181, 3187, 3191, 3203, 3209, 3217, 3221, 3229, 3251, 
	3253, 3257, 3259, 3271, 3299, 3301, 3307, 3313, 3319, 3323, 3329, 3331, 
	3343, 3347, 3359, 3361, 3371, 3373, 3389, 3391, 3407, 3413, 3433, 3449, 
	3457, 3461, 3463, 3467, 3469, 3491, 3499, 3511, 3517, 3527, 3529, 3533, 
	3539, 3541, 3547, 3557, 3559, 3571, 3581, 3583, 3593, 3607, 3613, 3617, 
	3623, 3631, 3637, 3643, 3659, 3671, 3673, 3677, 3691, 3697, 3701, 3709, 
	3719, 3727, 3733, 3739, 3761, 3767, 3769, 3779, 3793, 3797, 3803, 3821, 
	3823, 3833, 3847, 3851, 3853, 3863, 3877, 3881, 3889, 3907, 3911, 3917, 
	3919, 3923, 3929, 3931, 3943, 3947, 3967, 3989, 4001, 4003, 4007, 4013, 
	4019, 4021, 4027, 4049, 4051, 4057, 4073, 4079, 4091, 4093, 4099, 4111, 
	4127, 4129, 4133, 4139, 4153, 4157, 4159, 4177, 4201, 4211, 4217, 4219, 
	4229, 4231, 4241, 4243, 4253, 4259, 4261, 4271, 4273, 4283, 4289, 4297, 
	4327, 4337, 4339, 4349, 4357, 4363, 4373, 4391, 4397, 4409, 4421, 4423, 
	4441, 4447, 4451, 4457, 4463, 4481, 4483, 4493, 4507, 4513, 4517, 4519, 
	4523, 4547, 4549, 4561, 4567, 4583, 4591, 4597, 4603, 4621, 4637, 4639, 
	4643, 4649, 4651, 4657, 4663, 4673, 4679, 4691, 4703, 4721, 4723, 4729, 
	4733, 4751, 4759, 4783, 4787, 4789, 4793, 4799, 4801, 4813, 4817, 4831, 
	4861, 4871, 4877, 4889, 4903, 4909, 4919, 4931, 4933, 4937, 4943, 4951, 
	4957, 4967, 4969, 4973, 4987, 4993, 4999, 5003, 5009, 5011, 5021, 5023, 
	5039, 5051, 5059, 5077, 5081, 5087, 5099, 5101, 5107, 5113, 5119, 5147, 
	5153, 5167, 5171, 5179, 5189, 5197, 5209, 5227, 5231, 5233, 5237, 5261, 
	5273, 5279, 5281, 5297, 5303, 5309, 5323, 5333, 5347, 5351, 5381, 5387, 
	5393, 5399, 5407, 5413, 5417, 5419, 5431, 5437, 5441, 5443, 5449, 5471, 
	5477, 5479, 5483, 5501, 5503, 5507, 5519, 5521, 5527, 5531, 5557, 5563, 
	5569, 5573, 5581, 5591, 5623, 5639, 5641, 5647, 5651, 5653, 5657, 5659, 
	5669, 5683, 5689, 5693, 5701, 5711, 5717, 5737, 5741, 5743, 5749, 5779, 
	5783, 5791, 5801, 5807, 5813, 5821, 5827, 5839, 5843, 5849, 5851, 5857, 
	5861, 5867, 5869, 5879, 5881, 5897, 5903, 5923,	5927, 5939, 5953, 5981, 
	5987, 6007, 6011, 6029, 6037, 6043, 6047, 6053, 6067, 6073, 6079, 6089, 
	6091, 6101, 6113, 6121, 6131, 6133, 6143, 6151, 6163, 6173, 6197, 6199, 
	6203, 6211, 6217, 6221, 6229, 6247, 6257, 6263, 6269, 6271, 6277, 6287, 
	6299, 6301, 6311, 6317, 6323, 6329, 6337, 6343, 6353, 6359, 6361, 6367, 
	6373, 6379, 6389, 6397, 6421, 6427, 6449, 6451, 6469, 6473, 6481, 6491, 
	6521, 6529, 6547, 6551, 6553, 6563, 6569, 6571, 6577, 6581, 6599, 6607, 
	6619, 6637, 6653, 6659, 6661, 6673, 6679, 6689, 6691, 6701, 6703, 6709, 
	6719, 6733, 6737, 6761, 6763, 6779, 6781, 6791, 6793, 6803, 6823, 6827, 
	6829, 6833, 6841, 6857, 6863, 6869, 6871, 6883, 6899, 6907, 6911, 6917, 
	6947, 6949, 6959, 6961, 6967, 6971, 6977, 6983, 6991, 6997, 7001, 7013, 
	7019, 7027, 7039, 7043, 7057, 7069, 7079, 7103, 7109, 7121, 7127, 7129, 
	7151, 7159, 7177, 7187, 7193, 7207, 7211, 7213, 7219, 7229, 7237, 7243, 
	7247, 7253, 7283, 7297, 7307, 7309, 7321, 7331, 7333, 7349, 7351, 7369, 
	7393, 7411, 7417, 7433, 7451, 7457, 7459, 7477, 7481, 7487, 7489, 7499, 
	7507, 7517, 7523, 7529, 7537, 7541, 7547, 7549, 7559, 7561, 7573, 7577, 
	7583, 7589, 7591, 7603, 7607, 7621, 7639, 7643, 7649, 7669, 7673, 7681, 
	7687, 7691, 7699, 7703, 7717, 7723, 7727, 7741, 7753, 7757, 7759, 7789, 
	7793, 7817, 7823, 7829, 7841, 7853, 7867, 7873, 7877, 7879, 7883, 7901, 
	7907, 7919, 7927, 7933, 7937, 7949, 7951, 7963, 7993, 8009, 8011, 8017, 
	8039, 8053, 8059, 8069, 8081, 8087, 8089, 8093, 8101, 8111, 8117, 8123, 
	8147, 8161, 8167, 
};

size_t priBaseSize()
{
	return COUNT_OF(_base);
}

word priBasePrime(size_t i)
{
	ASSERT(i < priBaseSize());
	return _base[i];
}

/*
*******************************************************************************
Произведения последовательных простых из факторной базы: множители 
накапливаются до тех пор, пока произведение помещается в машинное слово.
Тривиальные произведения из одного множителя не фиксируются.

Построены в Mathematica: 
\code
	n = 1024;
	w = B_PER_W;
	prods = {};
	For[i = 2, i <= n + 1, 
		For[p = 1; l = 0, 
			i + l <= n + 1 && p * Prime[i + ++l] < 2^w, 
			p *= Prime[i + l]];
		i += l; 
		If[l > 1, AppendTo[prods, {p, l}]
	]
	prods
\endcode
*******************************************************************************
*/

typedef struct pri_prod_t
{
	word prod;		/*< произведение простых из факторной базы */
	size_t num;		/*< количество множителей */	
} pri_prod_t;

static const pri_prod_t _prods[] =
{
#if (B_PER_W == 16)
	{15015u, 5}, {7429u, 3}, {33263u, 3}, {1763u, 2}, {2491u, 2}, 
	{3599u, 2}, {4757u, 2}, {5767u, 2}, {7387u, 2}, {9797u, 2}, {11021u, 2}, 
	{12317u, 2}, {16637u, 2}, {19043u, 2}, {22499u, 2}, {25591u, 2}, 
	{28891u, 2}, {32399u, 2}, {36863u, 2}, {39203u, 2}, {47053u, 2}, 
	{51983u, 2}, {55687u, 2}, {60491u, 2},
#elif (B_PER_W == 32)
	{3234846615u, 9}, {95041567u, 5}, {907383479u, 5}, {4132280413u, 5},
	{121330189u, 4}, {257557397u, 4}, {490995677u, 4}, {842952707u, 4},
	{1314423991u, 4}, {2125525169u, 4}, {3073309843u, 4}, {16965341u, 3},
	{20193023u, 3}, {23300239u, 3}, {29884301u, 3}, {35360399u, 3},
	{42749359u, 3}, {49143869u, 3}, {56466073u, 3}, {65111573u, 3},
	{76027969u, 3}, {84208541u, 3}, {94593973u, 3}, {103569859u, 3},
	{119319383u, 3}, {133390067u, 3}, {154769821u, 3}, {178433279u, 3},
	{193397129u, 3}, {213479407u, 3}, {229580147u, 3}, {250367549u, 3},
	{271661713u, 3}, {293158127u, 3}, {319512181u, 3}, {357349471u, 3},
	{393806449u, 3}, {422400701u, 3}, {452366557u, 3}, {507436351u, 3},
	{547978913u, 3}, {575204137u, 3}, {627947039u, 3}, {666785731u, 3},
	{710381447u, 3}, {777767161u, 3}, {834985999u, 3}, {894826021u, 3},
	{951747481u, 3}, {1019050649u, 3}, {1072651369u, 3}, {1125878063u, 3},
	{1185362993u, 3}, {1267745273u, 3}, {1322520163u, 3}, {1391119619u, 3},
	{1498299287u, 3}, {1608372013u, 3}, {1700725291u, 3}, {1805418283u, 3},
	{1871456063u, 3}, {2008071007u, 3}, {2115193573u, 3}, {2178429527u, 3},
	{2246284699u, 3}, {2385788087u, 3}, {2591986471u, 3}, {2805004793u, 3},
	{2922149239u, 3}, {3021320083u, 3}, {3118412617u, 3}, {3265932301u, 3},
	{3332392423u, 3}, {3523218343u, 3}, {3711836171u, 3}, {3837879163u, 3},
	{3991792529u, 3}, {4139646463u, 3}, {4233155587u, 3}, {2663399u, 2},
	{2755591u, 2}, {2782223u, 2}, {2873021u, 2}, {2903591u, 2}, {2965283u, 2},
	{3017153u, 2}, {3062491u, 2}, {3125743u, 2}, {3186221u, 2}, {3221989u, 2},
	{3301453u, 2}, {3381857u, 2}, {3474487u, 2}, {3504383u, 2}, {3526883u, 2},
	{3590989u, 2}, {3648091u, 2}, {3732623u, 2}, {3802499u, 2}, {3904567u, 2},
	{3960091u, 2}, {3992003u, 2}, {4028033u, 2}, {4088459u, 2}, {4137131u, 2},
	{4235339u, 2}, {4305589u, 2}, {4347221u, 2}, {4384811u, 2}, {4460543u, 2},
	{4536899u, 2}, {4575317u, 2}, {4613879u, 2}, {4708819u, 2}, {4862021u, 2},
	{4915073u, 2}, {5008643u, 2}, {5048993u, 2}, {5143823u, 2}, {5184713u, 2},
	{5244091u, 2}, {5303773u, 2}, {5391563u, 2}, {5475599u, 2}, {5517797u, 2},
	{5588447u, 2}, {5659637u, 2}, {5692987u, 2}, {5740807u, 2}, {5827387u, 2},
	{5904851u, 2}, {5973127u, 2}, {6066353u, 2}, {6125621u, 2}, {6310063u, 2},
	{6426209u, 2}, {6482107u, 2}, {6522907u, 2}, {6682189u, 2}, {6765137u, 2},
	{6859157u, 2}, {6969551u, 2}, {7064963u, 2}, {7112873u, 2}, {7182391u, 2},
	{7225343u, 2}, {7268407u, 2}, {7338677u, 2}, {7376647u, 2}, {7452899u, 2},
	{7535009u, 2}, {7617551u, 2}, {7745053u, 2}, {7806427u, 2}, {7851203u, 2},
	{7986227u, 2}, {8065591u, 2}, {8145307u, 2}, {8236819u, 2}, {8363639u, 2},
	{8444827u, 2}, {8538059u, 2}, {8678867u, 2}, {8761591u, 2}, {8820899u, 2},
	{8999999u, 2}, {9090209u, 2}, {9180851u, 2}, {9272009u, 2}, {9388087u, 2},
	{9492557u, 2}, {9603701u, 2}, {9734399u, 2}, {9922331u, 2}, {10036223u, 2}, 
	{10137847u, 2}, {10220773u, 2}, {10323353u, 2}, {10400609u, 2}, 
	{10575503u, 2}, {10614563u, 2}, {10791029u, 2}, {10916407u, 2}, 
	{10995847u, 2}, {11062267u, 2}, {11135533u, 2}, {11242573u, 2}, 
	{11329931u, 2}, {11431097u, 2}, {11553137u, 2}, {11716829u, 2}, 
	{11923193u, 2}, {11985443u, 2}, {12027023u, 2}, {12215009u, 2},
	{12348187u, 2}, {12446783u, 2}, {12503287u, 2}, {12559927u, 2}, 
	{12659363u, 2}, {12787751u, 2}, {12873719u, 2}, {13032091u, 2}, 
	{13104391u, 2}, {13205947u, 2}, {13329737u, 2}, {13483583u, 2}, 
	{13571807u, 2}, {13682597u, 2}, {13793771u, 2}, {13912891u, 2}, 
	{14062379u, 2}, {14197823u, 2}, {14333747u, 2}, {14439991u, 2},
	{14607683u, 2}, {14745551u, 2}, {14837903u, 2}, {14976851u, 2}, 
	{15093209u, 2}, {15280277u, 2}, {15350723u, 2}, {15413467u, 2}, 
	{15499933u, 2}, {15657749u, 2}, {15959989u, 2}, {16040021u, 2}, 
	{16128247u, 2}, {16192567u, 2}, {16402499u, 2}, {16524161u, 2}, 
	{16687189u, 2}, {16777207u, 2}, {16966097u, 2}, {17065157u, 2},
	{17189267u, 2}, {17288963u, 2}, {17547577u, 2}, {17757787u, 2}, 
	{17842151u, 2}, {17943671u, 2}, {18045479u, 2}, {18147599u, 2}, 
	{18249983u, 2}, {18369787u, 2}, {18593119u, 2}, {18818243u, 2}, 
	{18948593u, 2}, {19079399u, 2}, {19307227u, 2}, {19492189u, 2}, 
	{19642543u, 2}, {19793597u, 2}, {19891591u, 2}, {20088323u, 2},
	{20249951u, 2}, {20385221u, 2}, {20439437u, 2}, {20684303u, 2}, 
	{20830087u, 2}, {21040553u, 2}, {21159991u, 2}, {21427577u, 2}, 
	{21538877u, 2}, {21622499u, 2}, {21715591u, 2}, {21864967u, 2}, 
	{22061773u, 2}, {22297283u, 2}, {22382357u, 2}, {22610009u, 2}, 
	{22896221u, 2}, {22953677u, 2}, {23039999u, 2}, {23184221u, 2},
	{23483491u, 2}, {23755867u, 2}, {23970767u, 2}, {24147371u, 2}, 
	{24324623u, 2}, {24403591u, 2}, {24542107u, 2}, {24681023u, 2}, 
	{24800351u, 2}, {24960007u, 2}, {25060027u, 2}, {25160231u, 2}, 
	{25310897u, 2}, {25553009u, 2}, {25796237u, 2}, {25938613u, 2}, 
	{26050807u, 2}, {26173447u, 2}, {26522491u, 2}, {26718557u, 2},
	{26873831u, 2}, {27071173u, 2}, {27342437u, 2}, {27405221u, 2}, 
	{27741253u, 2}, {27878399u, 2}, {28089991u, 2}, {28259807u, 2}, 
	{28515551u, 2}, {28793731u, 2}, {29052091u, 2}, {29192393u, 2}, 
	{29322221u, 2}, {29430589u, 2}, {29582717u, 2}, {29658907u, 2}, 
	{29964667u, 2}, {30041357u, 2}, {30272003u, 2}, {30393133u, 2},
	{30514567u, 2}, {30735767u, 2}, {30980347u, 2}, {31102913u, 2}, 
	{31438193u, 2}, {31809599u, 2}, {31911197u, 2}, {31979021u, 2}, 
	{32080871u, 2}, {32330587u, 2}, {32455793u, 2}, {32649787u, 2}, 
	{32936117u, 2}, {33016507u, 2}, {33419957u, 2}, {33593591u, 2}, 
	{33756091u, 2}, {33918967u, 2}, {34117277u, 2}, {34222499u, 2},
	{34327877u, 2}, {34433423u, 2}, {34574399u, 2}, {34809991u, 2}, 
	{35105621u, 2}, {35354867u, 2}, {35808247u, 2}, {36108077u, 2}, 
	{36397073u, 2}, {36542021u, 2}, {36723551u, 2}, {36917767u, 2}, 
	{37088099u, 2}, {37295413u, 2}, {37527851u, 2}, {37675019u, 2}, 
	{37908613u, 2}, {38254081u, 2}, {38452397u, 2}, {38613787u, 2},
	{38750609u, 2}, {39087479u, 2}, {39262747u, 2}, {39363067u, 2}, 
	{39601813u, 2}, {39765611u, 2}, {39942391u, 2}, {40106873u, 2}, 
	{40297079u, 2}, {40449599u, 2}, {40576891u, 2}, {40755431u, 2}, 
	{41075137u, 2}, {41447723u, 2}, {41731519u, 2}, {41951513u, 2}, 
	{42327811u, 2}, {42745363u, 2}, {42928703u, 2}, {43112347u, 2},
	{43217467u, 2}, {43428019u, 2}, {43731733u, 2}, {44155961u, 2}, 
	{44355599u, 2}, {44568967u, 2}, {44756099u, 2}, {44916803u, 2}, 
	{45077771u, 2}, {45360221u, 2}, {45724643u, 2}, {45968399u, 2}, 
	{46131263u, 2}, {46416869u, 2}, {46621583u, 2}, {46744553u, 2}, 
	{47059591u, 2}, {47196899u, 2}, {47485817u, 2}, {47734277u, 2},
	{48052399u, 2}, {48358091u, 2}, {48497287u, 2}, {48636667u, 2}, 
	{48818153u, 2}, {48985997u, 2}, {49224247u, 2}, {49463053u, 2}, 
	{49702451u, 2}, {50041451u, 2}, {50495227u, 2}, {50751367u, 2}, 
	{50979479u, 2}, {51380143u, 2}, {51696091u, 2}, {51969677u, 2}, 
	{52070647u, 2}, {52316273u, 2}, {52490021u, 2}, {52823599u, 2},
	{53319179u, 2}, {53509189u, 2}, {53758223u, 2}, {54022499u, 2}, 
	{54479017u, 2}, {54967387u, 2}, {55383283u, 2}, {55621763u, 2}, 
	{55935437u, 2}, {56070143u, 2}, {56294993u, 2}, {56550391u, 2}, 
	{56746073u, 2}, {56911927u, 2}, {57062891u, 2}, {57259453u, 2}, 
	{57456391u, 2}, {57608099u, 2}, {57836021u, 2}, {58216819u, 2},
	{58461307u, 2}, {58844237u, 2}, {59043847u, 2}, {59213009u, 2}, 
	{59444051u, 2}, {59675621u, 2}, {60015973u, 2}, {60186563u, 2}, 
	{60699677u, 2}, {61152391u, 2}, {61387189u, 2}, {61779551u, 2}, 
	{62015621u, 2}, {62110157u, 2}, {62473207u, 2}, {62773913u, 2}, 
	{62964221u, 2}, {63202499u, 2}, {63648259u, 2}, {64160099u, 2},
	{64448663u, 2}, {64899127u, 2}, {65205589u, 2}, {65415743u, 2}, 
	{65561393u, 2}, {65836987u, 2}, {66178081u, 2}, {66650887u, 2},
#else
	{16294579238595022365u, 15}, {7145393598349078859u, 10},
	{6408001374760705163u, 9}, {690862709424854779u, 8},
	{4312024209383942993u, 8}, {71235931512604841u, 7},
	{192878245514479103u, 7}, {542676746453092519u, 7},
	{1230544604996048471u, 7}, {2618501576975440661u, 7},
	{4771180125133726009u, 7}, {9247077179230889629u, 7},
	{32156968791364271u, 6}, {46627620659631719u, 6}, {64265583549260393u, 6}, 
	{88516552714582021u, 6}, {131585967012906751u, 6}, 
	{182675399263485151u, 6}, {261171077386532413u, 6}, 
	{346060227726080771u, 6}, {448604664249794309u, 6},
	{621993868801161359u, 6}, {813835565706097817u, 6}, 
	{1050677302683430441u, 6}, {1294398862104002783u, 6}, 
	{1615816556891330179u, 6}, {1993926996710486603u, 6}, 
	{2626074105497143999u, 6}, {3280430033433832817u, 6}, 
	{4076110663011485663u, 6}, {4782075577404875363u, 6}, 
	{5906302864496324923u, 6}, {7899206880638488339u, 6}, 
	{9178333502078117453u, 6}, {10680076322389870367u, 6}, 
	{12622882367374918799u, 6}, {14897925470078818423u, 6}, 
	{17264316336968551717u, 6}, {11896905306684389u, 5}, 
	{13580761294555417u, 5}, {15289931661301991u, 5}, 
	{17067874133764579u, 5}, {19008757261780379u, 5}, 
	{21984658219193689u, 5}, {23721541361298551u, 5}, 
	{26539432378378657u, 5}, {30167221680049747u, 5}, 
	{32433198277139683u, 5}, {35517402656173043u, 5}, 
	{39100537712055041u, 5}, {42477532426853543u, 5}, 
	{45618621452253523u, 5}, {52071972962579407u, 5}, 
	{57329264013213233u, 5}, {61692083285823527u, 5}, 
	{66885169838978461u, 5}, {72186879569637319u, 5}, 
	{77103033998665567u, 5}, {82549234838454463u, 5},
	{89609394623390063u, 5}, {100441814079170659u, 5}, 
	{109045745121501371u, 5}, {120230527473437819u, 5}, 
	{131125107904515419u, 5}, {138612182127286823u, 5}, 
	{144712752835963307u, 5}, {152692680370726429u, 5}, 
	{164664356404541573u, 5}, {175376065798883557u, 5}, 
	{187958301132741257u, 5}, {203342285718459187u, 5}, 
	{219115706321995421u, 5}, {235226887496676263u, 5}, 
	{253789253193479219u, 5}, {271717583502831491u, 5}, 
	{293266389497362763u, 5}, {321821627692439603u, 5}, 
	{339856237957830049u, 5}, {362469273063260281u, 5}, 
	{390268963330916339u, 5}, {408848490015359209u, 5}, 
	{429644565036857699u, 5}, {458755816747679897u, 5}, 
	{495450768525623033u, 5}, {523240424009891327u, 5}, 
	{551070603968128061u, 5}, {574205321266688311u, 5}, 
	{606829434176923693u, 5}, {637763212653336997u, 5}, 
	{676538378976146257u, 5}, {710263471119657661u, 5}, 
	{754496879875465343u, 5}, {800075738315885429u, 5}, 
	{845197573085733239u, 5}, {894146362391888161u, 5}, 
	{930105507041885771u, 5}, {985345849616172623u, 5}, 
	{1040222328124784927u, 5}, {1091468150538871153u, 5}, 
	{1150933747479716653u, 5}, {1210604027868555713u, 5}, 
	{1277530693373553361u, 5}, {1350088100087645657u, 5}, 
	{1398676120233167591u, 5}, {1459450139327525269u, 5}, 
	{1555755169940697937u, 5}, {1645735334920325819u, 5}, 
	{1732866357938791147u, 5}, {1815492864312158099u, 5}, 
	{1894564116319543619u, 5}, {1993720023757886939u, 5}, 
	{2103356633892712673u, 5}, {2180099035358103487u, 5}, 
	{2277315690161244011u, 5}, {2390146379836558999u, 5}, 
	{2522126262040806983u, 5}, {2613887383383648311u, 5}, 
	{2795412145600606001u, 5}, {2919958494381348367u, 5}, 
	{3012266980379247553u, 5}, {3119360766859522543u, 5}, 
	{3216618305468232557u, 5}, {3385071039891962579u, 5}, 
	{3509427475807939163u, 5}, {3700008514672760651u, 5}, 
	{3873423910591589033u, 5}, {4050200067084600439u, 5}, 
	{4233429923647833421u, 5}, {4472862244562412787u, 5}, 
	{4638587045132438407u, 5}, {4765110805097342489u, 5}, 
	{4951886102290887619u, 5}, {5103665412856065733u, 5}, 
	{5306636943410213377u, 5}, {5581202660702121667u, 5}, 
	{5774946339890457283u, 5}, {5948565823654343479u, 5}, 
	{6175776426345604697u, 5}, {6454381412132929663u, 5}, 
	{6685489970462824483u, 5}, {6864273057227912189u, 5}, 
	{7020466399135670969u, 5}, {7326535375987923521u, 5}, 
	{7795297680723533551u, 5}, {8101368883577379127u, 5}, 
	{8353548973662446233u, 5}, {8642941459163335097u, 5}, 
	{8989536585105548947u, 5}, {9281597047973093449u, 5}, 
	{9623989560555822323u, 5}, {9884958654427267811u, 5}, 
	{10161260209201654649u, 5}, {10427299413974952277u, 5}, 
	{10759022378261015069u, 5}, {11290266633494854903u, 5}, 
	{11852839900193264543u, 5}, {12209591760462366097u, 5}, 
	{12604874462407914499u, 5}, {13152204116524238149u, 5}, 
	{13487108616207513373u, 5}, {13935742926215786057u, 5}, 
	{14426307807825845411u, 5}, {14869398407236523377u, 5}, 
	{15287602532539390847u, 5}, {15824557271701228177u, 5}, 
	{16348641675671844607u, 5}, {16684838939207505557u, 5}, 
	{17148166373867218913u, 5}, {17832011695956938489u, 5}, 
	{2587278248197793u, 4}, {2656152548121013u, 4}, {2706094705771019u, 4}, 
	{2746082268411733u, 4}, {2816510930505221u, 4}, {2876558914811147u, 4}, 
	{2943092641403483u, 4}, {3044274349991521u, 4}, {3111227620115431u, 4}, 
	{3156468307693999u, 4}, {3209012615864543u, 4}, {3247559087000957u, 4}, 
	{3289921520014123u, 4}, {3331823223534079u, 4}, {3403431328122433u, 4}, 
	{3474390126259739u, 4}, {3519861126859459u, 4}, {3581490458694233u, 4}, 
	{3653304933840151u, 4}, {3753973384118899u, 4}, {3831297220366171u, 4}, 
	{3880220695063499u, 4}, {3952510531166773u, 4}, {4022729025799241u, 4}, 
	{4135032598497637u, 4}, {4231785801620803u, 4}, {4288747235209999u, 4}, 
	{4356965458481947u, 4}, {66650887u, 2},
#endif
};

void priBaseMod(word mods[], const word a[], size_t n, size_t count)
{
	size_t i, j;
	// pre
	ASSERT(wwIsValid(a, n));
	ASSERT(count <= priBaseSize());
	ASSERT(wwIsValid(mods, count));
	// пробегаем произведения простых из факторной базы
	for (i = j = 0; i < count && j < COUNT_OF(_prods); ++j)
	{
		size_t num = _prods[j].num;
		// t <- a mod _base[i] * ... * _base[i + num - 1]
		word t = zzModW(a, n, _prods[j].prod);
		// mods[i] <- t mod _base[i]
		while (num-- && i < count)
			mods[i] = t % _base[i], ++i;
	}
	// пробегаем оставшиеся простые из факторной базы
	for (; i < count; ++i)
		mods[i] = zzModW(a, n, _base[i]);
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
		// при необходимости скорректировать факторную базу
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
	if (wwIsW(t, n, 1))
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
			if (wwIsW(t, n, 1))
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

Применяется тест Рабина -- Миллера со специально подобранными основаниями.
Успешное завершение теста на всех основаниях из списка _base16 гарантирует
простоту чисел вплоть до 1373653 [1], из списка _base32 --- вплоть
до 4759123141 [2], из списка _base64 --- для всех 64-разрядных чисел
(Sinclair, unpublished, see [3] and [4]).

[1]	Pomerance C., Selfridge J., Wagstaff S. Jr. The pseudoprimes to 25 * 10^9.
	Mathematics of Computation. 35(151): 1003–1026.
[2]	Jaeschke G. On strong pseudoprimes to several bases. Mathematics
	of Computation. 61(204): 915-925.
[3]	Forisek M., Jancina, J. Fast Primality Testing for Integers That Fit into
	a Machine Word. 2015. https://ceur-ws.org/Vol-1326/020-Forisek.pdf.
[4]	 Izykowski, W.: The best known SPRP bases sets. 2024-02-28.
	https://miller-rabin.appspot.com/.
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
		for (i = 1; i < s; ++i)
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
		if (i == s)
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

В начале функции проверяется, что a >= 49. Поэтому основание base будет 
совпадать с \pm R \mod a с вероятностью p <= 2/(49 - 1) = 1/24 и число попыток 
генерации можно ограничить величиной 
B_PER_IMPOSSLIBLE / log_2(24) <= B_PER_IMPOSSLIBLE / 4.5.
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
	if (n == 1 && a[0] < 49)
		return a[0] != 1 && (a[0] == 3 || a[0] % 3) && (a[0] == 5 || a[0] % 5);
	// подготовить генератор
	prngCOMBOStart(combo_state, utilNonce32());
	// создать кольцо
	wwTo(base, O_OF_W(n), a);
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
		i = 0;
		do
			if (i++ * 45 > B_PER_IMPOSSIBLE * 10 || 
				!zzRandNZMod(base, a, n, prngCOMBOStepR, combo_state))
			{
				s = m = 0;
				return FALSE;
			}
		while (wwEq(base, qr->unity, n) || zzIsSumEq(a, base, qr->unity, n));
		// base <- base^r \mod a
		qrPower(base, base, r, m, qr, stack);
		// base == \pm one => тест пройден
		if (wwEq(base, qr->unity, n) || zzIsSumEq(a, base, qr->unity, n))
			continue;
		// base^{2^i} \equiv -1 \mod a?
		for (i = 1; i < s; ++i)
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
		if (i == s)
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
	wwTo(p, no, p);
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
		// при необходимости скорректировать факторную базу
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

\remark Если l <= 2 * k, где k = bitlen(q), то условие 2r < 4q + 1 будет
выполнено:
2r = (p - 1) / q < 2^l / (2^{k - 1}} = 2^{l - k + 1} <= 2^{k + 2} < 4q.

Построение p:
1) t <-R {2^{l - 2},..., 2^{l - 1} - 1};
2) r <- ceil(t / q);
3) p <- 2qr + 1;
4) если bitlen(p) != l, то вернуться к шагу 1.

Если требуется, чтобы p - 1 кроме q делилось на число a, то построить p можно
следующим образом: 
1) t <-R {2^{l - 2},..., 2^{l - 1} - 1};
2) r <- ceil(t / qa);
3) p <- 2qar + 1;
4) если bitlen(p) != l, то вернуться к шагу 1.

\remark Если t укладывается в nt слов, q занимает n слов, a занимает m слов, 
то r на шаге 2) укладывается в nt - n - m + 3 слов и не обязательно в меньшее
число слов. Действительно, максимальное r' получается  при
	t = B^nt - 1, q = B^{n - 1} + 1, a = B^{m - 1}
и достигает величины
	r = B^{nt - n - m + 2}
при n близких к nt.
В самом деле, при таких n и 
	r' = B^{nt - n - m + 2} - 1
величина
	qar' = B^nt - B^{n + m - 2} + B^{nt - n + 1} - B^{m - 1} < B^nt - 1 = t,
т. е.
	r' < ceil(t / qa).
*******************************************************************************
*/

bool_t priExtendPrime2(word p[], size_t l, const word q[], size_t n,
	const word a[], size_t m, size_t trials, size_t base_count, gen_i rng, 
	void* rng_state, void* stack)
{
	const size_t np = W_OF_B(l);
	const size_t npo = O_OF_B(l);
	size_t i;
	size_t nqa;
	// переменные в stack
	word* qa;		/* [n + m] */
	word* t;		/* [np + 2] */
	word* r;		/* [np - n - m + 3] */
	word* four;		/* [np] */
	word* mods;		/* base_count */
	word* mods1;	/* base_count */
	qr_o* qr;
	// pre
	ASSERT(wwIsDisjoint2(p, np, q, n));
	ASSERT(wwIsValid(a, m));
	ASSERT(zzIsOdd(q, n) && wwCmpW(q, n, 3) >= 0);
	ASSERT(n > 0 && q[n - 1] != 0 && m > 0 && a[m - 1] != 0);
	ASSERT(wwBitSize(q, n) + wwBitSize(a, m) <= l);
	ASSERT(l <= 2 * wwBitSize(q, n));
	ASSERT(base_count <= priBaseSize());
	ASSERT(rng != 0);
	// раскладка stack
	qa = (word*)stack;
	t = qa + n + m;
	r = t + np + 2;
	four = r + np - n - m + 3;
	mods = four + np;
	mods1 = mods + base_count;
	qr = (qr_o*)(mods1 + base_count);
	stack = (octet*)qr + zmCreate_keep(npo);
	// малое p?
	if (l < B_PER_W)
		// при необходимости уменьшить факторную базу
		while (base_count > 0 && 
			priBasePrime(base_count - 1) > WORD_BIT_POS(l - 1))
			--base_count;
	// qa <- q * a
	zzMul(qa, q, n, a, m, stack); 
	ASSERT(wwBitSize(qa, n + m) + 1 <= l);
	nqa = wwWordSize(qa, n + m);
	// попытки
	while (trials == SIZE_MAX || trials--)
	{
		// t <-R [2^{l - 2}, 2^{l - 1})
		rng(t, npo, rng_state);
		wwFrom(t, t, npo);
		wwTrimHi(t, np, l - 2);
		wwSetBit(t, l - 2, 1);
		// r <- ceil(t / qa)
		zzDiv(r, t, t, np, qa, nqa, stack);
		r[np - nqa + 1] = wwIsZero(t, nqa) ? 0 : zzAddW2(r, np - nqa + 1, 1);
		// t <- qa * r
		zzMul(t, qa, nqa, r, np - nqa + 2, stack);
		if (wwBitSize(t, np + 2) > l - 1)
			continue;
		// p <- 2 * t + 1
		wwCopy(p, t, np);
		wwShHi(p, np, 1);
		++p[0];
		ASSERT(wwBitSize(p, np) == l);
		// рассчитать вычеты p, 2qa по малым модулям
		priBaseMod(mods, p, np, base_count);
		priBaseMod(mods1, qa, nqa, base_count);
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
				wwTo(t, npo, p);
				zmCreate(qr, (octet*)t, npo, stack);
				// four <- 4 [в кольце qr]
				qrAdd(four, qr->unity, qr->unity, qr);
				qrAdd(four, four, four, qr);
				// (4^r)^a \mod p != 1?
				qrPower(t, four, r, np - nqa + 1, qr, stack);
				qrPower(t, t, a, m, qr, stack);
				if (qrCmp(t, qr->unity, qr) != 0)
				{
					// ((4^r)^a)^q \mod p == 1?
					qrPower(t, t, q, n, qr, stack);
					if (qrCmp(t, qr->unity, qr) == 0)
						return TRUE;
				}
			}
			// p <- p + 2 * qa, переполнение?
			if (zzAddW2(p + nqa, np - nqa, zzAdd2(p, qa, nqa)) ||
				zzAddW2(p + nqa, np - nqa, zzAdd2(p, qa, nqa)) ||
				wwBitSize(p, np) > l)
				break;
			// r <- r + 1, без переполнения
			VERIFY(zzAddW2(r, np - nqa + 1, 1) == 0);
			// пересчитать mods
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

size_t priExtendPrime2_deep(size_t l, size_t n, size_t m, size_t base_count)
{
	const size_t np = W_OF_B(l);
	const size_t npo = O_OF_B(l);
	const size_t qr_deep = zmCreate_deep(npo);
	ASSERT(np >= n);
	ASSERT(np + 3 >= n + m);
	return O_OF_W(3 * np + 5 + 2 * base_count) + 
		zmCreate_keep(npo) +
		utilMax(5,
			zzMul_deep(n, m),
			zzDiv_deep(np, n + m),
			zzMul_deep(n + m, np - n - m + 3),
			qr_deep,
			qrPower_deep(np, np, qr_deep));
}

bool_t priExtendPrime(word p[], size_t l, const word q[], size_t n,
	size_t trials, size_t base_count, gen_i rng, void* rng_state, void* stack)
{
	word* a;
	// pre
	ASSERT(memIsValid(stack, O_OF_W(1)));
	// a <- 1
	a = (word*)stack;
	a[0] = 1;
	// расширить
	return priExtendPrime2(p, l, q, n, a, 1, trials, base_count, 
		rng, rng_state, a + 1);
}

size_t priExtendPrime_deep(size_t l, size_t n, size_t base_count)
{
	return  O_OF_W(1) + priExtendPrime2_deep(l, n, 1, base_count);
}
