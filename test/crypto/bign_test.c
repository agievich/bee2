/*
*******************************************************************************
\file bign_test.c
\brief Tests for STB 34.101.45 (bign)
\project bee2/test
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2012.08.27
\version 2018.08.31
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include <bee2/core/mem.h>
#include <bee2/core/hex.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include <bee2/math/ww.h>
#include <bee2/math/zz.h>
#include <bee2/crypto/bign.h>
#include <bee2/crypto/belt.h>
#include <bee2/crypto/brng.h>

/*
*******************************************************************************
brngCTRX: Расширение brngCTR

-#	При инициализации можно передать дополнительное слово X.
*******************************************************************************
*/
typedef struct
{
	const octet* X;		/*< дополнительное слово */
	size_t count;		/*< размер X в октетах */
	size_t offset;		/*< текущее смещение в X */
	octet state_ex[];	/*< состояние brngCTR */
} brng_ctrx_st;

static size_t brngCTRX_keep()
{
	return sizeof(brng_ctrx_st) + brngCTR_keep();
}

static void brngCTRXStart(const octet theta[32], const octet iv[32],
	const void* X, size_t count, void* state)
{
	brng_ctrx_st* s = (brng_ctrx_st*)state;
	ASSERT(memIsValid(s, sizeof(brng_ctrx_st)));
	ASSERT(count > 0);
	ASSERT(memIsValid(s->state_ex, brngCTR_keep()));
	brngCTRStart(s->state_ex, theta, iv);
	s->X = (const octet*)X;
	s->count = count;
	s->offset = 0;
}

static void brngCTRXStepR(void* buf, size_t count, void* stack)
{
	brng_ctrx_st* s = (brng_ctrx_st*)stack;
	octet* buf1 = (octet*)buf;
	size_t count1 = count;
	ASSERT(memIsValid(s, sizeof(brng_ctrx_st)));
	// заполнить buf
	while (count1)
		if (count1 < s->count - s->offset)
		{
			memCopy(buf1, s->X + s->offset, count1);
			s->offset += count1;
			count1 = 0;
		}
		else
		{
			memCopy(buf1, s->X + s->offset, s->count - s->offset);
			buf1 += s->count - s->offset;
			count1 -= s->count - s->offset;
			s->offset = 0;
		}
	// сгенерировать
	brngCTRStepR(buf, count, s->state_ex);
}

/*
*******************************************************************************
Самотестирование

-#	Выполняются тесты из приложения  к СТБ 34.101.45.
-#	Номера тестов соответствуют номерам таблиц приложения.
-#	Дополнительные тесты покрывают ошибки, выявленные в результате испытаний.
*******************************************************************************
*/

bool_t bignTest()
{
	bign_params params[1];
	octet oid_der[128];
	size_t oid_len;
	octet privkey[64];
	octet pubkey[128];
	octet id_privkey[64];
	octet id_pubkey[128];
	octet hash[64];
	octet id_hash[64];
	octet sig[64 + 32];
	octet id_sig[64 + 32 + 128];
	octet brng_state[1024];
	octet zz_stack[512];
	octet token[80];
	word q[W_OF_O(32)];
	word d[W_OF_O(32)];
	word H[W_OF_O(32)];
	word k[W_OF_O(32)];
	word S0[W_OF_O(32)];
	word S1[W_OF_O(32)];
	char pwd[] = "B194BAC80A08F53B";
	size_t iter = 10000;
	octet theta[32];
	// создать стек
	ASSERT(sizeof(brng_state) >= brngCTRX_keep());
	ASSERT(sizeof(zz_stack) >= zzMulMod_deep(W_OF_O(32)));
	// проверить таблицы Б.1, Б.2, Б.3
	if (bignStdParams(params, "1.2.112.0.2.0.34.101.45.3.3") != ERR_OK ||
		bignValParams(params) != ERR_OK)
		return FALSE;
	if (bignStdParams(params, "1.2.112.0.2.0.34.101.45.3.2") != ERR_OK ||
		bignValParams(params) != ERR_OK)
		return FALSE;
	if (bignStdParams(params, "1.2.112.0.2.0.34.101.45.3.1") != ERR_OK ||
		bignValParams(params) != ERR_OK)
		return FALSE;
	// идентификатор объекта
	oid_len = sizeof(oid_der);
	if (bignOidToDER(oid_der, &oid_len, "1.2.112.0.2.0.34.101.31.81") 
		!= ERR_OK || oid_len != 11)
		return FALSE;
	// инициализировать ГПСЧ
	brngCTRXStart(beltH() + 128, beltH() + 128 + 64,
		beltH(), 8 * 32, brng_state);
	// тест Г.1
	if (bignGenKeypair(privkey, pubkey, params, brngCTRXStepR, brng_state) !=
		ERR_OK)
		return FALSE;
	if (!hexEq(privkey,
		"1F66B5B84B7339674533F0329C74F218"
		"34281FED0732429E0C79235FC273E269") || 
		!hexEq(pubkey,
		"BD1A5650179D79E03FCEE49D4C2BD5DD"
		"F54CE46D0CF11E4FF87BF7A890857FD0"
		"7AC6A60361E8C8173491686D461B2826"
		"190C2EDA5909054A9AB84D2AB9D99A90"))
		return FALSE;
	if (bignValPubkey(params, pubkey) != ERR_OK)
		return FALSE;
	if (bignCalcPubkey(pubkey, params, privkey) != ERR_OK)
		return FALSE;
	if (!hexEq(pubkey,
		"BD1A5650179D79E03FCEE49D4C2BD5DD"
		"F54CE46D0CF11E4FF87BF7A890857FD0"
		"7AC6A60361E8C8173491686D461B2826"
		"190C2EDA5909054A9AB84D2AB9D99A90"))
		return FALSE;
	memSetZero(pubkey, 32);
	memCopy(pubkey + 32, params->yG, 32);
	if (bignDH(pubkey, params, privkey, pubkey, 64) != ERR_OK)
		return FALSE;
	if (!hexEq(pubkey,
		"BD1A5650179D79E03FCEE49D4C2BD5DD"
		"F54CE46D0CF11E4FF87BF7A890857FD0"
		"7AC6A60361E8C8173491686D461B2826"
		"190C2EDA5909054A9AB84D2AB9D99A90"))
		return FALSE;
	// тест Г.2
	if (beltHash(hash, beltH(), 13) != ERR_OK)
		return FALSE;
	if (bignSign(sig, params, oid_der, oid_len, hash, privkey, brngCTRXStepR, 
		brng_state) != ERR_OK)
		return FALSE;
	if (!hexEq(sig, 
		"E36B7F0377AE4C524027C387FADF1B20"
		"CE72F1530B71F2B5FD3A8C584FE2E1AE"
		"D20082E30C8AF65011F4FB54649DFD3D"))
		return FALSE;
	if (bignVerify(params, oid_der, oid_len, hash, sig, pubkey) != ERR_OK)
		return FALSE;
	sig[0] ^= 1;
	if (bignVerify(params, oid_der, oid_len, hash, sig, pubkey) == ERR_OK)
		return FALSE;
	sig[0] ^= 1, pubkey[0] ^= 1;
	if (bignVerify(params, oid_der, oid_len, hash, sig, pubkey) == ERR_OK)
		return FALSE;
	pubkey[0] ^= 1;
	// тест Г.8
	memCopy(id_hash, hash, 32);
	if (bignIdExtract(id_privkey, id_pubkey, params, oid_der, oid_len, 
		id_hash, sig, pubkey) != ERR_OK)
		return FALSE;
	if (!hexEq(id_pubkey,
		"CCEEF1A313A406649D15DA0A851D486A"
		"695B641B20611776252FFDCE39C71060"
		"7C9EA1F33C23D20DFCB8485A88BE6523"
		"A28ECC3215B47FA289D6C9BE1CE837C0") ||
		!hexEq(id_privkey,
		"79628979DF369BEB94DEF3299476AED4"
		"14F39148AA69E31A7397E8AA70578AB3"))
		return FALSE;
	// тест Г.4
	if (bignKeyWrap(token, params, beltH(), 18, beltH() + 32, pubkey,
		brngCTRXStepR, brng_state) != ERR_OK)
		return FALSE;
	if (!hexEq(token,
		"9B4EA669DABDF100A7D4B6E6EB76EE52"
		"51912531F426750AAC8A9DBB51C54D8D"
		"EB9289B50A46952D0531861E45A8814B"
		"008FDC65DE9FF1FA2A1F16B6A280E957"
		"A814"))
		return FALSE;
	if (bignKeyUnwrap(token, params, token, 18 + 16 + 32, beltH() + 32,
		privkey) != ERR_OK)
		return FALSE;
	if (!memEq(token, beltH(), 18))
		return FALSE;
	// тест Г.3
	if (beltHash(hash, beltH(), 48) != ERR_OK)
		return FALSE;
	if (bignSign(sig, params, oid_der, oid_len, hash, privkey, brngCTRXStepR, 
		brng_state) != ERR_OK)
		return FALSE;
	if (!hexEq(sig, 
		"47A63C8B9C936E94B5FAB3D9CBD78366"
		"290F3210E163EEC8DB4E921E8479D413"
		"8F112CC23E6DCE65EC5FF21DF4231C28"))
		return FALSE;
	if (bignVerify(params, oid_der, oid_len, hash, sig, pubkey) != ERR_OK)
		return FALSE;
	// тест Г.5
	bignKeyWrap(token, params, beltH(), 32, beltH() + 64,
		pubkey, brngCTRXStepR, brng_state);
	if (!hexEq(token,
		"4856093A0F6C13015FC8E15F1B23A762"
		"02D2F4BA6E5EC52B78658477F6486DE6"
		"87AFAEEA0EF7BC1326A7DCE7A10BA10E"
		"3F91C0126044B22267BF30BD6F1DA29E"
		"0647CF39C1D59A56BB0194E0F4F8A2BB"))
		return FALSE;
	bignKeyUnwrap(token, params, token, 32 + 16 + 32, beltH() + 64,
		privkey);
	if (!memEq(token, beltH(), 32))
		return FALSE;
	// тест Г.6
	if (beltHash(hash, beltH(), 13) != ERR_OK)
		return FALSE;
	if (bignSign2(sig, params, oid_der, oid_len, hash, privkey, 0, 0) 
		!= ERR_OK)
		return FALSE;
	wwFrom(q, params->q, 32);
	wwFrom(d, privkey, 32);
	wwFrom(S0, sig, 16);
	wwFrom(S1, sig + 16, 32);
	wwFrom(H, hash, 32);
	S0[W_OF_O(16)] = 1;
	wwSetZero(S0 + W_OF_O(16) + 1, W_OF_O(16) - 1);
	zzMulMod(k, S0, d, q, W_OF_O(32), zz_stack);
	zzAddMod(k, S1, k, q, W_OF_O(32));
	zzAddMod(k, k, H, q, W_OF_O(32));
	wwTo(k, 32, k);
	if (!hexEq(k,
		"829614D8411DBBC4E1F2471A40045864"
		"40FD8C9553FAB6A1A45CE417AE97111E"))
		return FALSE;
	// тест Г.7
	if (beltHash(hash, beltH(), 48) != ERR_OK)
		return FALSE;
	if (bignSign2(sig, params, oid_der, oid_len, hash, privkey, 
		beltH() + 128 + 64, 23) != ERR_OK)
		return FALSE;
	wwFrom(q, params->q, 32);
	wwFrom(d, privkey, 32);
	wwFrom(S0, sig, 16);
	wwFrom(S1, sig + 16, 32);
	wwFrom(H, hash, 32);
	S0[W_OF_O(16)] = 1;
	wwSetZero(S0 + W_OF_O(16) + 1, W_OF_O(16) - 1);
	zzMulMod(k, S0, d, q, W_OF_O(32), zz_stack);
	zzAddMod(k, S1, k, q, W_OF_O(32));
	zzAddMod(k, k, H, q, W_OF_O(32));
	wwTo(k, 32, k);
	if (!hexEq(k,
		"7ADC8713283EBFA547A2AD9CDFB245AE"
		"0F7B968DF0F91CB785D1F932A3583107"))
		return FALSE;
	// тест Г.9
	if (beltHash(hash, beltH() + 32, 16) != ERR_OK)
		return FALSE;
	if (bignIdSign(id_sig, params, oid_der, oid_len, id_hash, hash, id_privkey,
		brngCTRXStepR, brng_state) != ERR_OK)
		return FALSE;
	if (!hexEq(id_sig,
		"1697FE6A073D3B28C9D0DD832A169D7B"
		"8D342FDC47BC8AAEB6226448956E22D6"
		"CC73B62CB21B66E5C8DE0A3E234FB0C6"))
		return FALSE;
	if (bignIdVerify(params, oid_der, oid_len, id_hash, hash, id_sig, 
		id_pubkey, pubkey) != ERR_OK)
		return FALSE;
	id_sig[0] ^= 1;
	if (bignIdVerify(params, oid_der, oid_len, id_hash, hash, id_sig, 
		id_pubkey, pubkey) == ERR_OK)
		return FALSE;
	id_sig[0] ^= 1, id_pubkey[0] ^= 1;
	if (bignIdVerify(params, oid_der, oid_len, id_hash, hash, id_sig, 
		id_pubkey, pubkey) == ERR_OK)
		return FALSE;
	id_pubkey[0] ^= 1;
	// тест Г.10
	if (beltHash(hash, beltH() + 32, 23) != ERR_OK)
		return FALSE;
	if (bignIdSign(id_sig, params, oid_der, oid_len, id_hash, hash, id_privkey,
		brngCTRXStepR, brng_state) != ERR_OK)
		return FALSE;
	if (!hexEq(id_sig,
		"31CBA14FC2D79AFCD8F50E29F993FC2C"
		"B270BD0A79D534B3B120791400C8BB18"
		"50AD6D3C78047FCB46F18608AC7006AA"))
		return FALSE;
	if (bignIdVerify(params, oid_der, oid_len, id_hash, hash, id_sig, 
		id_pubkey, pubkey) != ERR_OK)
		return FALSE;
	id_sig[0] ^= 1;
	if (bignIdVerify(params, oid_der, oid_len, id_hash, hash, id_sig, 
		id_pubkey, pubkey) == ERR_OK)
		return FALSE;
	id_sig[0] ^= 1, id_pubkey[0] ^= 1;
	if (bignIdVerify(params, oid_der, oid_len, id_hash, hash, id_sig, 
		id_pubkey, pubkey) == ERR_OK)
		return FALSE;
	id_pubkey[0] ^= 1;
	// дополнительный тест для проверки bignIdSign2
	if (bignIdSign2(id_sig, params, oid_der, oid_len, id_hash, hash, 
		id_privkey, 0, 0) != ERR_OK ||
		bignIdVerify(params, oid_der, oid_len, id_hash, hash, id_sig, 
		id_pubkey, pubkey) != ERR_OK)
		return FALSE;
	id_sig[0] ^= 1;
	if (bignIdVerify(params, oid_der, oid_len, id_hash, hash, id_sig, 
		id_pubkey, pubkey) == ERR_OK)
		return FALSE;
	id_sig[0] ^= 1, id_pubkey[0] ^= 1;
	if (bignIdVerify(params, oid_der, oid_len, id_hash, hash, id_sig, 
		id_pubkey, pubkey) == ERR_OK)
		return FALSE;
	id_pubkey[0] ^= 1;
	// тест E.5
	beltPBKDF2(theta, (const octet*)pwd, strLen(pwd), iter, 
		beltH() + 128 + 64, 8);
	if (!hexEq(theta,
		"3D331BBBB1FBBB40E4BF22F6CB9A689E"
		"F13A77DC09ECF93291BFE42439A72E7D"))
		return FALSE;
	beltKWPWrap(token, privkey, 32, 0, theta, 32);
	if (!hexEq(token,
		"4EA289D5F718087DD8EDB305BA1CE898"
		"0E5EC3E0B56C8BF9D5C3E909CF4C14F0"
		"7B8204E67841A165E924945CD07F37E7"))
		return FALSE;
	// дополнительный тест: транспорт ключа из 16 октетов
	if (bignKeyWrap(token, params, beltH(), 16, beltH() + 64,
		pubkey, brngCTRXStepR, brng_state) != ERR_OK ||
		bignKeyUnwrap(token, params, token, 32 + 16 + 16, beltH() + 64,
		privkey) != ERR_OK ||
		!memEq(token, beltH(), 16))
		return FALSE;
	// дополнительные тесты (vs OpenSSL)
	hexTo(theta, "49FEFF8076CD9480");
	beltPBKDF2(theta, (const octet*)"zed", 3, 2048, theta, 8);
	if (!hexEq(theta,
		"7249B4785FE68B1586D189A23E3842E4"
		"8705C080A3248D8F0E8C3D63A93B2670"))
		return FALSE;
	hexTo(theta, "C65017E4F108BCF0");
	beltPBKDF2(theta, (const octet*)"zed", 3, 10000, theta, 8);
	if (!hexEq(theta,
		"E48329259BC1211DDAC2EF1DADFFC993"
		"2702A92F1DD66C14A9BA1D7300C8713C"))
		return FALSE;
	// все нормально
	return TRUE;
}
