/*
*******************************************************************************
\file dstu-test.c
\brief Tests for DSTU 4145-2002 (Ukraine)
\project bee2/test
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2012.03.01
\version 2015.10.29
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include <bee2/core/mem.h>
#include <bee2/core/hex.h>
#include <bee2/core/prng.h>
#include <bee2/core/util.h>
#include <bee2/crypto/dstu.h>


/*
*******************************************************************************
COMBO-генератор
*******************************************************************************
*/
#define combo_rng prngCOMBOStepG

/*
*******************************************************************************
Самотестирование

-#	Выполняются тесты из приложения Б к ДСТУ 4145-2002.
-#	Дополнительно проверяются кривые в полиномиальном базисе, заданные 
	в приложении Г.

\warning Ошибка в примере Б.1: x-координата открытого ключа должна 
заканчиваться на ...BDC2DA (в примере BD2DA)
*******************************************************************************
*/

bool_t dstuTest()
{
	dstu_params params[1];
	octet buf[DSTU_SIZE];
	octet privkey[DSTU_SIZE];
	octet pubkey[2 * DSTU_SIZE];
	octet hash[32];
	octet sig[2 * DSTU_SIZE];
	size_t ld;
	octet state[512];
	// тест Б.1 [загрузка параметров]
	if (dstuStdParams(params, "1.2.804.2.1.1.1.1.3.1.1.1.2.0") != ERR_OK ||
		dstuValParams(params) != ERR_OK)
		return FALSE;
	// тест Б.1 [генерация ключей]
	hexToRev(buf, 
		"0183F60FDF7951FF47D67193F8D073790C1C"
		"9B5A3E");
	ASSERT(sizeof(state) >= prngEcho_keep());
	prngEchoStart(state, buf, memNonZeroSize(params->n, O_OF_B(163)));
	if (dstuGenKeypair(privkey, pubkey, params, prngEchoStepG, 
			state) != ERR_OK ||
		!hexEqRev(privkey, 
			"0183F60FDF7951FF47D67193F8D07379"
			"0C1C9B5A3E") ||
		!hexEqRev(pubkey, 
			"057DE7FDE023FF929CB6AC785CE4B79C"
			"F64ABDC2DA") ||
		!hexEqRev(pubkey + O_OF_B(163), 
			"03E85444324BCF06AD85ABF6AD7B5F34"
			"770532B9AA"))
		return FALSE;
	// тест Б.1 [выработка ЭЦП]
	ld = 512;
	hexToRev(hash, 
		"003A2EB95B7180166DDF73532EEB76ED"
		"AEF52247FF");
	hexToRev(buf, 
		"01025E40BD97DB012B7A1D79DE8E1293"
		"2D247F61C6");
	if (dstuSign(sig, params, ld, hash, 21, privkey, prngEchoStepG, 
			state) != ERR_OK ||
		!hexEqRev(sig, 
			"000000000000000000000002100D8695"
			"7331832B8E8C230F5BD6A332B3615ACA"
			"00000000000000000000000274EA2C0C"
			"AA014A0D80A424F59ADE7A93068D08A7"))
		return FALSE;
	// тест Б.1 [проверка ЭЦП]
	if (dstuVerify(params, ld, hash, 21, sig, pubkey) != ERR_OK)
		return FALSE;
	sig[0] ^= 1;
	if (dstuVerify(params, ld, hash, 21, sig, pubkey) == ERR_OK)
		return FALSE;
	// создать генератор COMBO
	ASSERT(sizeof(state) >= prngCOMBO_keep());
	prngCOMBOStart(state, utilNonce32());
	// максимальная длина ЭЦП
	ld = B_OF_O(2 * DSTU_SIZE);
	// сгенерировать hash
	combo_rng(hash, 32, state);
	// проверить кривую dstu_163pb
	if (dstuGenPoint(params->P, params, prngCOMBOStepG, state) != ERR_OK ||
		dstuCompressPoint(pubkey, params, params->P) != ERR_OK ||
		dstuRecoverPoint(pubkey, params, pubkey) != ERR_OK ||
		!memEq(params->P, pubkey, 2 * O_OF_B(163)) || 
		dstuGenKeypair(privkey, pubkey, params, prngCOMBOStepG, 
			state) != ERR_OK ||
		dstuSign(sig, params, ld, hash, 32, privkey, prngCOMBOStepG, 
			state) != ERR_OK ||
		dstuVerify(params, ld, hash, 32, sig, pubkey) != ERR_OK ||
		(sig[0] ^= 1, dstuVerify(params, ld, hash, 32, sig, pubkey) == ERR_OK))
		return FALSE;
	// проверить кривую dstu_167pb
	if (dstuStdParams(params, "1.2.804.2.1.1.1.1.3.1.1.1.2.1") != ERR_OK ||
		dstuGenPoint(params->P, params, prngCOMBOStepG, state) != ERR_OK ||
		dstuValParams(params) != ERR_OK ||
		dstuCompressPoint(pubkey, params, params->P) != ERR_OK ||
		dstuRecoverPoint(pubkey, params, pubkey) != ERR_OK ||
		!memEq(params->P, pubkey, 2 * O_OF_B(167)) || 
		dstuGenKeypair(privkey, pubkey, params, prngCOMBOStepG, 
			state) != ERR_OK ||
		dstuSign(sig, params, ld, hash, 32, privkey, prngCOMBOStepG, 
			state) != ERR_OK ||
		dstuVerify(params, ld, hash, 32, sig, pubkey) != ERR_OK ||
		(sig[0] ^= 1, dstuVerify(params, ld, hash, 32, sig, pubkey) == ERR_OK))
		return FALSE;
	// проверить кривую dstu_173pb
	if (dstuStdParams(params, "1.2.804.2.1.1.1.1.3.1.1.1.2.2") != ERR_OK ||
		dstuGenPoint(params->P, params, prngCOMBOStepG, state) != ERR_OK ||
		dstuValParams(params) != ERR_OK ||
		dstuCompressPoint(pubkey, params, params->P) != ERR_OK ||
		dstuRecoverPoint(pubkey, params, pubkey) != ERR_OK ||
		!memEq(params->P, pubkey, 2 * O_OF_B(173)) || 
		dstuGenKeypair(privkey, pubkey, params, prngCOMBOStepG, 
			state) != ERR_OK ||
		dstuSign(sig, params, ld, hash, 32, privkey, prngCOMBOStepG, 
			state) != ERR_OK ||
		dstuVerify(params, ld, hash, 32, sig, pubkey) != ERR_OK ||
		(sig[0] ^= 1, dstuVerify(params, ld, hash, 32, sig, pubkey) == ERR_OK))
		return FALSE;
	// проверить кривую dstu_179pb
	if (dstuStdParams(params, "1.2.804.2.1.1.1.1.3.1.1.1.2.3") != ERR_OK ||
		dstuGenPoint(params->P, params, prngCOMBOStepG, state) != ERR_OK ||
		dstuValParams(params) != ERR_OK ||
		dstuCompressPoint(pubkey, params, params->P) != ERR_OK ||
		dstuRecoverPoint(pubkey, params, pubkey) != ERR_OK ||
		!memEq(params->P, pubkey, 2 * O_OF_B(179)) || 
		dstuGenKeypair(privkey, pubkey, params, prngCOMBOStepG, 
			state) != ERR_OK ||
		dstuSign(sig, params, ld, hash, 32, privkey, prngCOMBOStepG, 
			state) != ERR_OK ||
		dstuVerify(params, ld, hash, 32, sig, pubkey) != ERR_OK ||
		(sig[0] ^= 1, dstuVerify(params, ld, hash, 32, sig, pubkey) == ERR_OK))
		return FALSE;
	// проверить кривую dstu_191pb
	if (dstuStdParams(params, "1.2.804.2.1.1.1.1.3.1.1.1.2.4") != ERR_OK ||
		dstuGenPoint(params->P, params, prngCOMBOStepG, state) != ERR_OK ||
		dstuValParams(params) != ERR_OK ||
		dstuCompressPoint(pubkey, params, params->P) != ERR_OK ||
		dstuRecoverPoint(pubkey, params, pubkey) != ERR_OK ||
		!memEq(params->P, pubkey, 2 * O_OF_B(191)) || 
		dstuGenKeypair(privkey, pubkey, params, prngCOMBOStepG, 
			state) != ERR_OK ||
		dstuSign(sig, params, ld, hash, 32, privkey, prngCOMBOStepG, 
			state) != ERR_OK ||
		dstuVerify(params, ld, hash, 32, sig, pubkey) != ERR_OK ||
		(sig[0] ^= 1, dstuVerify(params, ld, hash, 32, sig, pubkey) == ERR_OK))
		return FALSE;
	// проверить кривую dstu_233pb
	if (dstuStdParams(params, "1.2.804.2.1.1.1.1.3.1.1.1.2.5") != ERR_OK ||
		dstuGenPoint(params->P, params, prngCOMBOStepG, state) != ERR_OK ||
		dstuValParams(params) != ERR_OK ||
		dstuCompressPoint(pubkey, params, params->P) != ERR_OK ||
		dstuRecoverPoint(pubkey, params, pubkey) != ERR_OK ||
		!memEq(params->P, pubkey, 2 * O_OF_B(233)) || 
		dstuGenKeypair(privkey, pubkey, params, prngCOMBOStepG, 
			state) != ERR_OK ||
		dstuSign(sig, params, ld, hash, 32, privkey, prngCOMBOStepG, 
			state) != ERR_OK ||
		dstuVerify(params, ld, hash, 32, sig, pubkey) != ERR_OK ||
		(sig[0] ^= 1, dstuVerify(params, ld, hash, 32, sig, pubkey) == ERR_OK))
		return FALSE;
	// проверить кривую dstu_257pb
	if (dstuStdParams(params, "1.2.804.2.1.1.1.1.3.1.1.1.2.6") != ERR_OK ||
		dstuGenPoint(params->P, params, prngCOMBOStepG, state) != ERR_OK ||
		dstuValParams(params) != ERR_OK ||
		dstuCompressPoint(pubkey, params, params->P) != ERR_OK ||
		dstuRecoverPoint(pubkey, params, pubkey) != ERR_OK ||
		!memEq(params->P, pubkey, 2 * O_OF_B(257)) || 
		dstuGenKeypair(privkey, pubkey, params, prngCOMBOStepG, 
			state) != ERR_OK ||
		dstuSign(sig, params, ld, hash, 32, privkey, prngCOMBOStepG, 
			state) != ERR_OK ||
		dstuVerify(params, ld, hash, 32, sig, pubkey) != ERR_OK ||
		(sig[0] ^= 1, dstuVerify(params, ld, hash, 32, sig, pubkey) == ERR_OK))
		return FALSE;
	// проверить кривую dstu_307pb
	if (dstuStdParams(params, "1.2.804.2.1.1.1.1.3.1.1.1.2.7") != ERR_OK ||
		dstuGenPoint(params->P, params, prngCOMBOStepG, state) != ERR_OK ||
		dstuValParams(params) != ERR_OK ||
		dstuCompressPoint(pubkey, params, params->P) != ERR_OK ||
		dstuRecoverPoint(pubkey, params, pubkey) != ERR_OK ||
		!memEq(params->P, pubkey, 2 * O_OF_B(307)) || 
		dstuGenKeypair(privkey, pubkey, params, prngCOMBOStepG, 
			state) != ERR_OK ||
		dstuSign(sig, params, ld, hash, 32, privkey, prngCOMBOStepG, 
			state) != ERR_OK ||
		dstuVerify(params, ld, hash, 32, sig, pubkey) != ERR_OK ||
		(sig[0] ^= 1, dstuVerify(params, ld, hash, 32, sig, pubkey) == ERR_OK))
		return FALSE;
	// проверить кривую dstu_367pb
	if (dstuStdParams(params, "1.2.804.2.1.1.1.1.3.1.1.1.2.8") != ERR_OK ||
		dstuGenPoint(params->P, params, prngCOMBOStepG, state) != ERR_OK ||
		dstuValParams(params) != ERR_OK ||
		dstuCompressPoint(pubkey, params, params->P) != ERR_OK ||
		dstuRecoverPoint(pubkey, params, pubkey) != ERR_OK ||
		!memEq(params->P, pubkey, 2 * O_OF_B(367)) || 
		dstuGenKeypair(privkey, pubkey, params, prngCOMBOStepG, 
			state) != ERR_OK ||
		dstuSign(sig, params, ld, hash, 32, privkey, prngCOMBOStepG, 
			state) != ERR_OK ||
		dstuVerify(params, ld, hash, 32, sig, pubkey) != ERR_OK ||
		(sig[0] ^= 1, dstuVerify(params, ld, hash, 32, sig, pubkey) == ERR_OK))
		return FALSE;
	// проверить кривую dstu_431pb
	if (dstuStdParams(params, "1.2.804.2.1.1.1.1.3.1.1.1.2.9") != ERR_OK ||
		dstuGenPoint(params->P, params, prngCOMBOStepG, state) != ERR_OK ||
		dstuValParams(params) != ERR_OK ||
		dstuCompressPoint(pubkey, params, params->P) != ERR_OK ||
		dstuRecoverPoint(pubkey, params, pubkey) != ERR_OK ||
		!memEq(params->P, pubkey, 2 * O_OF_B(431)) || 
		dstuGenKeypair(privkey, pubkey, params, prngCOMBOStepG, 
			state) != ERR_OK ||
		dstuSign(sig, params, ld, hash, 32, privkey, prngCOMBOStepG, 
			state) != ERR_OK ||
		dstuVerify(params, ld, hash, 32, sig, pubkey) != ERR_OK ||
		(sig[0] ^= 1, dstuVerify(params, ld, hash, 32, sig, pubkey) == ERR_OK))
		return FALSE;
	// все нормально
	return TRUE;
}
