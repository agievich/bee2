/*
*******************************************************************************
\file pfok_test.c
\brief Tests for Draft of RD_RB (pfok)
\project bee2/test
\created 2014.07.08
\version 2022.06.07
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <bee2/core/mem.h>
#include <bee2/core/hex.h>
#include <bee2/core/prng.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include <bee2/math/ww.h>
#include <bee2/math/zz.h>
#include <bee2/crypto/pfok.h>

/*
*******************************************************************************
Функция интерфейса pfok_on_q_i
*******************************************************************************
*/

#include <stdio.h>

static void _on_q(const word q[], size_t n, size_t num)
{
	printf("\rq%u", (unsigned)num);
}

static void _on_q_silent(const word q[], size_t n, size_t num)
{
}

/*
*******************************************************************************
Самотестирование

Реализованы тесты из Методики НИИ ППМИ.

\remark Тесты PFOK.GENP.2-4, реализованные в функции pfokTestStdParams(),
выполняются очень долго и поэтому заблокированы.
*******************************************************************************
*/

bool_t pfokTestTestParams()
{
	pfok_params params[1];
	pfok_params params1[1];
	pfok_seed seed[1];
	// тест PFOK.GENP.1
	if (pfokStdParams(params, seed, "test") != ERR_OK ||
		pfokGenParams(params1, seed, _on_q_silent) != ERR_OK ||
		pfokValParams(params1) != ERR_OK ||
		!memEq(params->p, params1->p, O_OF_B(params->l)) ||
		params->l != params1->l || params->r != params1->r)
		return FALSE;
	// все нормально
	return TRUE;
}

bool_t pfokTestStdParams()
{
	pfok_params params[1];
	pfok_params params1[1];
	pfok_seed seed[1];
	// тест PFOK.GENP.2
	if (pfokStdParams(params, seed, "1.2.112.0.2.0.1176.2.3.3.2") != ERR_OK ||
		pfokValParams(params) != ERR_OK ||
		pfokGenParams(params1, seed, _on_q) != ERR_OK ||
		!memEq(params->p, params1->p, O_OF_B(params->l)) ||
		params->l != params1->l || params->r != params1->r)
		return FALSE;
	// тест PFOK.GENP.3
	if (pfokStdParams(params, seed, "1.2.112.0.2.0.1176.2.3.6.2") != ERR_OK ||
		pfokGenParams(params1, seed, _on_q) != ERR_OK ||
		!memEq(params->p, params1->p, O_OF_B(params->l)) ||
		params->l != params1->l || params->r != params1->r)
		return FALSE;
	// тест PFOK.GENP.4
	if (pfokStdParams(params, seed, "1.2.112.0.2.0.1176.2.3.10.2") != ERR_OK ||
		pfokGenParams(params1, seed, _on_q) != ERR_OK ||
		!memEq(params->p, params1->p, O_OF_B(params->l)) ||
		params->l != params1->l || params->r != params1->r)
		return FALSE;
	// все нормально
	return TRUE;
}

bool_t pfokTest()
{
	pfok_params params[1];
	octet combo_state[128];
	octet ua[O_OF_B(130)];
	octet xa[O_OF_B(130)];
	octet vb[O_OF_B(638)];
	octet yb[O_OF_B(638)];
	octet key[32];
	// подготовить память
	if (sizeof(combo_state) < prngCOMBO_keep())
		return FALSE;
	// тест PFOK.GENP.1
	if (!pfokTestTestParams())
		return FALSE;
	// тест PFOK.GENG.1
	if (pfokStdParams(params, 0, "test") != ERR_OK ||
		pfokValParams(params) != ERR_OK ||
		(params->g[0] += 2) == 0 ||
		pfokValParams(params) == ERR_OK)
		return FALSE;
	// тест PFOK.GENG.2
	if (pfokStdParams(params, 0, "1.2.112.0.2.0.1176.2.3.3.2") != ERR_OK ||
		pfokValParams(params) != ERR_OK ||
		(params->g[0] += 3) == 0 ||
		pfokValParams(params) == ERR_OK)
		return FALSE;
	// тест PFOK.GENG.3
	if (pfokStdParams(params, 0, "1.2.112.0.2.0.1176.2.3.6.2") != ERR_OK ||
		pfokValParams(params) != ERR_OK ||
		(params->g[0] += 1) == 0 ||
		pfokValParams(params) == ERR_OK)
		return FALSE;
	// тест PFOK.GENG.4
	if (pfokStdParams(params, 0, "1.2.112.0.2.0.1176.2.3.10.2") != ERR_OK ||
		pfokValParams(params) != ERR_OK ||
		(params->g[0] += 1) == 0 ||
		pfokValParams(params) == ERR_OK)
		return FALSE;
	// загрузить параметры "test"
	if (pfokStdParams(params, 0, "test") != ERR_OK)
		return FALSE;
	// сгенерировать ключи
	prngCOMBOStart(combo_state, utilNonce32());
	if (pfokGenKeypair(ua, vb, params, prngCOMBOStepR, combo_state) != ERR_OK ||
		pfokValPubkey(params, vb) != ERR_OK ||
		pfokCalcPubkey(yb, params, ua) != ERR_OK ||
		!memEq(vb, yb, O_OF_B(params->l)))
		return FALSE;
	// тест PFOK.ANON.1
	hexToRev(ua, 
		"01"
		"1D4665B357DB361D106E32E353CD534B");
	hexToRev(vb, 
		"0739539C2AE25B53A05C8D16A14351D8"
		"EA86A1DD1893E08EE4A266F970E0243F"
		"8DF27F738F64E99E262E337792E5DD84"
		"7CF2A83362C6EC3C024E47313AA49A1E"
		"0A2E637AD35E31EB5F034D889B666701");
	if (pfokValPubkey(params, vb) != ERR_OK ||
		pfokDH(key, params, ua, vb) != ERR_OK ||
		!hexEqRev(key, 
			"777BB35E950D3080C1E896BE4172DBD0" 
			"61423D3BFEF78F15E3F7A7F2FF7A242B"))
		return FALSE;
	// тест PFOK.ANON.2
	hexToRev(ua, 
		"00"
		"0530110167E1443819A8662A0FAB7AC0");
	hexToRev(vb, 
		"1590312CBACB7B21FC0B173DC100AC5D"
		"8692E04813CA2F87A5763E3F4940B10C"
		"DF3F2B3ECDF28BE4BEA9363B07A8A8A3"
		"BFDDE074DCF36D669A56931D083FC3BE"
		"46D02CC8EF719EF66AE47F57BEAE8E02");
	if (pfokValPubkey(params, vb) != ERR_OK ||
		pfokDH(key, params, ua, vb) != ERR_OK ||
		!hexEqRev(key, 
			"46FA834B28D5E5D4183E28646AFFE806"
			"803E4C865CB99B1C423B0F1C78DE758D"))
		return FALSE;
	// тест PFOK.AUTH.1
	hexToRev(xa, 
		"00"
		"78E7101B4A8F421D2AF5740D6ED27680");
	hexToRev(yb, 
		"193E5E1E0839091BC7ABBDD09E8D2298"
		"8812D37EDEB39E077130A244888BE1A7"
		"53337AB5743C898D1CFC947430813448"
		"16AF5189A4E84D5B6EA310F72534D2E5"
		"E531B579CEA862EAB0251A3C20F0EC1D");
	hexToRev(ua, 
		"01"
		"27E33C0D7595566570936FEF0AA53A24");
	hexToRev(vb, 
		"0947264BEFA107E99616F347B6A05C62"
		"D7F5F26804D848FC4A7D81915F4546DD"
		"22949C07131D84F8B5A73A60ED61BC6E"
		"158E9B83F38C1EE6AD97F2BF771AA4FF"
		"B10A38298498D943995697FD0F65284C");
	if (pfokValPubkey(params, yb) != ERR_OK ||
		pfokValPubkey(params, vb) != ERR_OK ||
		pfokMTI(key, params, xa, ua, yb, vb) != ERR_OK ||
		!hexEqRev(key, 
			"EA92D5BCEC18BB44514E096748DB3E21"
			"D6E7B9C97D604699BEA7D3B96C87E18B"))
		return FALSE;
	// тест PFOK.AUTH.2
	hexToRev(xa, 
		"00"
		"05773C812D6F2A002D4E3EAC643C2CF3");
	hexToRev(yb, 
		"221CBFEB62F4AA3204D349B3D57E45E4"
		"C9BA601483CF9DDE4DD1AE1CC2694149"
		"F08765C5CCAEBD44B7B7D0F1783F9FDD"
		"2929523E1CEF2A46FBD419C5E5E2E712"
		"4099B405E0B90A5FB15A56F439DA47D1");
	hexToRev(ua, 
		"01"
		"3BB0377B3C0E55577A0D4A43627C6EC2");
	hexToRev(vb, 
		"2740ECD0631257DD8124DC38CFAC3DEF"
		"7162503B7F7C8DEC6478408B225D4C05"
		"56E566AF50661CE2F46662FC66DC429A"
		"CCF65D95E4F90BDCD08A11957C898EE2"
		"C2B77231929ACE9649B2C184CC9D8104");
	if (pfokValPubkey(params, yb) != ERR_OK ||
		pfokValPubkey(params, vb) != ERR_OK ||
		pfokMTI(key, params, xa, ua, yb, vb) != ERR_OK ||
		!hexEqRev(key, 
			"5A4C323604206C8898BF6C234F75A537"
			"DF75E9A249D87F1E55CBD7B40C4FDAFA"))
		return FALSE;
	// все нормально
	return TRUE;
}
