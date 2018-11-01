/*
*******************************************************************************
\file bash-test.c
\brief Tests for STB 34.101.77 (bash)
\project bee2/test
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2015.09.22
\version 2018.11.01
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include <bee2/core/mem.h>
#include <bee2/core/hex.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include <bee2/crypto/bash.h>
#include <bee2/crypto/belt.h>

/*
*******************************************************************************
Самотестирование

Создаются тесты для приложения А к СТБ 34.101.bash.

\todo Использовать state, или убрать.
*******************************************************************************
*/

bool_t bashTest()
{
	octet buf[192];
	octet hash[64];
	octet state[1024];
	// создать стек
	ASSERT(sizeof(state) >= bash256_keep());
	ASSERT(sizeof(state) >= bash384_keep());
	ASSERT(sizeof(state) >= bash512_keep());
	ASSERT(sizeof(state) >= bashAE_keep());
	// тест A.1
	memCopy(buf, beltH(), 192);
	bashF(buf);
	if (!hexEq(buf, 
		"8FE727775EA7F140B95BB6A200CBB28C"
		"7F0809C0C0BC68B7DC5AEDC841BD94E4"
		"03630C301FC255DF5B67DB53EF65E376"
		"E8A4D797A6172F2271BA48093173D329"
		"C3502AC946767326A2891971392D3F70"
		"89959F5D61621238655975E00E2132A0"
		"D5018CEEDB17731CCD88FC50151D37C0"
		"D4A3359506AEDC2E6109511E7703AFBB"
		"014642348D8568AA1A5D9868C4C7E6DF"
		"A756B1690C7C2608A2DC136F5997AB8F"
		"BB3F4D9F033C87CA6070E117F099C409"
		"4972ACD9D976214B7CED8E3F8B6E058E"))
		return FALSE;
	// тест A.2.1
	bash256Hash(hash, beltH(), 0);
	if (!hexEq(hash, 
		"114C3DFAE373D9BCBC3602D6386F2D6A"
		"2059BA1BF9048DBAA5146A6CB775709D"))
		return FALSE;
	bash256Start(state);
	bash256StepH(beltH(), 0, state);
	bash256StepG(buf, state);
	if (!memEq(hash, buf, 32))
		return FALSE;
	// тест A.2.2
	bash256Hash(hash, beltH(), 127);
	if (!hexEq(hash, 
		"3D7F4EFA00E9BA33FEED259986567DCF"
		"5C6D12D51057A968F14F06CC0F905961"))
		return FALSE;
	bash256Start(state);
	bash256StepH(beltH(), 127, state);
	bash256StepG(buf, state);
	if (!memEq(hash, buf, 32))
		return FALSE;
	// тест A.2.3
	bash256Hash(hash, beltH(), 128);
	if (!hexEq(hash, 
		"D7F428311254B8B2D00F7F9EEFBD8F30"
		"25FA87C4BABD1BDDBE87E35B7AC80DD6"))
		return FALSE;
	// тест A.2.4
	bash256Hash(hash, beltH(), 135);
	if (!hexEq(hash, 
		"1393FA1B65172F2D18946AEAE576FA1C"
		"F54FDD354A0CB2974A997DC4865D3100"))
		return FALSE;
	// тест A.2.5
	bash384Hash(hash, beltH(), 95);
	if (!hexEq(hash, 
		"64334AF830D33F63E9ACDFA184E32522"
		"103FFF5C6860110A2CD369EDBC04387C"
		"501D8F92F749AE4DE15A8305C353D64D"))
		return FALSE;
	bash384Start(state);
	bash384StepH(beltH(), 95, state);
	bash384StepG(buf, state);
	if (!memEq(hash, buf, 48))
		return FALSE;
	// тест A.2.6
	bash384Hash(hash, beltH(), 96);
	if (!hexEq(hash, 
		"D06EFBC16FD6C0880CBFC6A4E3D65AB1"
		"01FA82826934190FAABEBFBFFEDE93B2"
		"2B85EA72A7FB3147A133A5A8FEBD8320"))
		return FALSE;
	// тест A.2.7
	bash384Hash(hash, beltH(), 108);
	if (!hexEq(hash, 
		"FF763296571E2377E71A1538070CC0DE"
		"88888606F32EEE6B082788D246686B00"
		"FC05A17405C5517699DA44B7EF5F55AB"))
		return FALSE;
	// тест A.2.8
	bash512Hash(hash, beltH(), 63);
	if (!hexEq(hash, 
		"2A66C87C189C12E255239406123BDEDB"
		"F19955EAF0808B2AD705E249220845E2"
		"0F4786FB6765D0B5C48984B1B16556EF"
		"19EA8192B985E4233D9C09508D6339E7"))
		return FALSE;
	bash512Start(state);
	bash512StepH(beltH(), 63, state);
	bash512StepG(buf, state);
	if (!memEq(hash, buf, 64))
		return FALSE;
	// тест A.2.9
	bash512Hash(hash, beltH(), 64);
	if (!hexEq(hash, 
		"07ABBF8580E7E5A321E9B940F667AE20"
		"9E2952CEF557978AE743DB086BAB4885"
		"B708233C3F5541DF8AAFC3611482FDE4"
		"98E58B3379A6622DAC2664C9C118A162"))
		return FALSE;
	// тест A.2.10
	bash512Hash(hash, beltH(), 127);
	if (!hexEq(hash, 
		"526073918F97928E9D15508385F42F03"
		"ADE3211A23900A30131F8A1E3E1EE21C"
		"C09D13CFF6981101235D895746A4643F"
		"0AA62B0A7BC98A269E4507A257F0D4EE"))
		return FALSE;
	// тест A.12
	bash512Hash(hash, beltH(), 192);
	if (!hexEq(hash, 
		"8724C7FF8A2A83F22E38CB9763777B96"
		"A70ABA3444F214C763D93CD6D19FCFDE"
		"6C3D3931857C4FF6CCCD49BD99852FE9"
		"EAA7495ECCDD96B571E0EDCF47F89768"))
		return FALSE;
	// AE.1: buf <- [8]iv || [12]data || [15]text || [8]mac
	memCopy(buf, beltH(), 8 + 12 + 15);
	bashAEStart(state, beltH() + 128, 32, buf, 8);
	bashAEAbsorb(BASH_AE_DATA, buf + 8, 12, state);
	bashAEEncr(buf + 8 + 12, 15, state);
	bashAESqueeze(BASH_AE_MAC, buf + 8 + 12 + 15, 8, state);
	if (!hexEq(buf + 20, 
		"FEC2A158AA464A81E7AC5B0E204D7F93"
		"9F242538755D18"))
		return FALSE;
	bashAEStart(state, beltH() + 128, 32, buf, 8);
	bashAEAbsorb(BASH_AE_DATA, buf + 8, 12, state);
	bashAEDecr(buf + 8 + 12, 15, state);
	bashAESqueeze(BASH_AE_MAC, hash, 8, state);
	if (!memEq(buf + 8 + 12, beltH() + 8 + 12, 15) ||
		!memEq(buf + 8 + 12 + 15, hash, 8))
		return FALSE;
	// все нормально
	return TRUE;
}
