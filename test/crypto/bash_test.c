/*
*******************************************************************************
\file bash_test.c
\brief Tests for STB 34.101.77 (bash)
\project bee2/test
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2015.09.22
\version 2020.06.24
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

Тесты из приложения А к СТБ 34.101.77.
*******************************************************************************
*/

bool_t bashTest()
{
	octet buf[192];
	octet hash[64];
	octet state[1024];
	octet state1[1024];
	size_t pos;
	// создать стек
	ASSERT(sizeof(state) >= bashF_deep());
	ASSERT(sizeof(state) >= bashHash_keep());
	ASSERT(sizeof(state) >= bashPrg_keep());
	ASSERT(sizeof(state) == sizeof(state1));
	// A.2
	memCopy(buf, beltH(), 192);
	bashF(buf, state);
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
	// A.3.1
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
	// A.3.2
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
	// A.3.3
	bash256Hash(hash, beltH(), 128);
	if (!hexEq(hash, 
		"D7F428311254B8B2D00F7F9EEFBD8F30"
		"25FA87C4BABD1BDDBE87E35B7AC80DD6"))
		return FALSE;
	// A.3.4
	bash256Hash(hash, beltH(), 135);
	if (!hexEq(hash, 
		"1393FA1B65172F2D18946AEAE576FA1C"
		"F54FDD354A0CB2974A997DC4865D3100"))
		return FALSE;
	// A.3.5
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
	// A.3.6
	bash384Hash(hash, beltH(), 96);
	if (!hexEq(hash, 
		"D06EFBC16FD6C0880CBFC6A4E3D65AB1"
		"01FA82826934190FAABEBFBFFEDE93B2"
		"2B85EA72A7FB3147A133A5A8FEBD8320"))
		return FALSE;
	// A.3.7
	bash384Hash(hash, beltH(), 108);
	if (!hexEq(hash, 
		"FF763296571E2377E71A1538070CC0DE"
		"88888606F32EEE6B082788D246686B00"
		"FC05A17405C5517699DA44B7EF5F55AB"))
		return FALSE;
	// A.3.8
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
	// A.3.9
	bash512Hash(hash, beltH(), 64);
	if (!hexEq(hash, 
		"07ABBF8580E7E5A321E9B940F667AE20"
		"9E2952CEF557978AE743DB086BAB4885"
		"B708233C3F5541DF8AAFC3611482FDE4"
		"98E58B3379A6622DAC2664C9C118A162"))
		return FALSE;
	// A.3.10
	bash512Hash(hash, beltH(), 127);
	if (!hexEq(hash, 
		"526073918F97928E9D15508385F42F03"
		"ADE3211A23900A30131F8A1E3E1EE21C"
		"C09D13CFF6981101235D895746A4643F"
		"0AA62B0A7BC98A269E4507A257F0D4EE"))
		return FALSE;
	// A.3.11
	bash512Hash(hash, beltH(), 192);
	if (!hexEq(hash, 
		"8724C7FF8A2A83F22E38CB9763777B96"
		"A70ABA3444F214C763D93CD6D19FCFDE"
		"6C3D3931857C4FF6CCCD49BD99852FE9"
		"EAA7495ECCDD96B571E0EDCF47F89768"))
		return FALSE;
	// A.4.alpha
	bashPrgStart(state, 256, 2, 0, 0, beltH(), 32);
	bashPrgAbsorb(beltH() + 32, 95, state);
	bashPrgRatchet(state);
	bashPrgSqueeze(hash, 16, state);
	if (!hexEq(hash,
		"69A3B04BF1C573728D15C26F3CC6C6F4"))
		return FALSE;
	// A.4.beta
	bashPrgStart(state, 128, 1, beltH() + 128, 16, hash, 16);
	memCopy(state1, state, bashPrg_keep());
	memCopy(buf, beltH() + 128 + 32, 23);
	bashPrgEncr(buf, 23, state);
	if (!hexEq(buf,
		"198351B5A8F2179F487F03970366CEAB"
		"264D804DD6389D"))
		return FALSE;
	bashPrgStart(state, 128, 1, beltH() + 128, 16, hash, 16);
	bashPrgDecr(buf, 23, state);
	if (!memEq(buf, beltH() + 128 + 32, 23))
		return FALSE;
	// A.4.gamma
	bashPrgRestart(beltH() + 128 + 16, 4, 0, 0, state1);
	memCopy(state, state1, bashPrg_keep());
	memCopy(buf, beltH() + 128 + 32, 23);
	bashPrgEncr(buf, 23, state1);
	if (!hexEq(buf,
		"D9D7EF6538CD693BAF8F8667FA512ECE"
		"CD2C6A87226299"))
		return FALSE;
	bashPrgDecr(buf, 23, state);
	if (!memEq(buf, beltH() + 128 + 32, 23))
		return FALSE;
	// A.5.1
	bashPrgStart(state, 128, 2, 0, 0, 0, 0);
	bashPrgAbsorb(beltH(), 0, state);
	bashPrgSqueeze(hash, 32, state);
	if (!hexEq(hash,
		"36FA075EC15721F250B9A641A8CB99A3"
		"33A9EE7BA8586D0646CBAC3686C03DF3"))
		return FALSE;
	// A.5.2
	bashPrgStart(state, 128, 2, 0, 0, 0, 0);
	bashPrgAbsorb(beltH(), 127, state);
	bashPrgSqueeze(hash, 32, state);
	if (!hexEq(hash,
		"C930FF427307420DA6E4182969AA1FFC"
		"3310179B8A0EDB3E20BEC285B568BA17"))
		return FALSE;
	// A.5.3
	bashPrgStart(state, 128, 2, 0, 0, 0, 0);
	bashPrgAbsorb(beltH(), 128, state);
	bashPrgSqueeze(hash, 32, state);
	if (!hexEq(hash,
		"92AD1402C2007191F2F7CFAD6A2F8807"
		"BB0C50F73DFF95EF1B8AF08504D54007"))
		return FALSE;
	// A.5.4
	bashPrgStart(state, 128, 2, 0, 0, 0, 0);
	bashPrgAbsorb(beltH(), 150, state);
	bashPrgSqueeze(hash, 32, state);
	if (!hexEq(hash,
		"48DB61832CA1009003BC0D8BDE67893A"
		"9DC683C48A5BC23AC884EB4613B480A6"))
		return FALSE;
	bashPrgStart(state, 128, 2, 0, 0, 0, 0);
	bashPrgAbsorbStart(state);
	bashPrgAbsorbStep(beltH(), 0, state);
	bashPrgAbsorbStep(beltH(), 50, state);
	bashPrgAbsorbStep(beltH() + 50, 50, state);
	bashPrgAbsorbStep(beltH() + 100, 50, state);
	bashPrgSqueezeStart(state);
	bashPrgSqueezeStep(buf, 13, state);
	bashPrgSqueezeStep(buf + 13, 32 - 13, state);
	if (!memEq(hash, buf, 32))
		return FALSE;
	// A.5.5
	bashPrgStart(state, 192, 1, 0, 0, 0, 0);
	bashPrgAbsorb(beltH(), 143, state);
	bashPrgSqueeze(hash, 48, state);
	if (!hexEq(hash,
		"6166032D6713D401A6BC687CCFFF2E60"
		"3287143A84C78D2C62C71551E0E2FB2A"
		"F6B799EE33B5DECD7F62F190B1FBB052"))
		return FALSE;
	// A.5.6
	bashPrgStart(state, 192, 1, 0, 0, 0, 0);
	bashPrgAbsorb(beltH(), 144, state);
	bashPrgSqueeze(hash, 48, state);
	if (!hexEq(hash,
		"8D84C82ECD0AB6468CC451CFC5EEB3B2"
		"98DFD381D200DA69FBED5AE67D26BAD5"
		"C727E2652A225BF465993043039E338B"))
		return FALSE;
	// A.5.7
	bashPrgStart(state, 192, 1, 0, 0, 0, 0);
	bashPrgAbsorb(beltH(), 150, state);
	bashPrgSqueeze(hash, 48, state);
	if (!hexEq(hash,
		"47529F9D499AB6AB8AD72B1754C90C39"
		"E7DA237BEB16CDFC00FE87934F5AFC11"
		"01862DFA50560F062A4DAC859CC13DBC"))
		return FALSE;
	// A.6.encr
	bashPrgStart(state, 256, 1, beltH(), 16, beltH() + 32, 32);
	bashPrgAbsorb(beltH() + 64, 49, state);
	memSetZero(buf, 192);
	bashPrgEncr(buf, 192, state);
	if (!hexEq(buf,
		"690673766C3E848CAC7C05169FFB7B77"
		"51E52A011040E5602573FAF991044A00"
		"4329EEF7BED8E6875830A91854D1BD2E"
		"DC6FC2FF37851DBAC249DF400A0549EA"
		"2E0C811D499E1FF1E5E32FAE7F0532FA"
		"4051D0F9E300D9B1DBF119AC8CFFC48D"
		"D3CBF1CA0DBA5DD97481C88DF0BE4127"
		"85E40988B31585537948B80F5A9C49E0"
		"8DD684A7DCA871C380DFDC4C4DFBE61F"
		"50D2D0FBD24D8B9D32974A347247D001"
		"BAD5B168440025693967E77394DC088B"
		"0ECCFA8D291BA13D44F60B06E2EDB351"))
		return FALSE;
	bashPrgSqueeze(hash, 32, state);
	if (!hexEq(hash,
		"CDE5AF6EF9A14B7D0C191B869A6343ED"
		"6A4E9AAB4EE00A579E9E682D0EC051E3"))
		return FALSE;
	// A.6.decr
	bashPrgStart(state, 256, 1, beltH(), 16, beltH() + 32, 32);
	bashPrgAbsorb(beltH() + 64, 49, state);
	bashPrgDecrStart(state);
	for (pos = 0; pos < 192; pos += 192 / 6)
		bashPrgDecrStep(buf + pos, 192 / 6, state);
	if (!memIsZero(buf, 192))
		return FALSE;
	bashPrgSqueezeStart(state);
	bashPrgSqueezeStep(buf, 14, state);
	bashPrgSqueezeStep(buf + 14, 32 - 14, state);
	if (!memEq(buf, hash, 32))
		return FALSE;
	// все нормально
	return TRUE;
}
