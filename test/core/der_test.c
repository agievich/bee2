/*
*******************************************************************************
\file der_test.c
\brief Tests for DER encoding rules
\project bee2/test
\created 2021.04.12
\version 2022.10.26
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include <bee2/core/der.h>
#include <bee2/core/hex.h>
#include <bee2/core/mem.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>

/*
*******************************************************************************
Тестирование

-#	used [Kaliski B. A Layman's Guide to a Subset of ASN.1, BER, and DER]
	http://luca.ntop.org/Teaching/Appunti/asn1.html
*******************************************************************************
*/

#define derStep(step, count)\
{\
	size_t t = (step);\
	if (t == SIZE_MAX)\
		return FALSE;\
	(count) += t;\
}\

#define derStep2(step, ptr, count)\
{\
	size_t t = (step);\
	if (t == SIZE_MAX)\
		return FALSE;\
	(ptr) += t, (count) -= t;\
}\


bool_t derTest()
{
	octet buf[1024];
	size_t count, len;
	u32 tag;
	union {
		size_t size;
		octet oct[128];
		octet* ptr;
		char oid[16];
		char str[16];
	} val;
	// SIZE(0)
	count = derSIZEEnc(0, 0);
	if (count != 3)
		return FALSE;
	ASSERT(count <= sizeof(buf));
	if (derSIZEEnc(buf, 0) != 3 ||
		!hexEq(buf, "020100") ||
		derDecTL(&tag, &len, buf, 1024) != 3 || tag != 2 || len != 1 ||
		derSIZEDec(&val.size, buf, sizeof(buf)) != 3 ||
		val.size != 0)
		return FALSE;
	// SIZE[APPLICATION 41](0)
	count = derTSIZEEnc(0, tag = 0x5F29, 0);
	if (count != 4)
		return FALSE;
	ASSERT(count <= sizeof(buf));
	if (derTSIZEEnc(buf, tag, 0) != 4 ||
		!hexEq(buf, "5F290100") ||
		derTSIZEDec(&val.size, buf, sizeof(buf), tag) != 4 ||
		val.size != 0 ||
		derTSIZEDec(&val.size, buf, sizeof(buf), tag + 1) != SIZE_MAX)
		return FALSE;
	// SIZE(127)
	count = derSIZEEnc(0, 127);
	if (count != 3)
		return FALSE;
	ASSERT(count <= sizeof(buf));
	if (derSIZEEnc(buf, 127) != 3 ||
		!hexEq(buf, "02017F") ||
		derSIZEDec(&val.size, buf, sizeof(buf)) != 3 ||
		val.size != 127)
		return FALSE;
	// SIZE(128)
	count = derSIZEEnc(0, 128);
	if (count != 4)
		return FALSE;
	ASSERT(count <= sizeof(buf));
	if (derSIZEEnc(buf, 128) != 4 ||
		!hexEq(buf, "02020080") ||
		derSIZEDec(&val.size, buf, sizeof(buf)) != 4 ||
		val.size != 128)
		return FALSE;
	// SIZE(256)
	count = derSIZEEnc(0, 256);
	if (count != 4)
		return FALSE;
	ASSERT(count <= sizeof(buf));
	if (derSIZEEnc(buf, 256) != 4 ||
		!hexEq(buf, "02020100") ||
		derSIZEDec(&val.size, buf, sizeof(buf)) != 4 ||
		val.size != 256)
		return FALSE;
	// NULL
	count = derNULLEnc(0);
	if (count != 2)
		return FALSE;
	ASSERT(count <= sizeof(buf));
	if (derNULLEnc(buf) != 2 ||
		!hexEq(buf, "0500") ||
		derNULLDec(buf, sizeof(buf)) != 2)
		return FALSE;
	// BIT
	hexTo(val.oct, "0123456789ABCDEF");
	count = derBITEnc(0, val.oct, 61);
	if (count != 11)
		return FALSE;
	ASSERT(count <= sizeof(buf));
	if (derBITEnc(buf, val.oct, 61) != 11 ||
		!hexEq(buf, "0309030123456789ABCDE8") ||
		derBITDec2(val.oct, buf, sizeof(buf), 61) != 11 ||
		!hexEq(val.oct, "0123456789ABCDE8") ||
		derBITDec2(val.oct, buf, sizeof(buf), 62) != SIZE_MAX ||
		derBITDec2(val.oct, buf, 6, 61) != SIZE_MAX ||
		derBITDec(val.oct, &len, buf, sizeof(buf)) != 11 || len != 61 ||
		!hexEq(val.oct, "0123456789ABCDE8") ||
		derBITEnc(buf, val.oct, 64) != 11 ||
		!hexEq(buf, "0309000123456789ABCDE8") ||
		derBITDec2(val.oct, buf, sizeof(buf), 64) != 11 ||
		!hexEq(val.oct, "0123456789ABCDE8") ||
		derBITDec2(val.oct, buf, sizeof(buf), 63) != SIZE_MAX ||
		derBITDec2(val.oct, buf, 6, 64) != SIZE_MAX ||
		derBITDec(val.oct, &len, buf, sizeof(buf)) != 11 || len != 64)
		return FALSE;
	// OCT
	hexTo(val.oct, "0123456789ABCDEF");
	count = derOCTEnc(0, val.oct, 8);
	if (count != 10)
		return FALSE;
	ASSERT(count <= sizeof(buf));
	if (derOCTEnc(buf, val.oct, 8) != 10 ||
		!hexEq(buf, "04080123456789ABCDEF") ||
		derOCTDec3(buf, sizeof(buf), val.oct, 8) != 10 ||
		derOCTDec2(val.oct, buf, sizeof(buf), 8) != 10 ||
		!hexEq(val.oct, "0123456789ABCDEF") ||
		derOCTDec2(0, buf, sizeof(buf), 8) != 10 ||
		derOCTDec(val.oct, &len, buf, sizeof(buf)) != 10 || len != 8 ||
		!hexEq(val.oct, "0123456789ABCDEF") ||
		derOCTDec(0, &len, buf, sizeof(buf)) != 10 || len != 8 ||
		derOCTDec(val.oct, 0, buf, sizeof(buf)) != 10 || 
		!hexEq(val.oct, "0123456789ABCDEF") ||
		derOCTDec(0, 0, buf, sizeof(buf)) != 10)
		return FALSE;
	// OID
	count = derOIDEnc(0, "1.2.840.113549");
	if (count != 8)
		return FALSE;
	ASSERT(count <= sizeof(buf));
	if (derOIDEnc(buf, "1.2.840.113549") != 8 ||
		!hexEq(buf, "06062A864886F70D") ||
		derOIDDec(0, 0, buf, sizeof(buf)) != 8 || 
		derOIDDec(val.oid, 0, buf, sizeof(buf)) != 8 || 
		!strEq(val.oid, "1.2.840.113549") ||
		derOIDDec(val.oid, &len, buf, sizeof(buf)) != 8 || len != 14 ||
		!strEq(val.oid, "1.2.840.113549") ||
		derOIDDec(0, &len, buf, sizeof(buf)) != 8 || len != 14 ||
		!strEq(val.oid, "1.2.840.113549") ||
		derOIDDec2(buf, sizeof(buf), val.oid) != 8)
		return FALSE;
	// PSTR
	count = derTPSTREnc(0, 0x42, "BYCA0000");
	if (count != 10)
		return FALSE;
	ASSERT(count <= sizeof(buf));
	if (derTPSTREnc(buf, 0x42, "BYCA0000") != 10 ||
		!hexEq(buf, "42084259434130303030") ||
		derTPSTRDec(0, 0, buf, sizeof(buf), 0x42) != 10 ||
		derPSTRDec(0, 0, buf, sizeof(buf)) != SIZE_MAX ||
		derTPSTRDec(val.str, 0, buf, sizeof(buf), 0x42) != 10 ||
		!strEq(val.str, "BYCA0000") ||
		derTPSTRDec(val.str, &len, buf, sizeof(buf), 0x42) != 10 || 
		!strEq(val.oid, "BYCA0000") || len != 8 ||
		derTPSTRDec(0, &len, buf, sizeof(buf), 0x42) != 10 || len != 8)
		return FALSE;
	// Seq1 ::= SEQUENCE { nothing NULL }
	{
		der_anchor_t Seq1[1];
		octet* ptr;
		// определить длину кода
		count = 0;
		derStep(derSEQEncStart(Seq1, 0, count), count);
		derStep(derNULLEnc(0), count);
		derStep(derSEQEncStop(0, count, Seq1), count);
		if (count != 4)
			return FALSE;
		// кодировать
		ASSERT(count <= sizeof(buf));
		count = 0;
		derStep(derSEQEncStart(Seq1, buf, count), count);
		derStep(derNULLEnc(buf + count), count);
		derStep(derSEQEncStop(buf + count, count, Seq1), count);
		if (count != 4 || !hexEq(buf, "30020500"))
			return FALSE;
		// проверить
		if (!derIsValid(buf, count) || !derIsValid2(buf, count, 0x30))
			return FALSE;
		// декодировать
		derStep2(derSEQDecStart(Seq1, ptr = buf, count), ptr, count);
		derStep2(derNULLDec(ptr, count), ptr, count);
		derStep2(derSEQDecStop(ptr, Seq1), ptr, count);
		if (count != 0)
			return FALSE;
	}
	// Seq2 ::= SEQUENCE { octet OCTET STRING(130) }
	{
		der_anchor_t Seq2[1];
		octet* ptr;
		// подготовить строку октетов
		memSetZero(val.oct, 127);
		// кодировать
		count = 0;
		derStep(derSEQEncStart(Seq2, buf, count), count);
		derStep(derOCTEnc(buf + count, val.oct, 127), count);
		derStep(derSEQEncStop(buf + count, count, Seq2), count);
		if (count != 132 || !hexEq(buf, "308181047F0000"))
			return FALSE;
		// декодировать
		derStep2(derSEQDecStart(Seq2, ptr = buf, count), ptr, count);
		derStep2(derOCTDec3(ptr, count, val.oct, 127), ptr, count);
		derStep2(derSEQDecStop(ptr, Seq2), ptr, count);
		if (count != 0)
			return FALSE;
	}
	// все нормально
	return TRUE;
}
