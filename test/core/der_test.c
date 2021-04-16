/*
*******************************************************************************
\file der_test.c
\brief Tests for DER encoding rules
\project bee2/test
\author Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2021.04.12
\version 2021.04.14
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
	union {
		size_t size;
		octet oct[128];
		octet* ptr;
		char oid[16];
	} val;
	// SIZE(0)
	count = derEncSIZE(0, 0);
	if (count != 3)
		return FALSE;
	ASSERT(count <= sizeof(buf));
	if (derEncSIZE(buf, 0) != 3 || !hexEq(buf, "020100") ||
		derDecSIZE(&val.size, buf, sizeof(buf)) != 3 || val.size != 0)
		return FALSE;
	// SIZE(127)
	count = derEncSIZE(0, 127);
	if (count != 3)
		return FALSE;
	ASSERT(count <= sizeof(buf));
	if (derEncSIZE(buf, 127) != 3 || !hexEq(buf, "02017F") ||
		derDecSIZE(&val.size, buf, sizeof(buf)) != 3 || val.size != 127)
		return FALSE;
	// SIZE(128)
	count = derEncSIZE(0, 128);
	if (count != 4)
		return FALSE;
	ASSERT(count <= sizeof(buf));
	if (derEncSIZE(buf, 128) != 4 || !hexEq(buf, "02020080") ||
		derDecSIZE(&val.size, buf, sizeof(buf)) != 4 || val.size != 128)
		return FALSE;
	// SIZE(256)
	count = derEncSIZE(0, 256);
	if (count != 4)
		return FALSE;
	ASSERT(count <= sizeof(buf));
	if (derEncSIZE(buf, 256) != 4 || !hexEq(buf, "02020100") ||
		derDecSIZE(&val.size, buf, sizeof(buf)) != 4 || val.size != 256)
		return FALSE;
	// NULL
	count = derEncNULL(0);
	if (count != 2)
		return FALSE;
	ASSERT(count <= sizeof(buf));
	if (derEncNULL(buf) != 2 || !hexEq(buf, "0500") ||
		derDecNULL(buf, sizeof(buf)) != 2)
		return FALSE;
	// OCT
	hexTo(val.oct, "0123456789ABCDEF");
	count = derEncOCT(0, val.oct, 8);
	if (count != 10)
		return FALSE;
	ASSERT(count <= sizeof(buf));
	if (derEncOCT(buf, val.oct, 8) != 10 || !hexEq(buf, "04080123456789ABCDEF") ||
		derDecOCT3(buf, sizeof(buf), val.oct, 8) != 10 ||
		derDecOCT2(val.oct, buf, sizeof(buf), 8) != 10 ||
		!hexEq(val.oct, "0123456789ABCDEF") ||
		derDecOCT2(0, buf, sizeof(buf), 8) != 10 ||
		derDecOCT(val.oct, &len, buf, sizeof(buf)) != 10 || len != 8 ||
		!hexEq(val.oct, "0123456789ABCDEF") ||
		derDecOCT(0, &len, buf, sizeof(buf)) != 10 || len != 8 ||
		derDecOCT(val.oct, 0, buf, sizeof(buf)) != 10 || 
		!hexEq(val.oct, "0123456789ABCDEF") ||
		derDecOCT(0, 0, buf, sizeof(buf)) != 10)
		return FALSE;
	// OID
	count = derEncOID(0, "1.2.840.113549");
	if (count != 8)
		return FALSE;
	ASSERT(count <= sizeof(buf));
	if (derEncOID(buf, "1.2.840.113549") != 8 ||
		!hexEq(buf, "06062A864886F70D") ||
		derDecOID(0, 0, buf, sizeof(buf)) != 8 || 
		derDecOID(val.oid, 0, buf, sizeof(buf)) != 8 || 
			!strEq(val.oid, "1.2.840.113549") ||
		derDecOID(val.oid, &len, buf, sizeof(buf)) != 8 || len != 15 ||
			!strEq(val.oid, "1.2.840.113549") ||
		derDecOID(0, &len, buf, sizeof(buf)) != 8 || len != 15 ||
			!strEq(val.oid, "1.2.840.113549") ||
		derDecOID2(buf, sizeof(buf), val.oid) != 8)
		return FALSE;
	// Seq1 ::= SEQUENCE { nothing NULL }
	{
		der_anchor Seq1[1];
		octet* ptr;
		// определить длину кода
		count = 0;
		derStep(derEncSEQStart(Seq1, 0, count), count);
		derStep(derEncNULL(0), count);
		derStep(derEncSEQStop(0, count, Seq1), count);
		if (count != 4)
			return FALSE;
		// кодировать
		ASSERT(count <= sizeof(buf));
		count = 0;
		derStep(derEncSEQStart(Seq1, buf, count), count);
		derStep(derEncNULL(buf + count), count);
		derStep(derEncSEQStop(buf + count, count, Seq1), count);
		if (count != 4 || !hexEq(buf, "30020500"))
			return FALSE;
		// проверить
		if (!derIsValid(buf, count) || !derIsValid2(buf, count, 0x30))
			return FALSE;
		// декодировать
		derStep2(derDecSEQStart(Seq1, ptr = buf, count), ptr, count);
		derStep2(derDecNULL(ptr, count), ptr, count);
		derStep2(derDecSEQStop(ptr, Seq1), ptr, count);
		if (count != 0)
			return FALSE;
	}
	// Seq2 ::= SEQUENCE { octet OCTET STRING(130) }
	{
		der_anchor Seq2[1];
		octet* ptr;
		// подготовить строку октетов
		memSetZero(val.oct, 127);
		// кодировать
		count = 0;
		derStep(derEncSEQStart(Seq2, buf, count), count);
		derStep(derEncOCT(buf + count, val.oct, 127), count);
		derStep(derEncSEQStop(buf + count, count, Seq2), count);
		if (count != 132 || !hexEq(buf, "308181047F0000"))
			return FALSE;
		// декодировать
		derStep2(derDecSEQStart(Seq2, ptr = buf, count), ptr, count);
		derStep2(derDecOCT3(ptr, count, val.oct, 127), ptr, count);
		derStep2(derDecSEQStop(ptr, Seq2), ptr, count);
		if (count != 0)
			return FALSE;
	}
	// все нормально
	return TRUE;
}
