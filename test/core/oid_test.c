/*
*******************************************************************************
\file oid_test.c
\brief Tests for object identifiers
\project bee2/test
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2013.04.01
\version 2015.10.29
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include <bee2/core/mem.h>
#include <bee2/core/hex.h>
#include <bee2/core/oid.h>
#include <bee2/core/str.h>

/*
*******************************************************************************
Тестирование

-#	used http://www.viathinksoft.de/~daniel-marschall/asn.1/oid_facts.html
*******************************************************************************
*/

bool_t oidTest()
{
	octet buf[1024];
	char str[2048];
	char str1[2048];
	size_t count;
	// length octet 0x00
	hexTo(buf, "060000");
	if (oidFromDER(0, buf, 3) != SIZE_MAX)
		return FALSE;
	// length octet 0x80
	hexTo(buf, "068000");
	if (oidFromDER(0, buf, 3) != SIZE_MAX)
		return FALSE;
	// length octet 0xFF
	hexTo(buf, "06FF00");
	if (oidFromDER(0, buf, 3) != SIZE_MAX)
		return FALSE;
	// invalid type
	hexTo(buf, "080100");
	if (oidFromDER(0, buf, 3) != SIZE_MAX)
		return FALSE;
	// illegal padding
	hexTo(buf, "06070180808080807F");
	if (oidFromDER(0, buf, 9) != SIZE_MAX)
		return FALSE;
	hexTo(buf, "06028001");
	if (oidFromDER(0, buf, 4) != SIZE_MAX)
		return FALSE;
	hexTo(buf, "0602807F");
	if (oidFromDER(0, buf, 4) != SIZE_MAX)
		return FALSE;
	// MacOS errors
	hexTo(buf, "06028100");
	if (oidFromDER(str, buf, 4) == SIZE_MAX || !strEq(str, "2.48"))
		return FALSE;
	hexTo(buf, "06028101");
	if (oidFromDER(str, buf, 4) == SIZE_MAX || !strEq(str, "2.49"))
		return FALSE;
	hexTo(buf, "06028837");
	if (oidFromDER(str, buf, 4) == SIZE_MAX || !strEq(str, "2.999"))
		return FALSE;
	// OpenSSL errors
	count = oidToDER(buf, "2.65500");
	if (count == SIZE_MAX || oidFromDER(str, buf, count) == SIZE_MAX ||
		!strEq(str, "2.65500"))
		return FALSE;
	// overflow
	hexTo(buf, "060981B1D1AF85ECA8804F");
	if (oidFromDER(0, buf, 11) != SIZE_MAX)
		return FALSE;
	if (oidIsValid("2.5.4.4294967299"))
		return FALSE;
	// belt-hash
	count = oidToDER(buf, "1.2.112.0.2.0.34.101.31.81");
	if (count != 11 || !hexEq(buf, "06092A7000020022651F51"))
		return FALSE;
	if (oidFromDER(str, buf, count - 1) != SIZE_MAX)
		return FALSE;
	if (oidFromDER(0, buf, count + 1) != SIZE_MAX)
		return FALSE;
	// длинная длина
	strCopy(str1, "1.2.3456.78910.11121314.15161718.19202122.23242526."
		"27282930.31323334.35363738.1.2.3.4.5.6.7.8.9.10.11.12.13.14.15.16.17.18."
		"19.20.21.22.23.24.25.26.27.28.29.30.31.32.33.34.35.36.37.38.39.40.41.42."
		"43.44.45.46.47.48.49.50.51.52.53.54.55.56.57.58.59.60.61.62.63.64.65.66."
		"19.20.21.22.23.24.25.26.27.28.29.30.31.32.33.34.35.36.37.38.39.40.41.42."
		"43.44.45.46.47.48.49.50.51.52.53.54.55.56.57.58.59.60.61.62.63.64.65.66."
		"19.20.21.22.23.24.25.26.27.28.29.30.31.32.33.34.35.36.37.38.39.40.41.42."
		"43.44.45.46.47.48.49.50.51.52.53.54.55.56.57.58.59.60.61.62.63.64.65.66");
	count = oidToDER(buf, str1);
	oidFromDER(str, buf, count);
	if (!strEq(str, str1))
		return FALSE;
	str1[strLen(str1)] = '.';
	strCopy(str1 + strLen(str) + 1, str);
	count = oidToDER(buf, str1);
	oidFromDER(str, buf, count);
	if (!strEq(str, str1))
		return FALSE;
	// все нормально
	return TRUE;
}
