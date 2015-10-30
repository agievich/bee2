/*
*******************************************************************************
\file prng-test.c
\brief Tests for pseudorandom number generators
\project bee2/test
\author (С) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2014.06.30
\version 2015.10.29
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include <bee2/core/mem.h>
#include <bee2/core/hex.h>
#include <bee2/core/prng.h>
#include <bee2/core/util.h>

/*
*******************************************************************************
Тестирование
*******************************************************************************
*/

bool_t prngTest()
{
	octet buf[128];
	char state[256];
	// prngSTB
	ASSERT(prngSTB_keep() <= sizeof(state));
	prngSTBStart(state, 0);
	prngSTBStepG(buf, 128, state);
	if (!hexEq(buf, 
		"402971E923BFD0B621E230D4CBFAF010"
		"E2D1F32D5C76B58AE05AB02BB85B2A10"
		"67F8DC6FFFF51932D956E3B3749884C5"
		"623331D616FF391C8AF12556A0CBA754"
		"79F682F6DD86DACB59346C50DD01CFAF"
		"6255D350C3B7392C8F6AA11496BBD25D"
		"D80C0173331A9C0DF721884E4E2773C5"
		"7FE4E23824E31FC902F1C7A09EB1C312"))
		return FALSE;
	// все нормально
	return TRUE;
}
