/*
*******************************************************************************
\file btok_pwd.c
\brief STB 34.101.79 (btok): Password management
\project bee2 [cryptographic library]
\created 2022.07.19
\version 2022.12.12
\license This program is released under the GNU General Public License
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/blob.h"
#include "bee2/core/err.h"
#include "bee2/core/der.h"
#include "bee2/core/mem.h"
#include "bee2/core/hex.h"
#include "bee2/core/rng.h"
#include "bee2/core/str.h"
#include "bee2/core/util.h"
#include "bee2/crypto/btok.h"

/*
*******************************************************************************
Парольный автомат
*******************************************************************************
*/

bool_t btokPwdTransition(btok_pwd_state* state, btok_pwd_event event)
{
	ASSERT(memIsValid(state, sizeof(btok_pwd_state)));
	switch (event)
	{
	case auth_close:
		if (state->auth == auth_none)
			return FALSE;
		state->auth = auth_none;
		return TRUE;
	case pin_deactivate:
		if (state->auth != auth_pin && state->auth != auth_puk)
			return FALSE;
		state->pin = pind;
		if (state->auth == auth_pin)
			state->auth = auth_none;
		return TRUE;
	case pin_activate:
		if (state->pin != pind || state->auth != auth_puk)
			return FALSE;
		state->pin = pin3;
		return TRUE;
	case can_ok:
		if (state->pin == pins)
			state->pin = pin1;
		state->auth = auth_can;
		return TRUE;
	case can_bad:
		if (state->auth == auth_can)
			state->auth = auth_none;
		return TRUE;
	case puk_ok:
		if (puk1 <= state->pin && state->pin <= pin0)
			state->pin = pin3;
		state->auth = auth_puk;
		return TRUE;
	case puk_bad:
		if (puk1 <= state->pin && state->pin <= pin0)
			--state->pin;
		if (state->auth == auth_puk)
			state->auth = auth_none;
		return TRUE;
	case pin_ok:
		if (state->pin != pin1 && state->pin != pin2 && state->pin != pin3)
			return FALSE;
		state->pin = pin3;
		state->auth = auth_pin;
		return TRUE;
	case pin_bad:
		if (state->pin != pin1 && state->pin != pin2 && state->pin != pin3)
			return FALSE;
		--state->pin;
		if (state->auth == auth_pin)
			state->auth = auth_none;
		return TRUE;
	}
	return FALSE;
}
