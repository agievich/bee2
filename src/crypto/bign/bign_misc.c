/*
*******************************************************************************
\file bign_misc.c
\brief STB 34.101.45 (bign): miscellaneous functions
\project bee2 [cryptographic library]
\author Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2012.04.27
\version 2021.07.20
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/err.h"
#include "bee2/core/mem.h"
#include "bee2/core/oid.h"
#include "bee2/core/str.h"
#include "bee2/core/util.h"
#include "bee2/crypto/bign.h"
#include "crypto/bign_lcl.h"

/*
*******************************************************************************
Тестовые параметры (пониженные уровни стойкости)
*******************************************************************************
*/

// bign-curve192v1
static const char _curve192v1_name[] = "bign-curve192v1";

static const octet _curve192v1_p[24] = {
	0x13, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

static const octet _curve192v1_a[24] = {
	0x10, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

static const octet _curve192v1_b[24] = {
	0x83, 0x4C, 0x34, 0x64, 0x4C, 0xE8, 0xDD, 0x6A,
	0x7A, 0x73, 0x01, 0x89, 0x88, 0x8E, 0x18, 0x87,
	0xA8, 0x98, 0x23, 0xFD, 0x25, 0xB9, 0x99, 0x31,
};

static const octet _curve192v1_seed[8] = {
	0xC6, 0x6C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const octet _curve192v1_q[24] = {
	0xAD, 0x11, 0x64, 0xFD, 0xBE, 0xEC, 0x0B, 0x91,
	0x37, 0xD3, 0x3A, 0x65, 0xFE, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

static const octet _curve192v1_yG[24] = {
	0xEC, 0xCC, 0x48, 0xF6, 0xEB, 0x7F, 0x21, 0xE0,
	0x0C, 0x93, 0xDA, 0x03, 0xB2, 0x1B, 0xF9, 0xE6,
	0x17, 0xC3, 0x68, 0xC1, 0x4B, 0x96, 0x38, 0x81,
};

// bign-curve128v1
static const char _curve128v1_name[] = "bign-curve128v1";

static const octet _curve128v1_p[16] = {
	0x53, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

static const octet _curve128v1_a[16] = {
	0x50, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

static const octet _curve128v1_b[16] = {
	0x8B, 0xDE, 0x1F, 0x8F, 0x64, 0xED, 0x49, 0x2D,
	0x3D, 0x78, 0xC2, 0x59, 0x0C, 0xE8, 0xB5, 0x74,
};

static const octet _curve128v1_seed[8] = {
	0xA0, 0x8A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const octet _curve128v1_q[16] = {
	0x09, 0x42, 0x37, 0xB3, 0xBA, 0xD1, 0xC7, 0xD2,
	0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

static const octet _curve128v1_yG[16] = {
	0xE3, 0xEF, 0x04, 0xA5, 0x25, 0xD1, 0x67, 0x04,
	0x55, 0xFC, 0xAC, 0x12, 0xE9, 0x75, 0x47, 0x0B,
};

// bign-curve64v1
static const char _curve64v1_name[] = "bign-curve64v1";

static const octet _curve64v1_p[8] = {
	0x43, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

static const octet _curve64v1_a[8] = {
	0x40, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

static const octet _curve64v1_b[8] = {
	0x1B, 0x1D, 0xA4, 0x03, 0x4D, 0x72, 0x42, 0x07,
};

static const octet _curve64v1_seed[8] = {
	0x1A, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const octet _curve64v1_q[8] = {
	0x7F, 0x4E, 0x79, 0x0C, 0xFF, 0xFF, 0xFF, 0xFF,
};

static const octet _curve64v1_yG[8] = {
	0x1B, 0xC6, 0xD2, 0xE7, 0x06, 0x49, 0x9B, 0xA7,
};

// bign-curve32v1
static const char _curve32v1_name[] = "bign-curve32v1";

static const octet _curve32v1_p[4] = {
	0xFB, 0xFF, 0xFF, 0xFF,
};

static const octet _curve32v1_a[4] = {
	0xF8, 0xFF, 0xFF, 0xFF,
};

static const octet _curve32v1_b[4] = {
	0xE5, 0xCE, 0xE8, 0x8B,
};

static const octet _curve32v1_seed[8] = {
	0x3A, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const octet _curve32v1_q[4] = {
	0x43, 0x65, 0xFE, 0xFF,
};

static const octet _curve32v1_yG[4] = {
	0x7C, 0x0D, 0x5F, 0x6B,
};

// bign-curve16v1
static const char _curve16v1_name[] = "bign-curve16v1";

static const octet _curve16v1_p[2] = {
	0xEF, 0xFF,
};

static const octet _curve16v1_a[2] = {
	0xEC, 0xFF,
};

static const octet _curve16v1_b[2] = {
	0x53, 0x44,
};

static const octet _curve16v1_seed[8] = {
	0x5C, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const octet _curve16v1_q[2] = {
	0xB3, 0xFE,
};

static const octet _curve16v1_yG[2] = {
	0x56, 0x9C,
};

// bign-curve8v1
static const char _curve8v1_name[] = "bign-curve8v1";

static const octet _curve8v1_p[1] = {
	0xFB,
};

static const octet _curve8v1_a[1] = {
	0xF8,
};

static const octet _curve8v1_b[1] = {
	0x3A,
};

static const octet _curve8v1_seed[8] = {
	0xAC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const octet _curve8v1_q[1] = {
	0xE5,
};

static const octet _curve8v1_yG[1] = {
	0x49,
};

/*
*******************************************************************************
Загрузка тестовых параметров
*******************************************************************************
*/

err_t bignTestParams(bign_params* params, const char* name)
{
	if (!memIsValid(params, sizeof(bign_params)))
		return ERR_BAD_INPUT;
	if (strEq(name, _curve192v1_name))
	{
		params->l = 96;
		memCopy(params->p, _curve192v1_p, 24);
		memCopy(params->a, _curve192v1_a, 24);
		memCopy(params->seed, _curve192v1_seed, 8);
		memCopy(params->b, _curve192v1_b, 24);
		memCopy(params->q, _curve192v1_q, 24);
		memCopy(params->yG, _curve192v1_yG, 24);
		return ERR_OK;
	}
	if (strEq(name, _curve128v1_name))
	{
		params->l = 64;
		memCopy(params->p, _curve128v1_p, 16);
		memCopy(params->a, _curve128v1_a, 16);
		memCopy(params->seed, _curve128v1_seed, 8);
		memCopy(params->b, _curve128v1_b, 16);
		memCopy(params->q, _curve128v1_q, 16);
		memCopy(params->yG, _curve128v1_yG, 16);
		return ERR_OK;
	}
	if (strEq(name, _curve64v1_name))
	{
		params->l = 32;
		memCopy(params->p, _curve64v1_p, 8);
		memCopy(params->a, _curve64v1_a, 8);
		memCopy(params->seed, _curve64v1_seed, 8);
		memCopy(params->b, _curve64v1_b, 8);
		memCopy(params->q, _curve64v1_q, 8);
		memCopy(params->yG, _curve64v1_yG, 8);
		return ERR_OK;
	}
	if (strEq(name, _curve32v1_name))
	{
		params->l = 16;
		memCopy(params->p, _curve32v1_p, 4);
		memCopy(params->a, _curve32v1_a, 4);
		memCopy(params->seed, _curve32v1_seed, 8);
		memCopy(params->b, _curve32v1_b, 4);
		memCopy(params->q, _curve32v1_q, 4);
		memCopy(params->yG, _curve32v1_yG, 4);
		return ERR_OK;
	}
	if (strEq(name, _curve16v1_name))
	{
		params->l = 8;
		memCopy(params->p, _curve16v1_p, 2);
		memCopy(params->a, _curve16v1_a, 2);
		memCopy(params->seed, _curve16v1_seed, 8);
		memCopy(params->b, _curve16v1_b, 2);
		memCopy(params->q, _curve16v1_q, 2);
		memCopy(params->yG, _curve16v1_yG, 2);
		return ERR_OK;
	}
	if (strEq(name, _curve8v1_name))
	{
		params->l = 4;
		memCopy(params->p, _curve8v1_p, 1);
		memCopy(params->a, _curve8v1_a, 1);
		memCopy(params->seed, _curve8v1_seed, 8);
		memCopy(params->b, _curve8v1_b, 1);
		memCopy(params->q, _curve8v1_q, 1);
		memCopy(params->yG, _curve8v1_yG, 1);
		return ERR_OK;
	}
	return ERR_FILE_NOT_FOUND;
}

/*
*******************************************************************************
Идентификатор объекта
*******************************************************************************
*/

err_t bignOidToDER(octet oid_der[], size_t* oid_len, const char* oid)
{
	size_t len;
	if (!strIsValid(oid) || 
		!memIsValid(oid_len, sizeof(size_t)) ||
		!memIsNullOrValid(oid_der, *oid_len))
		return ERR_BAD_INPUT;
	len = oidToDER(0, oid);
	if (len == SIZE_MAX)
		return ERR_BAD_OID;
	if (oid_der)
	{
		if (*oid_len < len)
			return ERR_OUTOFMEMORY;
		len = oidToDER(oid_der, oid);
		ASSERT(len != SIZE_MAX);
	}
	*oid_len = len;
	return ERR_OK;
}

