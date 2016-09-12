/*
*******************************************************************************
\file pfok.c
\brief Draft of RD_RB: key establishment protocols in finite fields
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2014.07.01
\version 2016.09.07
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/blob.h"
#include "bee2/core/err.h"
#include "bee2/core/mem.h"
#include "bee2/core/prng.h"
#include "bee2/core/str.h"
#include "bee2/core/util.h"
#include "bee2/crypto/pfok.h"
#include "bee2/math/pri.h"
#include "bee2/math/zm.h"
#include "bee2/math/ww.h"
#include "bee2/math/zz.h"

/*
*******************************************************************************
При генерации параметров pfok требуется находить простые числа, битовая длина 
которых лежит в интервале (16, 32]. Для этого используется функция 
priNextPrimeVal(), которая находит гарантированно простое число из одного 
машинного слова. Функция не подходит, если длина машинного слова равняется 16.

\todo Поддержать B_PER_W == 16.
*******************************************************************************
*/

#if (B_PER_W == 16)
	#error "Can't construct small primes"
#endif

/*
*******************************************************************************
Стандартные размерности
*******************************************************************************
*/
static u32 const _ls[] = 
{
	638, 702, 766, 862, 958, 1022, 1118, 
	1214, 1310, 1438, 1534, 1662, 1790, 1918, 
	2046, 2174, 2334, 2462, 2622, 2782, 2942, 
};

static u32 const _rs[] = 
{
	130, 136, 141, 149, 154, 161, 168,
	175, 181, 188, 194, 201, 208, 214,
	221, 225, 234, 240, 246, 253, 259, 
};

/*
*******************************************************************************
Тестовые параметры: методика ИЛ НИИ ППМИ
*******************************************************************************
*/

static const u32 _test_params_n = 256;

static const u16 _test_params_z[] = {
	40046, 43788,  1706, 57707, 58664,  8036, 56277, 12802, 
	22211, 49982, 39997,  7717,  7896, 18474, 58455,  3341, 
	30740, 54550, 18656, 61919, 54929, 55271, 27359, 45417, 
	54224, 30379, 40508, 57601, 27245, 54721,  4700,
};

static const char _test_params_name[] = "test";

static const u32 _test_params_l = 638;

static const u32 _test_params_r = 130;

static const octet _test_params_p[] = {
	0xDF, 0x60, 0x3F, 0xB4, 0xB1, 0xCB, 0x6B, 0xEB, 
	0xBE, 0xB8, 0x47, 0xA8, 0x70, 0x61, 0x37, 0x93,
	0x16, 0xAE, 0x3C, 0x66, 0xFA, 0x82, 0x8A, 0x6F,
	0x90, 0x05, 0x8A, 0x59, 0xBA, 0xE3, 0xDC, 0x65,
	0x80, 0x56, 0xB4, 0x67, 0xAE, 0x55, 0x59, 0x77,
	0x11, 0x12, 0x33, 0x3B, 0x0B, 0x3C, 0xF8, 0xF9,
	0x77, 0xE9, 0x7F, 0x51, 0xDC, 0xAE, 0x1F, 0x3C,
	0x3E, 0x0E, 0x6C, 0xE0, 0xFB, 0xFA, 0xD8, 0x9D,
	0x75, 0xB7, 0xF2, 0x4B, 0x3B, 0xE7, 0x37, 0xE1,
	0x75, 0xAB, 0xAA, 0x86, 0xAB, 0x91, 0xF7, 0x2A,
};

static const octet _test_params_g[] = {
	0xEA, 0x36, 0x50, 0x71, 0xE2, 0x10, 0x2E, 0x77,
	0x59, 0xB7, 0x21, 0x16, 0x69, 0xBC, 0xD6, 0x11,
	0xF6, 0x80, 0x58, 0x9A, 0x2B, 0x0E, 0xF9, 0xDC,
	0x96, 0x51, 0xF0, 0x0E, 0x85, 0xB0, 0x21, 0x8E,
	0xBD, 0xC1, 0xB1, 0xCC, 0x43, 0xF5, 0xD1, 0x12,
	0x8E, 0xDD, 0xA8, 0x19, 0x8D, 0xE7, 0x21, 0x5E,
	0x01, 0xF0, 0x6D, 0x2E, 0x3C, 0x35, 0x3B, 0xBA,
	0x7C, 0x99, 0x27, 0x45, 0x2F, 0x7F, 0x47, 0x50,
	0x28, 0x73, 0x4F, 0x54, 0x0A, 0xE9, 0x24, 0xDF,
	0xB8, 0x81, 0x33, 0xC5, 0x97, 0xD3, 0x43, 0x2A,
};

static const u32 _test_params_lt[] = {
	637, 319, 160, 81, 41, 21,
};

/*
*******************************************************************************
Стандартные параметры: приложение В к СТБ П 34.101.50
*******************************************************************************
*/

// bdh-params (common)
static const u32 _bdh_params_n = 256;

static const u16 _bdh_params_z[] = {
	1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 
	18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
};

// bdh-params3
static const char _bdh_params3_name[] = "1.2.112.0.2.0.1176.2.3.3.2";

static const u32 _bdh_params3_l = 1022;

static const u32 _bdh_params3_r = 161;

static const octet _bdh_params3_p[] = {
	0x6F, 0x5E, 0xBE, 0x31, 0xD7, 0x55, 0x76, 0x17,
	0x84, 0x3F, 0xC5, 0xAB, 0x4E, 0xC7, 0x67, 0xE0,
	0x6E, 0x42, 0xDE, 0xEA, 0x2C, 0x82, 0xBE, 0x7B,
	0x3F, 0xEA, 0xCB, 0xEC, 0xC4, 0x17, 0x07, 0x65,
	0x27, 0xB6, 0x04, 0xBF, 0xA6, 0x67, 0xE5, 0x2C,
	0x48, 0xD2, 0x19, 0xEC, 0xAB, 0x83, 0x16, 0x72,
	0x4F, 0x0B, 0xAB, 0x80, 0xD8, 0x10, 0x27, 0xB6,
	0x9C, 0x80, 0xB7, 0xE8, 0xA2, 0x14, 0xAB, 0x94,
	0x0E, 0x24, 0x0C, 0x05, 0x98, 0x9B, 0xC1, 0x4B,
	0xEE, 0x10, 0x05, 0x2B, 0xE7, 0xC2, 0x68, 0x78,
	0xAB, 0xE9, 0xEB, 0x51, 0x27, 0xCB, 0x9D, 0xA6,
	0x48, 0x6A, 0x7E, 0x5E, 0x5D, 0x1E, 0xFE, 0x77,
	0x66, 0xE5, 0x87, 0x6E, 0x34, 0x98, 0x66, 0x74,
	0x64, 0x3E, 0xB8, 0x42, 0x93, 0xE6, 0xE3, 0x4E,
	0x78, 0x9E, 0x50, 0x8B, 0x8C, 0x8C, 0xAF, 0x80,
	0xA4, 0x66, 0xF6, 0x38, 0xC5, 0x17, 0x96, 0x33,
};

static const octet _bdh_params3_g[] = {
	0x69, 0x4D, 0x08, 0xFB, 0x1D, 0x37, 0x1A, 0x1B,
	0x5C, 0xFB, 0x53, 0x95, 0xCD, 0x61, 0xCB, 0xE4,
	0x2E, 0x88, 0xFB, 0xA5, 0xEE, 0x3C, 0xC6, 0x03,
	0xFA, 0x45, 0x14, 0x99, 0x16, 0xB6, 0xCA, 0xD7,
	0xA6, 0xEC, 0x80, 0x2F, 0x64, 0x0A, 0x7D, 0x7A,
	0xEA, 0x41, 0x81, 0x6A, 0x02, 0x0C, 0x60, 0x9A,
	0xE7, 0x2B, 0xF0, 0xC3, 0xC3, 0xE1, 0x7D, 0xD4,
	0x13, 0x78, 0xEB, 0x85, 0xC2, 0xFF, 0xE6, 0xC7,
	0x39, 0x5F, 0x46, 0x80, 0xB5, 0x56, 0x98, 0xAC,
	0x25, 0xE7, 0xCE, 0x34, 0xA4, 0x49, 0x83, 0x54,
	0xF3, 0xE6, 0x72, 0xC2, 0x8B, 0xE4, 0x8C, 0xCD,
	0xD8, 0x4C, 0x82, 0x58, 0x1F, 0x54, 0x17, 0xFF,
	0x6C, 0x5E, 0x06, 0x18, 0xC4, 0x80, 0x58, 0x67,
	0x3B, 0xB5, 0x10, 0x0F, 0xA3, 0x11, 0x87, 0x69,
	0xD8, 0xD3, 0xEE, 0xA2, 0xA0, 0xBC, 0x0D, 0x69,
	0xC8, 0xFE, 0xDC, 0x50, 0xD3, 0x3A, 0x2A, 0x32,
};

static const u32 _bdh_params3_lt[] = {
	1021, 511, 256, 129, 65, 33, 17,
};

// bdh-params6
static const char _bdh_params6_name[] = "1.2.112.0.2.0.1176.2.3.6.2";

static const u32 _bdh_params6_l = 1534;

static const u32 _bdh_params6_r = 194;

static const octet _bdh_params6_p[] = {
	0xC7, 0x51, 0x14, 0x7B, 0xED, 0x69, 0xF4, 0x2D,
	0x32, 0x5F, 0xB1, 0x45, 0x0A, 0x66, 0xAF, 0xA5,
	0x34, 0xE1, 0xBF, 0x35, 0x42, 0xCB, 0xBF, 0x36,
	0xB5, 0x14, 0x2E, 0xF6, 0x64, 0x17, 0xF5, 0x2D,
	0x42, 0x2E, 0x3F, 0x7A, 0x35, 0x7E, 0xF2, 0xAC,
	0x1B, 0xBF, 0xB8, 0xAA, 0xA7, 0x69, 0xB1, 0xF0,
	0x49, 0x1B, 0x46, 0x61, 0xFA, 0x8F, 0xE0, 0xC7,
	0x0F, 0x40, 0x94, 0xF8, 0x28, 0x73, 0x19, 0xFA,
	0x2E, 0x95, 0x40, 0x05, 0x22, 0xC8, 0x85, 0xD9,
	0x3B, 0x70, 0x0F, 0x58, 0x1B, 0xBE, 0xC1, 0xDC,
	0x4C, 0xC7, 0xEC, 0xCF, 0xB4, 0x3C, 0x04, 0x79,
	0x3A, 0x25, 0x9A, 0x2E, 0x6F, 0xFA, 0x3E, 0x8C,
	0x1A, 0x06, 0xA8, 0x9F, 0x96, 0x88, 0x38, 0xBB,
	0x74, 0xA5, 0x77, 0xC3, 0x0D, 0x09, 0x57, 0x45,
	0x74, 0x08, 0x97, 0x44, 0xA1, 0xF4, 0x7C, 0xE0,
	0x98, 0x85, 0xD2, 0x46, 0x24, 0x82, 0x1D, 0xA0,
	0xAD, 0x39, 0xE6, 0x77, 0xF4, 0x5C, 0x00, 0xE0,
	0x9E, 0x92, 0x06, 0x6B, 0x2B, 0xAD, 0xE0, 0xCB,
	0x66, 0xD2, 0x02, 0xCC, 0xAD, 0x51, 0xEB, 0xE1,
	0x1F, 0xE9, 0x4D, 0xB1, 0x30, 0x65, 0xBF, 0xBB,
	0x94, 0x55, 0xE7, 0x58, 0x61, 0xAA, 0x78, 0x78,
	0x1C, 0x5E, 0x6C, 0xB5, 0x88, 0xCA, 0x4E, 0xD5,
	0x50, 0x3A, 0xDF, 0x8C, 0xD4, 0x4B, 0x05, 0x2D,
	0xA5, 0xF5, 0xA9, 0x6B, 0x50, 0x1F, 0x7C, 0x39,
};

static const octet _bdh_params6_g[] = {
	0xB2, 0x85, 0x48, 0xF3, 0x48, 0xEB, 0xE7, 0x5A,
	0xBD, 0x23, 0xCE, 0x48, 0xB7, 0x2E, 0x92, 0xC5,
	0x78, 0x0F, 0x74, 0xC2, 0xD7, 0xDF, 0x35, 0x1D,
	0x76, 0x31, 0x54, 0x3F, 0xEE, 0x2C, 0x40, 0xB4,
	0xE2, 0x9B, 0x5E, 0x7B, 0x94, 0xF9, 0x34, 0xD8,
	0xA1, 0xD8, 0x71, 0x5E, 0x25, 0xC5, 0x21, 0xE4,
	0xCE, 0xFC, 0xA4, 0x13, 0x22, 0xDF, 0x78, 0x8C,
	0x6A, 0x71, 0xFD, 0x64, 0x4E, 0xE5, 0x74, 0x60,
	0x1B, 0xCC, 0x01, 0xEC, 0x99, 0xF6, 0xCE, 0x18,
	0xE2, 0x53, 0x4D, 0xA0, 0xA6, 0x85, 0x4B, 0xF6,
	0xC8, 0xC6, 0xF9, 0xB0, 0x59, 0x3E, 0x31, 0x3A,
	0x1A, 0x20, 0x6D, 0xB7, 0xB7, 0xC6, 0x54, 0x45,
	0xA3, 0x00, 0xB1, 0x33, 0x06, 0x09, 0x2B, 0x97,
	0x0D, 0xD7, 0x98, 0xC7, 0x32, 0x15, 0xC5, 0x3A,
	0x97, 0xD3, 0xB4, 0xAF, 0xE1, 0xF9, 0x25, 0x08,
	0xD1, 0xE5, 0x22, 0x13, 0x56, 0xAD, 0x88, 0xD2,
	0xCD, 0xA0, 0xD7, 0x73, 0xD9, 0x62, 0x76, 0xC1,
	0x47, 0x50, 0xBF, 0x1E, 0xD8, 0x7D, 0x58, 0x8B,
	0xC7, 0xC5, 0x47, 0xEE, 0xB7, 0x57, 0xA9, 0xC3,
	0xAF, 0x25, 0xC8, 0x7B, 0x8F, 0x13, 0x3A, 0x3C,
	0xFD, 0x6F, 0x7D, 0xEE, 0x66, 0xF7, 0xD0, 0x9A,
	0xCC, 0xA7, 0xCB, 0xB3, 0x0B, 0x4D, 0xDA, 0x41,
	0xB4, 0x21, 0x84, 0xF9, 0xBD, 0xF4, 0xE3, 0x6B,
	0xEF, 0x90, 0x3E, 0x5E, 0xB6, 0xA8, 0xE7, 0x24,
};

static const u32 _bdh_params6_lt[] = {
	1533, 767, 384, 193, 97, 49, 25,
};

// bdh-params10
static const char _bdh_params10_name[] = "1.2.112.0.2.0.1176.2.3.10.2";

static const u32 _bdh_params10_l = 2462;

static const u32 _bdh_params10_r = 240;

static const octet _bdh_params10_p[] = {
	0xDB, 0x80, 0x4A, 0x65, 0x29, 0x2D, 0x15, 0x9C,
	0x56, 0xF9, 0x99, 0x47, 0x65, 0xAE, 0x74, 0xFC,
	0xE1, 0xE8, 0x0C, 0x12, 0x3E, 0x82, 0xBB, 0x75,
	0x20, 0xE2, 0x33, 0x17, 0xD8, 0x03, 0xA6, 0x6A,
	0x90, 0x8C, 0x5E, 0x94, 0x39, 0x65, 0x08, 0xA6,
	0x92, 0x7F, 0x4A, 0xC6, 0x38, 0x33, 0xDF, 0x8E,
	0xA6, 0x1A, 0x08, 0x23, 0xB8, 0x29, 0xFA, 0x3A,
	0x33, 0xC6, 0xC8, 0x27, 0x58, 0xA4, 0xFE, 0x4D,
	0xED, 0x1F, 0xDE, 0x37, 0x36, 0x84, 0x93, 0x68,
	0x0B, 0x68, 0xE6, 0xA9, 0x5E, 0x07, 0xBF, 0x1C,
	0xE0, 0x16, 0xAE, 0x73, 0xAE, 0x92, 0xAD, 0x2D,
	0x0D, 0xC4, 0xE0, 0xF5, 0x39, 0x7B, 0x41, 0xF1,
	0xFC, 0xBA, 0x14, 0x09, 0x8F, 0xA0, 0xFD, 0x21,
	0x05, 0xB0, 0xD3, 0x8E, 0x63, 0xB5, 0x2F, 0x3A,
	0xDE, 0x4B, 0x20, 0x36, 0xC3, 0xEC, 0xCD, 0x9A,
	0xEF, 0x52, 0xE4, 0xA8, 0x56, 0x13, 0x00, 0xC4,
	0xD5, 0x3C, 0x9A, 0x37, 0x08, 0x5B, 0xE9, 0xF8,
	0x52, 0xBF, 0x29, 0xF4, 0x97, 0x85, 0x64, 0x42,
	0x69, 0x45, 0x50, 0x41, 0xE6, 0x47, 0x56, 0xFF,
	0xA6, 0xA3, 0xB2, 0xD9, 0x75, 0x9B, 0x01, 0x0C,
	0x11, 0xDD, 0x63, 0xE1, 0x5F, 0x2E, 0x46, 0xA8,
	0xD1, 0xA1, 0x36, 0x39, 0xC1, 0xA3, 0x6F, 0x51,
	0xB4, 0xB9, 0xF6, 0x53, 0x26, 0x9F, 0xF9, 0xDC,
	0xF2, 0x11, 0x27, 0x4E, 0xC1, 0x70, 0xF4, 0x1F,
	0xEE, 0x33, 0x74, 0xAF, 0x40, 0xAE, 0x58, 0xA3,
	0x5B, 0xD0, 0xAB, 0x66, 0x7F, 0x26, 0x39, 0x51,
	0xDF, 0xB6, 0x8B, 0xB6, 0xF0, 0xAD, 0xB1, 0xE5,
	0x3B, 0x02, 0x72, 0xB7, 0x8E, 0xA4, 0xD7, 0xF6,
	0x2D, 0x05, 0x38, 0x3D, 0xE5, 0x34, 0x8D, 0x21,
	0x87, 0x23, 0x7D, 0xEB, 0xA1, 0x3D, 0xF3, 0x22,
	0xDA, 0xF1, 0xE4, 0x2D, 0xCF, 0x42, 0x69, 0x1C,
	0x96, 0x54, 0x10, 0x16, 0xB1, 0xF4, 0xEA, 0x94,
	0x9C, 0xED, 0x31, 0x46, 0x7F, 0x8F, 0x1F, 0x93,
	0x9B, 0x59, 0x4A, 0x69, 0xEC, 0x92, 0x92, 0x9B,
	0xA9, 0xB6, 0x0A, 0xD8, 0x3A, 0xED, 0x0F, 0x23,
	0x08, 0x8C, 0xDD, 0xA0, 0x12, 0xAD, 0xC0, 0x26,
	0xEE, 0x65, 0xC3, 0xD0, 0x38, 0x6B, 0x20, 0xAA,
	0xA0, 0x13, 0x8F, 0xAF, 0x6F, 0xC2, 0x81, 0xEA,
	0x85, 0xF4, 0xA8, 0x20,
};

static const octet _bdh_params10_g[] = {
	0x14, 0xE1, 0x96, 0x49, 0x7C, 0x27, 0xCD, 0x04, 
	0x2E, 0xF3, 0x32, 0x7B, 0x74, 0x12, 0x2C, 0xDE,
	0x04, 0xF8, 0xE6, 0x30, 0x2E, 0xB5, 0x25, 0x2A, 
	0x39, 0xBC, 0x4A, 0x90, 0xD7, 0xE0, 0x98, 0x97,
	0xF9, 0xF4, 0xFD, 0xFD, 0x97, 0x96, 0xBF, 0xD7, 
	0x50, 0xA9, 0x51, 0x74, 0x6D, 0x40, 0xA0, 0xD7,
	0x5F, 0x6A, 0xC6, 0x10, 0x3B, 0xAF, 0xB8, 0x51, 
	0xDA, 0xD5, 0x19, 0x0F, 0xD9, 0x66, 0xF4, 0x4E,
	0xA6, 0x96, 0x5C, 0x33, 0x38, 0x88, 0xA6, 0x9B, 
	0x80, 0xCE, 0x13, 0xAE, 0xBF, 0x87, 0x63, 0x44,
	0xF4, 0x6E, 0x44, 0x6D, 0x7C, 0x96, 0x32, 0x3B, 
	0xD9, 0xDD, 0x64, 0x84, 0xE2, 0x30, 0x5E, 0x94,
	0x19, 0x9C, 0x67, 0xC4, 0xFB, 0xB7, 0x53, 0x38, 
	0x57, 0x55, 0xD5, 0x94, 0x7A, 0x08, 0xD6, 0x48,
	0xA9, 0x7A, 0xF8, 0x74, 0xF4, 0x03, 0x6A, 0x01, 
	0x67, 0x2E, 0xEB, 0x54, 0x9F, 0x04, 0xF7, 0xB5,
	0x0A, 0xCF, 0x6D, 0xAA, 0x7C, 0x7E, 0x70, 0x96, 
	0x32, 0xBA, 0x20, 0x16, 0x65, 0xB4, 0x6A, 0xFC,
	0xB6, 0xDD, 0xC4, 0x58, 0x8A, 0xB0, 0x1B, 0x3A, 
	0x09, 0xC7, 0xD9, 0x7B, 0x67, 0x96, 0xEF, 0x0A,
	0x94, 0x38, 0x17, 0x4C, 0xF1, 0x11, 0x8F, 0x8C,
	0xCC, 0x6F, 0x27, 0x95, 0x9A, 0x7C, 0x9A, 0xC2,
	0xC0, 0x92, 0x3B, 0x87, 0x00, 0xB9, 0xAE, 0x1F,
	0x2B, 0xE6, 0xB3, 0xDD, 0xB5, 0xDB, 0xC8, 0x5A,
	0x6C, 0xD2, 0x3F, 0xE3, 0x69, 0x41, 0xCD, 0x1E,
	0x04, 0x6A, 0x6C, 0x48, 0x71, 0x22, 0x82, 0xAB,
	0xD4, 0x52, 0x55, 0x4F, 0x84, 0xF5, 0x96, 0x13,
	0x9F, 0xBA, 0xBB, 0x67, 0x8D, 0x39, 0x26, 0xE5,
	0x58, 0x4E, 0x4C, 0x28, 0x0C, 0x18, 0xB2, 0xC2,
	0x49, 0xF2, 0x35, 0x91, 0x03, 0x9E, 0x46, 0xA9,
	0x86, 0xA8, 0x29, 0x8D, 0x76, 0x52, 0x57, 0x97,
	0x7C, 0x54, 0x0F, 0x11, 0x23, 0x88, 0x3D, 0x87,
	0xC9, 0x2B, 0x34, 0x7E, 0xB9, 0x41, 0x02, 0xD9,
	0xA5, 0x0A, 0xE6, 0x0C, 0x10, 0x8D, 0x3E, 0x61,
	0x73, 0x3D, 0x41, 0x6D, 0x82, 0x8E, 0x8F, 0x84,
	0x96, 0xAD, 0x42, 0x9A, 0x75, 0xB6, 0xE2, 0x26,
	0x95, 0xF1, 0x79, 0xED, 0x94, 0x4B, 0x2E, 0x44,
	0x01, 0x06, 0x45, 0x62, 0x57, 0x39, 0xC2, 0xFA,
	0xE5, 0x64, 0x83, 0x03,
};

static const u32 _bdh_params10_lt[] = {
	2461, 1231, 616, 309, 155, 78, 40, 21,
};

/*
*******************************************************************************
Загрузка стандартных параметров
*******************************************************************************
*/

err_t pfokStdParams(pfok_params* params, pfok_seed* seed, const char* name)
{
	if (!memIsValid(params, sizeof(pfok_params)) ||
		!memIsNullOrValid(seed, sizeof(pfok_seed)))
		return ERR_BAD_INPUT;
	// подготовить params
	memSetZero(params, sizeof(pfok_params));
	// найти params
	if (strEq(name, _test_params_name))
	{
		params->l = _test_params_l;
		params->r = _test_params_r;
		params->n = _test_params_n;
		memCopy(params->p, _test_params_p, sizeof(_test_params_p));
		memCopy(params->g, _test_params_g, sizeof(_test_params_g));
		if (seed)
		{
			memCopy(seed->z, _test_params_z, sizeof(_test_params_z));
			memCopy(seed->lt, _test_params_lt, sizeof(_test_params_lt));
		}
		return ERR_OK;
	}
	if (strEq(name, _bdh_params3_name))
	{
		params->l = _bdh_params3_l;
		params->r = _bdh_params3_r;
		params->n = _bdh_params_n;
		memCopy(params->p, _bdh_params3_p, sizeof(_bdh_params3_p));
		memCopy(params->g, _bdh_params3_g, sizeof(_bdh_params3_g));
		if (seed)
		{
			memCopy(seed->z, _bdh_params_z, sizeof(_bdh_params_z));
			memCopy(seed->lt, _bdh_params3_lt, sizeof(_bdh_params3_lt));
		}
		return ERR_OK;
	}
	if (strEq(name, _bdh_params6_name))
	{
		params->l = _bdh_params6_l;
		params->r = _bdh_params6_r;
		params->n = _bdh_params_n;
		memCopy(params->p, _bdh_params6_p, sizeof(_bdh_params6_p));
		memCopy(params->g, _bdh_params6_g, sizeof(_bdh_params6_g));
		if (seed)
		{
			memCopy(seed->z, _bdh_params_z, sizeof(_bdh_params_z));
			memCopy(seed->lt, _bdh_params6_lt, sizeof(_bdh_params6_lt));
		}
		return ERR_OK;
	}
	if (strEq(name, _bdh_params10_name))
	{
		params->l = _bdh_params10_l;
		params->r = _bdh_params10_r;
		params->n = _bdh_params_n;
		memCopy(params->p, _bdh_params10_p, sizeof(_bdh_params10_p));
		memCopy(params->g, _bdh_params10_g, sizeof(_bdh_params10_g));
		if (seed)
		{
			memCopy(seed->z, _bdh_params_z, sizeof(_bdh_params_z));
			memCopy(seed->lt, _bdh_params10_lt, sizeof(_bdh_params10_lt));
		}
		return ERR_OK;
	}
	return ERR_FILE_NOT_FOUND;
}

/*
*******************************************************************************
Работоспособные параметры?

Не проверяется простота p и q и примитивность g. Проверяется только то, что
1)	битовая длина p равняется l;
2)	p \equiv 3 \mod 4;
3)	0 < g < p.
*******************************************************************************
*/

static bool_t pfokIsOperableParams(const pfok_params* params)
{
	size_t n;
	ASSERT(memIsValid(params, sizeof(pfok_params)));
	// проверить размерности
	for (n = 0; n < COUNT_OF(_ls); ++n)
		if (_ls[n] == params->l)
			break;
	if (n == COUNT_OF(_ls) || _rs[n] != params->r || params->n >= params->l)
		return FALSE;
	// проверить p (младшие два бита -- 11? старшие 3 бита -- 001?)
	ASSERT((params->l + 2) % 8 == 0);
	n = O_OF_B(params->l);
	if (params->p[0] % 4 != 3 || params->p[n - 1] / 32 != 1)
		return FALSE;
	// проверить g
	return !memIsZero(params->g, n) && memCmp(params->g, params->p, n) < 0;
}

/*
*******************************************************************************
Генерация параметров

Строится число q битовой длины l - 1, а затем проверяется, что p = 2q + 1
является простым. Если p составное, то строится новое q и так далее. 
Подходящее простое q называется простым Софи Жермен.

\remark Известна эвристика: имеется \approx 1.32 n / (\log n)^2 простых Жермен,
не превосходящих n. С другой стороны, имеется \approx n / \log n простых, 
не превосходящих n. Поэтому случайное простое q, не превосходящее n, 
окажется простым Жермен с вероятностью близкой к 1.32 / \log n. 
Отсюда среднее число кандидатов q:
\log n / 1.32 \approx 0.52 l. 

Статистика генерации стандартных параметров:
------------------------------------------------------------------
параметры                     | l    | число кандидатов  | оценка
------------------------------------------------------------------
"test"                        | 638  | 6                 | 332   
"1.2.112.0.2.0.1176.2.3.3.2"  | 1022 | 582               | 531
"1.2.112.0.2.0.1176.2.3.6.2"  | 1534 | 274               | 798  
"1.2.112.0.2.0.1176.2.3.10.2" | 2462 | 415               | 1280 
------------------------------------------------------------------

Проверка примитивности g:
g^(q) \neq e => g^(q) == - e
g^(2) \neq e => g == e или g == -e
*******************************************************************************
*/

err_t pfokGenParams(pfok_params* params, const pfok_seed* seed, 
	pfok_on_q_i on_q)
{
	size_t num = 0;
	size_t i;
	size_t no, n;
	size_t offset;
	const u32* lt;
	// состояние 
	void* state;
	octet* stb_state;
	word* qi;
	word* p;
	word* g;
	qr_o* qr;
	void* stack;
	// проверить указатели
	if (!memIsValid(params, sizeof(pfok_params)) ||
		!memIsValid(seed, sizeof(pfok_seed)))
		return ERR_BAD_INPUT;
	// подготовить params
	memSetZero(params, sizeof(pfok_params));
	// проверить числа z[i]
	for (i = 0; i < 31; ++i)
		if (seed->z[i] == 0 || seed->z[i] >= 65257)
			return ERR_BAD_PARAMS;
	// проверить цепочку lt[i] и одновременно зафиксировать размерности
	for (i = 0, lt = seed->lt; i < COUNT_OF(_ls); ++i)
		if (lt[0] == _ls[i] - 1)
			break;
	if (i == COUNT_OF(_ls))
		return ERR_BAD_PARAMS;
	params->l = _ls[i], params->r = _rs[i], params->n = 256;
	for (i = 1, offset = W_OF_B(lt[0]); lt[i] > 32; ++i)
	{
		if (lt[i - 1] > 2 * lt[i] || 5 * lt[i] + 16 >= 4 * lt[i - 1])
			return ERR_BAD_PARAMS;
		offset += W_OF_B(lt[i]);
	}
	ASSERT(lt[i] > 16);
	// размерности
	no = O_OF_B(params->l), n = W_OF_B(params->l);
	// создать состояние
	state = blobCreate(
		prngSTB_keep() + O_OF_W(offset) + O_OF_B(lt[i]) + 
		O_OF_W(n) +	zmMontCreate_keep(no) +
		utilMax(6,
			priNextPrimeW_deep(),
			priExtendPrime_deep(params->l, n, (lt[0] + 3) / 4),
			priIsSieved_deep((lt[0] + 3) / 4),
			priIsSGPrime_deep(n),
			zmMontCreate_deep(no), 
			qrPower_deep(n, n, zmMontCreate_deep(no))));
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// раскладка состояния
	stb_state = (octet*)state;
	qi = (word*)(stb_state + prngSTB_keep());
	p = qi + offset + W_OF_B(lt[i]);
	qr = (qr_o*)(p + n);
	stack = (octet*)qr + zmMontCreate_keep(no);
	// запустить генератор
	prngSTBStart(stb_state, seed->z);
	// основной цикл
	while (1)
	{
		// первое (минимальное) простое?
		if (lt[i] <= 32)
		{
			do
			{
				prngSTBStepR(qi + offset, O_OF_B(lt[i]), stb_state);
				wwTrimHi(qi + offset, W_OF_B(lt[i]), lt[i] - 1);
				wwSetBit(qi + offset, lt[i] - 1, 1);
			}
			while (!priNextPrimeW(qi + offset, qi[offset], stack));
			// к следующему простому
			offset -= W_OF_B(lt[--i]);
		}
		// обычное простое
		else
		{
			size_t trials = (i == 0) ? 4 * lt[i] * lt[i] : 4 * lt[i];
			size_t base_count = (lt[i] + 3) / 4;
			// потенциальное отступление от Проекта, не влияющее на результат
			if (base_count > priBaseSize())
				base_count = priBaseSize();
			// не удается построить новое простое?
			if (!priExtendPrime(qi + offset, lt[i], 
					qi + offset + W_OF_B(lt[i]), W_OF_B(lt[i + 1]), 
					trials, base_count, prngSTBStepR, stb_state, stack))
			{
				// к предыдущему простому
				offset += W_OF_B(lt[i++]);
				continue;
			}
			// не последнее простое?
			if (i > 0)
			{
				// к следующему простому
				offset -= W_OF_B(lt[--i]);
				continue;
			}
			// обработать нового кандидата
			on_q ? on_q(qi, W_OF_B(lt[0]), ++num) : 0;
			// p <- 2q_0 + 1
			ASSERT(W_OF_B(lt[0]) == n);
			wwCopy(p, qi, n);
			wwShHi(p, n, 1);
			p[0] |= 1;
			// p -- простое?
			if (priIsSieved(p, n, base_count, stack) && 
				priIsSGPrime(qi, n, stack))
				break;
		}
	}
	// сохранить p
	wwTo(params->p, no, p);
	// построить кольцо Монтгомери
	zmMontCreate(qr, params->p, no, params->l + 2, stack);
	// сгенерировать g
	g = qi + W_OF_B(lt[0]);
	do
	{
		// g <- g + 1
		for (i = 0; i < no && ++params->g[i] == 0;);
		// p <- g^(q) [p == e или p == -e]
		qrFrom(g, params->g, qr, stack);
		qrPower(p, g, qi, W_OF_B(lt[0]), qr, stack);
	}
	while (qrIsUnity(p, qr) || qrIsUnity(g, qr) || qrCmp(p, g, qr) == 0);
	// все нормально
	blobClose(state);
	return ERR_OK;
}

err_t pfokValParams(const pfok_params* params)
{
	size_t no, n;
	// состояние 
	void* state;
	word* p;
	word* g;
	qr_o* qr;
	void* stack;
	// проверить указатели
	if (!memIsValid(params, sizeof(pfok_params)))
		return ERR_BAD_INPUT;
	// работоспособные параметры?
	if (!pfokIsOperableParams(params))
		return ERR_BAD_PARAMS;
	// размерности
	no = O_OF_B(params->l), n = W_OF_B(params->l);
	// создать состояние
	state = blobCreate(
		2 * O_OF_W(n) + zmMontCreate_keep(no) +  
		utilMax(3,
			priIsPrime_deep(n),
			zmMontCreate_deep(no),
			qrPower_deep(n, n, zmMontCreate_deep(no))));
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// раскладка состояния
	p = (word*)state;
	g = p + n;
	qr = (qr_o*)(g + n);
	stack = (octet*)qr + zmMontCreate_keep(no);
	// p -- простое?
	wwFrom(p, params->p, no);
	if (!priIsPrime(p, n, stack))
	{
		blobClose(state);
		return ERR_BAD_PARAMS;
	}
	// q -- простое?
	wwShLo(p, n, 1);
	if (!priIsPrime(p, n, stack))
	{
		blobClose(state);
		return ERR_BAD_PARAMS;
	}
	// построить кольцо Монтгомери
	zmMontCreate(qr, params->p, no, params->l + 2, stack);
	// проверить g
	qrFrom(g, params->g, qr, stack);
	qrPower(p, g, p, W_OF_B(params->l - 1), qr, stack);
	if (qrIsUnity(p, qr) || qrIsUnity(g, qr) || qrCmp(p, g, qr) == 0)
	{
		blobClose(state);
		return ERR_BAD_PARAMS;
	}
	// все нормально
	blobClose(state);
	return ERR_OK;
}

/*
*******************************************************************************
Управление ключами
*******************************************************************************
*/

err_t pfokGenKeypair(octet privkey[], octet pubkey[], 
	const pfok_params* params, gen_i rng, void* rng_state)
{
	size_t no, n;
	size_t mo, m;
	// состояние
	void* state;
	word* x;				/* [m] личный ключ */
	word* y;				/* [n] открытый ключ */
	qr_o* qr;				/* описание кольца Монтгомери */
	void* stack;
	// проверить params
	if (!memIsValid(params, sizeof(pfok_params)))
		return ERR_BAD_INPUT;
	// работоспособные параметры?
	if (!pfokIsOperableParams(params))
		return ERR_BAD_PARAMS;
	// размерности
	no = O_OF_B(params->l), n = W_OF_B(params->l);
	mo = O_OF_B(params->r), m = W_OF_B(params->r);
	// проверить остальные входные данные
	if (!memIsValid(privkey, mo) || !memIsValid(pubkey, no) || rng == 0)
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(
		O_OF_W(n) + O_OF_W(m) + zmMontCreate_keep(no) +  
		utilMax(2,
			zmMontCreate_deep(no),
			qrPower_deep(n, n, zmMontCreate_deep(no))));
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// раскладка состояния
	x = (word*)state;
	y = x + m;
	qr = (qr_o*)(y + n);
	stack = (octet*)qr + zmMontCreate_keep(no);
	// построить кольцо Монтгомери
	zmMontCreate(qr, params->p, no, params->l + 2, stack);
	// x <-R {0, 1,..., 2^r - 1}
	rng(x, mo, rng_state);
	wwFrom(x, x, mo);
	wwTrimHi(x, m, params->r);
	// y <- g^(x)
	wwFrom(y, params->g, no);
	qrPower(y, y, x, m, qr, stack);
	// выгрузить ключи
	wwTo(privkey, mo, x);
	qrTo(pubkey, y, qr, stack);
	// все нормально
	blobClose(state);
	return ERR_OK;
}

err_t pfokValPubkey(const pfok_params* params, const octet pubkey[])
{
	size_t no;
	// проверить params
	if (!memIsValid(params, sizeof(pfok_params)))
		return ERR_BAD_INPUT;
	// работоспособные параметры?
	if (!pfokIsOperableParams(params))
		return ERR_BAD_PARAMS;
	// размерности
	no = O_OF_B(params->l);
	// проверить остальные входные данные
	if (!memIsValid(pubkey, no))
		return ERR_BAD_INPUT;
	// 0 < pubkey < p?
	if (memIsZero(pubkey, no) || memCmp(pubkey, params->p, no) >= 0)
		return ERR_BAD_PUBKEY;
	// все нормально
	return ERR_OK;
}

err_t pfokCalcPubkey(octet pubkey[], const pfok_params* params, 
	const octet privkey[])
{
	size_t no, n;
	size_t mo, m;
	// состояние
	void* state;
	word* x;				/* [m] личный ключ */
	word* y;				/* [n] открытый ключ */
	qr_o* qr;				/* описание кольца Монтгомери */
	void* stack;
	// проверить params
	if (!memIsValid(params, sizeof(pfok_params)))
		return ERR_BAD_INPUT;
	// работоспособные параметры?
	if (!pfokIsOperableParams(params))
		return ERR_BAD_PARAMS;
	// размерности
	no = O_OF_B(params->l), n = W_OF_B(params->l);
	mo = O_OF_B(params->r), m = W_OF_B(params->r);
	// проверить остальные входные данные
	if (!memIsValid(privkey, mo) || !memIsValid(pubkey, no))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(
		O_OF_W(n) + O_OF_W(m) + zmMontCreate_keep(no) +  
		utilMax(2,
			zmMontCreate_deep(no),
			qrPower_deep(n, n, zmMontCreate_deep(no))));
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// раскладка состояния
	x = (word*)state;
	y = x + m;
	qr = (qr_o*)(y + n);
	stack = (octet*)qr + zmMontCreate_keep(no);
	// построить кольцо Монтгомери
	zmMontCreate(qr, params->p, no, params->l + 2, stack);
	// x <- privkey
	wwFrom(x, privkey, mo);
	if (wwGetBits(x, params->r, B_OF_W(m) - params->r) != 0)
	{
		blobClose(state);
		return ERR_BAD_PRIVKEY;
	}
	// y <- g^(x)
	wwFrom(y, params->g, no);
	qrPower(y, y, x, m, qr, stack);
	// выгрузить открытый ключ
	qrTo(pubkey, y, qr, stack);
	// все нормально
	blobClose(state);
	return ERR_OK;
}

/*
*******************************************************************************
Протоколы
*******************************************************************************
*/

err_t pfokDH(octet sharekey[], const pfok_params* params, 
	const octet privkey[], const octet pubkey[])
{
	size_t no, n;
	size_t mo, m;
	// состояние
	void* state;
	word* x;				/* [m] личный ключ */
	word* y;				/* [n] открытый ключ визави */
	qr_o* qr;				/* описание кольца Монтгомери */
	void* stack;
	// проверить params
	if (!memIsValid(params, sizeof(pfok_params)))
		return ERR_BAD_INPUT;
	// работоспособные параметры?
	if (!pfokIsOperableParams(params))
		return ERR_BAD_PARAMS;
	// размерности
	no = O_OF_B(params->l), n = W_OF_B(params->l);
	mo = O_OF_B(params->r), m = W_OF_B(params->r);
	// проверить остальные входные данные
	if (!memIsValid(privkey, mo) || 
		!memIsValid(pubkey, no) ||
		!memIsValid(sharekey, O_OF_B(params->n)))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(
		O_OF_W(n) + O_OF_W(m) + zmMontCreate_keep(no) +  
		utilMax(2,
			zmMontCreate_deep(no),
			qrPower_deep(n, n, zmMontCreate_deep(no))));
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// раскладка состояния
	x = (word*)state;
	y = x + m;
	qr = (qr_o*)(y + n);
	stack = (octet*)qr + zmMontCreate_keep(no);
	// построить кольцо Монтгомери
	zmMontCreate(qr, params->p, no, params->l + 2, stack);
	// x <- privkey
	wwFrom(x, privkey, mo);
	if (wwGetBits(x, params->r, B_OF_W(m) - params->r) != 0)
	{
		blobClose(state);
		return ERR_BAD_PRIVKEY;
	}
	// y <- pubkey
	wwFrom(y, pubkey, no);
	if (wwIsZero(y, n) || wwCmp(y, qr->mod, n) >= 0)
	{
		blobClose(state);
		return ERR_BAD_PUBKEY;
	}
	qrPower(y, y, x, m, qr, stack);
	// выгрузить открытый ключ
	qrTo((octet*)y, y, qr, stack);
	memCopy(sharekey, y, O_OF_B(params->n));
	if (params->n % 8)
		sharekey[params->n / 8] &= (octet)255 >> (8 - params->n % 8);
	// все нормально
	blobClose(state);
	return ERR_OK;
}

err_t pfokMTI(octet sharekey[], const pfok_params* params, 
	const octet privkey[], const octet privkey1[], 
	const octet pubkey[], const octet pubkey1[])
{
	size_t no, n;
	size_t mo, m;
	// состояние
	void* state;
	word* x;				/* [m] личный ключ */
	word* u;				/* [m] одноразовый личный ключ */
	word* y;				/* [n] открытый ключ визави */
	word* v;				/* [n] одноразовый открытый ключ визави */
	qr_o* qr;				/* описание кольца Монтгомери */
	void* stack;
	// проверить params
	if (!memIsValid(params, sizeof(pfok_params)))
		return ERR_BAD_INPUT;
	// работоспособные параметры?
	if (!pfokIsOperableParams(params))
		return ERR_BAD_PARAMS;
	// размерности
	no = O_OF_B(params->l), n = W_OF_B(params->l);
	mo = O_OF_B(params->r), m = W_OF_B(params->r);
	// проверить остальные входные данные
	if (!memIsValid(privkey, mo) || 
		!memIsValid(privkey1, mo) || 
		!memIsValid(pubkey, no) ||
		!memIsValid(pubkey1, no) ||
		!memIsValid(sharekey, O_OF_B(params->n)))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(
		2 * O_OF_W(n) + 2 * O_OF_W(m) + zmMontCreate_keep(no) +  
		utilMax(2,
			zmMontCreate_deep(no),
			qrPower_deep(n, n, zmMontCreate_deep(no))));
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// раскладка состояния
	x = (word*)state;
	u = x + m;
	y = u + m;
	v = y + n;
	qr = (qr_o*)(v + n);
	stack = (octet*)qr + zmMontCreate_keep(no);
	// построить кольцо Монтгомери
	zmMontCreate(qr, params->p, no, params->l + 2, stack);
	// x <- privkey, u <- privkey1
	wwFrom(x, privkey, mo);
	wwFrom(u, privkey1, mo);
	if (wwGetBits(x, params->r, B_OF_W(m) - params->r) != 0 ||
		wwGetBits(u, params->r, B_OF_W(m) - params->r) != 0)
	{
		blobClose(state);
		return ERR_BAD_PRIVKEY;
	}
	// y <- pubkey, v <- pubkey1
	wwFrom(y, pubkey, no);
	wwFrom(v, pubkey1, no);
	if (wwIsZero(y, n) || wwCmp(y, qr->mod, n) >= 0 ||
		wwIsZero(v, n) || wwCmp(v, qr->mod, n) >= 0)
	{
		blobClose(state);
		return ERR_BAD_PUBKEY;
	}
	// y <- y^u, v <- v^x
	qrPower(y, y, u, m, qr, stack);
	qrPower(v, v, x, m, qr, stack);
	// выгрузить открытый ключ
	qrTo((octet*)y, y, qr, stack);
	qrTo((octet*)v, v, qr, stack);
	memCopy(sharekey, y, O_OF_B(params->n));
	memXor2(sharekey, v, O_OF_B(params->n));
	if (params->n % 8)
		sharekey[params->n / 8] &= (octet)255 >> (8 - params->n % 8);
	// все нормально
	blobClose(state);
	return ERR_OK;
}
