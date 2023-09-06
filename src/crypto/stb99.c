/*
*******************************************************************************
\file stb99.c
\brief STB 1176.2-99: generation of parameters
\project bee2 [cryptographic library]
\created 2023.08.01
\version 2023.09.06
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/core/blob.h"
#include "bee2/core/err.h"
#include "bee2/core/mem.h"
#include "bee2/core/prng.h"
#include "bee2/core/str.h"
#include "bee2/core/u32.h"
#include "bee2/core/util.h"
#include "bee2/crypto/stb99.h"
#include "bee2/math/pri.h"
#include "bee2/math/zm.h"
#include "bee2/math/ww.h"
#include "bee2/math/zz.h"

/*
*******************************************************************************
При генерации параметров stb99 требуется находить простые числа, битовая длина 
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
	638, 766, 1022, 1118, 1310, 1534, 1790, 2046, 2334, 2462,
};

static u32 const _rs[] = 
{
	143, 154, 175, 182, 195, 208, 222, 235, 249, 257, 
};

/*
*******************************************************************************
Тестоые параметры: методика ИЛ НИИ ППМИ (уровень 1) 
*******************************************************************************
*/

static const char _test_params_name[] = "test";

static const u32 _test_params_l = 638;

static const u32 _test_params_r = 143;

static const octet _test_params_p[] = {
	0xD7, 0x7E, 0xB2, 0xB7, 0x32, 0x05, 0x93, 0xED,
	0xC5, 0xAC, 0x46, 0x6E, 0xF4, 0xAF, 0x13, 0xBE,
	0x67, 0x92, 0x86, 0x9D, 0xF7, 0x58, 0x2C, 0xB5,
	0x9C, 0xB0, 0xF9, 0x77, 0xEA, 0x5A, 0xC3, 0x6A,
	0xB9, 0xAD, 0xA2, 0x3A, 0x1D, 0xF4, 0x25, 0x1F,
	0x22, 0xE6, 0xC9, 0x74, 0xBD, 0x75, 0xAF, 0x43,
	0xD6, 0x54, 0xD5, 0xB8, 0x58, 0x65, 0x08, 0x5D,
	0x7C, 0xAC, 0x58, 0xD9, 0xAB, 0x2C, 0x85, 0x26,
	0xCE, 0x18, 0xDD, 0x8B, 0x73, 0xF8, 0x24, 0x6B,
	0xAE, 0xCE, 0xBF, 0x2F, 0xDF, 0x2B, 0x61, 0x2E,
};

static const octet _test_params_q[] = {
	0xA9, 0x33, 0x19, 0x5B, 0x3F, 0x4E, 0x03, 0x37,
	0x15, 0x04, 0x9D, 0x4E, 0xE6, 0x8A, 0xFF, 0xC8,
	0xC5, 0x71,
};

static const octet _test_params_a[] = {
	0xBC, 0xAF, 0x5C, 0x24, 0x6B, 0x71, 0xA3, 0xEC,
	0x1B, 0x49, 0x05, 0xDD, 0xA5, 0xD6, 0xF8, 0x03,
	0x0F, 0xDD, 0x54, 0xCF, 0x54, 0x07, 0x0C, 0xF9,
	0xA1, 0x8E, 0xC5, 0xDA, 0xCC, 0xBA, 0xDA, 0x3D,
	0xFA, 0xDE, 0xAF, 0x4E, 0xBE, 0x18, 0x73, 0x23,
	0x97, 0x72, 0x1D, 0x5C, 0x43, 0x07, 0x53, 0xB6,
	0xEC, 0xED, 0x80, 0xB8, 0xF2, 0x22, 0xA3, 0xC6,
	0xE4, 0x83, 0x5F, 0xB6, 0x4B, 0x0D, 0xF4, 0x3A,
	0x2C, 0xB4, 0x64, 0x0C, 0xF7, 0x53, 0x96, 0xF7,
	0xE9, 0x67, 0x15, 0x20, 0x86, 0xDC, 0x3B, 0x02,
};

static const u16 _test_params_zi[] = {
	1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 
	18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
};

static const u32 _test_params_di[] = {
	320, 161, 81, 41, 21,
};

static const u32 _test_params_ri[] = {
	143, 72, 37, 19,
};

static const octet _test_params_d[] = {
	0x05,
};

/*
*******************************************************************************
Стандартные параметры: приложение В к СТБ 34.101.50
*******************************************************************************
*/

// bds-params (common)

static const u16 _bds_params_zi[] = {
	1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 
	18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
};

static const octet _bds_params_d[] = {
	0x05,
};

// bds-params3

static const char _bds_params3_name[] = "1.2.112.0.2.0.1176.2.3.3.1";

static const u32 _bds_params3_l = 1022;

static const u32 _bds_params3_r = 175;

static const octet _bds_params3_p[] = {
	0xE5, 0x91, 0xB1, 0x0E, 0x48, 0x70, 0x26, 0xBC,
	0x28, 0xA2, 0x7E, 0x74, 0xE4, 0x0D, 0xA9, 0xCB,
	0x42, 0xEC, 0x7B, 0xCF, 0xAB, 0xAA, 0xCD, 0x99,
	0xB8, 0xE9, 0x23, 0x8B, 0xB1, 0x2D, 0x15, 0xE7,
	0x4D, 0x1B, 0xEB, 0x16, 0x8F, 0xBE, 0xB4, 0x7F,
	0x81, 0x31, 0xC6, 0xE7, 0x24, 0x4D, 0xCE, 0x67,
	0xC4, 0x78, 0xD0, 0xE6, 0x9B, 0x0C, 0x53, 0x16,
	0xDA, 0x71, 0x5D, 0x53, 0x9E, 0x2C, 0xE1, 0x7D,
	0x50, 0xCE, 0x31, 0x0E, 0x17, 0x3C, 0xCD, 0xD2,
	0xF5, 0x70, 0x5C, 0x88, 0x3B, 0x42, 0x5E, 0x2C,
	0x57, 0xCA, 0x9E, 0x56, 0xD1, 0xBE, 0xB3, 0x1B,
	0x17, 0x72, 0x3B, 0x02, 0x80, 0x77, 0xCF, 0x77,
	0x9A, 0xCB, 0xAD, 0xA7, 0x5C, 0x20, 0x92, 0x8B,
	0x57, 0x46, 0x60, 0x7B, 0xB4, 0xF4, 0xA8, 0xB5,
	0xF3, 0xA5, 0x61, 0x3C, 0x6F, 0xC9, 0x81, 0xB8,
	0x56, 0x41, 0x1D, 0xF5, 0x79, 0xB9, 0x46, 0x28,
};  
    
static const octet _bds_params3_q[] = {
	0xC5, 0xF3, 0x63, 0x1D, 0xF5, 0x93, 0x6C, 0x63,
	0xCC, 0x50, 0xE4, 0x4E, 0x41, 0x53, 0x98, 0x84,
	0x17, 0x0B, 0xC8, 0x48, 0x3D, 0x7A,
};

static const octet _bds_params3_a[] = {
	0x83, 0x19, 0x93, 0x7D, 0x35, 0xBB, 0xFF, 0x7A,
	0x04, 0x34, 0xD9, 0xE4, 0xDB, 0xAA, 0x12, 0x21,
	0x13, 0x20, 0x33, 0x96, 0x65, 0x3F, 0xB9, 0x33,
	0x38, 0x33, 0xCE, 0x67, 0x31, 0xE1, 0x96, 0x1E,
	0xF0, 0xBD, 0x62, 0x5C, 0xF4, 0x25, 0x22, 0x8E,
	0x56, 0x5E, 0xF3, 0x53, 0xF4, 0xC9, 0x90, 0x1C,
	0xF6, 0x4C, 0xB7, 0x51, 0x7F, 0xFE, 0xF8, 0xD6,
	0xEA, 0x4E, 0xB0, 0x67, 0x2E, 0x16, 0x5D, 0x36,
	0x2F, 0xD9, 0x93, 0x08, 0xCB, 0x64, 0x8F, 0x1F,
	0xEE, 0x2C, 0xBC, 0x52, 0xD0, 0x88, 0x6A, 0x7D,
	0x2E, 0x73, 0x9F, 0x0D, 0x34, 0x04, 0xAE, 0x41,
	0xD0, 0x11, 0xBD, 0x32, 0xED, 0xCB, 0x86, 0xCF,
	0xFC, 0x73, 0xEB, 0x18, 0x1C, 0x2E, 0x52, 0x9A,
	0x9B, 0xA6, 0x2A, 0xB7, 0xB0, 0x34, 0x52, 0xD0,
	0xC9, 0x1F, 0x8B, 0xAB, 0x8F, 0xC5, 0xCB, 0xE1,
	0xE2, 0xAB, 0xD2, 0xB9, 0x81, 0xF4, 0xA7, 0x0C,
};

static const u32 _bds_params3_di[] = {
	512, 257, 129, 65, 33, 17,
};

static const u32 _bds_params3_ri[] = {
	175, 88, 45, 23,
};

// bds-params6

static const char _bds_params6_name[] = "1.2.112.0.2.0.1176.2.3.6.1";

static const u32 _bds_params6_l = 1534;

static const u32 _bds_params6_r = 208;

static const octet _bds_params6_p[] = {
	0x53, 0x34, 0x95, 0x5E, 0xE5, 0xC6, 0xEB, 0x5B,
	0x22, 0xAC, 0x91, 0x25, 0xA9, 0x5A, 0xC0, 0x6B,
	0xAA, 0x5A, 0x5E, 0x3C, 0x65, 0x1C, 0x2A, 0xF8,
	0x11, 0xF7, 0x0A, 0xCD, 0x81, 0x3A, 0xAF, 0x87,
	0xE2, 0xAC, 0x09, 0xA2, 0xAC, 0x48, 0x6F, 0x70,
	0x8A, 0x0C, 0xBA, 0x6E, 0x5D, 0x85, 0xC3, 0xDD,
	0xD4, 0xB8, 0xEA, 0x5D, 0x45, 0x5F, 0xB1, 0x61,
	0x22, 0xED, 0x98, 0x7F, 0xFF, 0x3A, 0x6F, 0xD6,
	0x62, 0xFA, 0xB9, 0x83, 0x64, 0xD8, 0x1F, 0x59,
	0x6C, 0xD6, 0x3D, 0x9B, 0xED, 0xEB, 0x98, 0x43,
	0x02, 0x8E, 0xFD, 0x44, 0x92, 0xB4, 0xE8, 0x70,
	0x15, 0x74, 0xF7, 0xB8, 0x2F, 0xEB, 0x79, 0x61,
	0x58, 0x1C, 0x4C, 0x5F, 0x6C, 0xD3, 0xE6, 0x4C,
	0x04, 0x76, 0xB9, 0xAF, 0x09, 0x6D, 0x6D, 0xCA,
	0x1D, 0x72, 0xAB, 0xF8, 0xB7, 0x2B, 0x81, 0xD0,
	0x8B, 0xA2, 0x98, 0xA5, 0x41, 0x6C, 0x46, 0xD5,
	0xCE, 0xC3, 0xC4, 0x07, 0xEF, 0xB7, 0x83, 0x81,
	0xC6, 0xED, 0x19, 0xC2, 0x57, 0xA0, 0xAB, 0x6D,
	0x3D, 0x39, 0x1E, 0x3B, 0x87, 0x51, 0xBF, 0xB9,
	0x9A, 0x96, 0x88, 0x75, 0xAF, 0xBA, 0xA2, 0x20,
	0x08, 0x96, 0xD7, 0x3D, 0x80, 0xF5, 0x68, 0xCB,
	0x10, 0x68, 0x08, 0x80, 0xAD, 0x64, 0x80, 0x86,
	0xFC, 0x91, 0x78, 0x15, 0x35, 0xC7, 0x9D, 0x5D,
	0xE3, 0x41, 0x5B, 0x5A, 0x83, 0xC3, 0x4B, 0x2E,
};

static const octet _bds_params6_q[] = {
	0x3D, 0x45, 0x6A, 0x5F, 0x71, 0xDA, 0x45, 0xDF,
	0x1B, 0x87, 0x2C, 0x74, 0xB9, 0xFC, 0x7C, 0xEC,
	0xEA, 0xD8, 0xDE, 0x27, 0x85, 0x80, 0x7D, 0x41,
	0xB5, 0xB7, 
};  

static const octet _bds_params6_a[] = {
	0x44, 0x80, 0xC7, 0xB7, 0x0E, 0x35, 0x0A, 0x45,
	0x76, 0xF3, 0xC8, 0x16, 0x08, 0x0F, 0x73, 0xBF,
	0x92, 0x70, 0xF9, 0x1B, 0x27, 0xE0, 0x7A, 0xFD,
	0x27, 0xA7, 0x45, 0x71, 0xC1, 0x2A, 0x3E, 0xDE,
	0x8B, 0xFF, 0xF8, 0x1A, 0xB6, 0xA0, 0x99, 0xF7,
	0x01, 0x1F, 0xF0, 0xED, 0xCA, 0x42, 0x0B, 0x16,
	0x31, 0x9B, 0x13, 0x17, 0x1C, 0xBB, 0x73, 0xFD,
	0x85, 0x81, 0x5A, 0x17, 0x9C, 0x3A, 0x65, 0xA7,
	0x93, 0xE1, 0x10, 0xF8, 0xCB, 0xDC, 0xA8, 0x2B,
	0xD4, 0x15, 0x9A, 0x9C, 0x5B, 0x05, 0x36, 0x0C,
	0x73, 0x3E, 0xA0, 0x88, 0x8E, 0xE4, 0x79, 0x20,
	0x42, 0xED, 0x7B, 0x98, 0xA1, 0xE2, 0xB1, 0xF1,
	0x54, 0x0D, 0x42, 0x1A, 0x18, 0x8E, 0x4D, 0xC8,
	0x06, 0x86, 0xE3, 0x57, 0x2F, 0x3F, 0x91, 0x24,
	0xCE, 0xB9, 0xE6, 0x12, 0xD0, 0x01, 0x12, 0xEF,
	0xD3, 0x8E, 0xC7, 0x1C, 0xD7, 0xF4, 0xE9, 0x25,
	0x7F, 0x25, 0x45, 0x8C, 0x76, 0xBA, 0xB6, 0xB8,
	0x0D, 0xC0, 0x2B, 0x40, 0x3C, 0x41, 0x1E, 0xB9,
	0x99, 0x19, 0xCF, 0x18, 0xD4, 0x16, 0x39, 0xBA,
	0xBD, 0x9F, 0xCC, 0xC0, 0x80, 0x02, 0x95, 0xD9,
	0x08, 0x4E, 0x0F, 0x21, 0x44, 0x3C, 0xE0, 0x19,
	0x85, 0xDC, 0xF3, 0x24, 0x6C, 0x86, 0xFF, 0x57,
	0x4A, 0x12, 0xD1, 0x08, 0xCF, 0x0A, 0x76, 0x2F,
	0x8D, 0x33, 0xBD, 0xC1, 0x4B, 0xA5, 0x7C, 0x01,
};

static const u32 _bds_params6_di[] = {
	768, 385, 193, 97, 49, 25,
};

static const u32 _bds_params6_ri[] = {
	208, 105, 53, 27,
};

// bds-params10

static const char _bds_params10_name[] = "1.2.112.0.2.0.1176.2.3.10.1";

static const u32 _bds_params10_l = 2462;

static const u32 _bds_params10_r = 257;

static const octet _bds_params10_p[] = {
	0x95, 0x1D, 0x9B, 0x6F, 0x5F, 0x28, 0xF2, 0xF1, 
	0x2A, 0x43, 0x37, 0x75, 0x6D, 0xD7, 0xE6, 0x51, 
	0xE3, 0xCC, 0x16, 0x15, 0x86, 0xF0, 0x2D, 0x2A, 
	0xD9, 0x30, 0x23, 0x12, 0xC9, 0xA7, 0x4C, 0x71, 
	0x25, 0x34, 0x2E, 0xF5, 0xE2, 0x38, 0x99, 0x8C, 
	0x77, 0xDD, 0xF5, 0xBD, 0x18, 0x29, 0x6D, 0x91, 
	0xD8, 0x16, 0xE9, 0x13, 0x8E, 0xE7, 0x26, 0x47, 
	0xE3, 0x79, 0x67, 0x22, 0xCE, 0xE4, 0x67, 0x26, 
	0x73, 0x94, 0xD6, 0xAF, 0x98, 0xCE, 0x17, 0x31, 
	0x1A, 0x55, 0x3C, 0xE9, 0xA1, 0xAE, 0xA0, 0x9B, 
	0x33, 0x30, 0x43, 0x14, 0x1A, 0xDC, 0xE7, 0x67, 
	0x8B, 0x8F, 0x9E, 0x94, 0xF1, 0x5D, 0x51, 0x0F, 
	0x0C, 0x8B, 0xEE, 0xD0, 0xA6, 0x3D, 0xCF, 0x54, 
	0x32, 0xFA, 0x94, 0x51, 0x15, 0x9B, 0xFD, 0x5E, 
	0x44, 0x76, 0x00, 0xB3, 0xEE, 0xD0, 0x2D, 0x37, 
	0x51, 0x22, 0xA6, 0x93, 0x49, 0xF5, 0x9C, 0x9E, 
	0x63, 0x82, 0x56, 0x94, 0xA4, 0xE8, 0x9D, 0xC4, 
	0xC0, 0xBE, 0x1C, 0xFC, 0x60, 0xCE, 0xE5, 0xBC, 
	0x09, 0x8D, 0xDF, 0x0A, 0x1B, 0x95, 0x75, 0x68, 
	0x9D, 0x0B, 0x5D, 0x8B, 0x05, 0x6E, 0xC9, 0xDB, 
	0x66, 0x05, 0xAC, 0x1C, 0x0E, 0xA7, 0xC5, 0x10, 
	0xDF, 0xAE, 0x34, 0x7E, 0xBD, 0x3B, 0xCB, 0x66, 
	0xAF, 0xBF, 0xE1, 0x2B, 0xEF, 0x22, 0xD2, 0x3B, 
	0x87, 0x18, 0x04, 0x5C, 0x7F, 0xCF, 0xD2, 0xA7, 
	0x24, 0x20, 0x10, 0xD1, 0x06, 0x9D, 0x8F, 0x00, 
	0xB6, 0x84, 0x9C, 0x90, 0x0D, 0xF3, 0xB3, 0x05, 
	0xA4, 0x64, 0x0A, 0x6D, 0x80, 0xDD, 0xE6, 0x01, 
	0xBE, 0x7A, 0x13, 0xD1, 0xE8, 0xA2, 0x88, 0x9A, 
	0xFE, 0xFD, 0xC6, 0xA9, 0x3F, 0xEE, 0x4E, 0x01, 
	0x81, 0x3C, 0xF6, 0xC7, 0x0F, 0xC8, 0x14, 0x53, 
	0x5A, 0x05, 0x2B, 0x45, 0x96, 0xD0, 0x65, 0x39, 
	0xC1, 0x55, 0xE7, 0x39, 0x02, 0x4C, 0xFA, 0xC0, 
	0xCF, 0x97, 0xA4, 0x34, 0xE0, 0x05, 0xD1, 0xE1, 
	0xD3, 0xEF, 0xF4, 0x2D, 0x8E, 0x41, 0x8F, 0xBF, 
	0x84, 0x76, 0x16, 0x38, 0x5B, 0x45, 0x17, 0xAA, 
	0x2B, 0xE4, 0xD7, 0x61, 0x8D, 0xB5, 0x3F, 0x2E, 
	0x2F, 0x2B, 0x59, 0x3A, 0x03, 0xFC, 0xD2, 0x14, 
	0xA2, 0xF0, 0x7C, 0xDA, 0x43, 0xBB, 0x63, 0x03, 
	0xCA, 0xEA, 0x01, 0x2F,
};

static const octet _bds_params10_q[] = {
	0xEB, 0x4E, 0x80, 0x4F, 0xC1, 0x52, 0xD1, 0x73, 
	0x46, 0x10, 0x78, 0xA1, 0x38, 0xB1, 0x1A, 0x3D, 
	0x19, 0xB1, 0x91, 0x44, 0xA4, 0x9F, 0x09, 0x9D, 
	0x82, 0xA5, 0x41, 0x6C, 0x46, 0xD5, 0xCE, 0xC3, 
	0x01,
};

static const octet _bds_params10_a[] = {
	0xEE, 0x4F, 0xC3, 0x6D, 0xEB, 0xAB, 0x19, 0x0E,
	0x07, 0x7B, 0xCE, 0x4F, 0x6C, 0xCC, 0x37, 0x88,
	0x6D, 0x47, 0xCC, 0x26, 0x24, 0xCC, 0x01, 0x06,
	0xB0, 0xB4, 0x14, 0xCB, 0xAE, 0x65, 0xBA, 0x0E,
	0x6E, 0xD8, 0xF5, 0xFA, 0x05, 0xC5, 0x5A, 0x3F,
	0x82, 0x24, 0xBB, 0x1B, 0xD3, 0x53, 0xCB, 0x3A,
	0x9D, 0x95, 0x40, 0xD5, 0x87, 0x47, 0xC1, 0xF5,
	0x57, 0x69, 0x7C, 0xB8, 0x1A, 0xB1, 0xE1, 0x38,
	0x46, 0xC4, 0xD3, 0x94, 0x67, 0x18, 0x63, 0x37,
	0xAA, 0xE9, 0xB7, 0xDD, 0x8E, 0xF1, 0x5D, 0x76,
	0xBE, 0x77, 0xF1, 0xCC, 0x12, 0x5E, 0x30, 0x75,
	0x18, 0xB2, 0xB0, 0x4B, 0x41, 0x20, 0xF4, 0x95,
	0x33, 0xF3, 0x88, 0x99, 0x30, 0x05, 0x60, 0xEB,
	0x94, 0xF7, 0xEA, 0x1E, 0xAD, 0x2C, 0x90, 0xE5,
	0x59, 0x73, 0x59, 0x26, 0x47, 0x1A, 0x45, 0xA0,
	0x88, 0x7B, 0x82, 0x63, 0xC8, 0x5A, 0x55, 0xC1,
	0x03, 0xCD, 0x11, 0x9D, 0x62, 0x89, 0x28, 0x6E,
	0x1B, 0x59, 0x5A, 0xF5, 0x67, 0xDC, 0x05, 0x38,
	0x66, 0xB3, 0xD2, 0x37, 0xE9, 0xBA, 0x22, 0xF7,
	0xBC, 0x90, 0x18, 0xEA, 0x9C, 0x74, 0x30, 0xF3,
	0xFF, 0xC7, 0x4E, 0x5C, 0x8A, 0x88, 0xF9, 0x0A,
	0xC7, 0x8C, 0x58, 0x9E, 0x75, 0x21, 0x90, 0xA1,
	0x1B, 0xCB, 0x3B, 0x85, 0xBD, 0xDB, 0x5C, 0xE8,
	0xB4, 0x1A, 0xEE, 0x7F, 0x0B, 0x9F, 0xB9, 0x51,
	0x80, 0x79, 0xC7, 0x1C, 0x99, 0x67, 0xF3, 0xD2,
	0x9E, 0xF3, 0xB1, 0xAF, 0xC4, 0xD9, 0xBE, 0x1D,
	0xB8, 0x11, 0x28, 0x6C, 0x39, 0xAE, 0x6A, 0x04,
	0xC5, 0x11, 0xE2, 0xEF, 0x35, 0x2C, 0x64, 0x3B,
	0x54, 0x65, 0x38, 0x2A, 0xE2, 0x83, 0xB2, 0xF1,
	0x53, 0xA1, 0x80, 0x18, 0xDA, 0x31, 0x52, 0x7F,
	0xF2, 0xAE, 0xB3, 0xF1, 0x2F, 0xF7, 0x2F, 0x55,
	0x99, 0x24, 0xA3, 0x4A, 0xAB, 0x2A, 0xDC, 0x7E,
	0x47, 0x61, 0x8F, 0xD9, 0x97, 0x1B, 0x2F, 0x2C,
	0xB2, 0xE2, 0x9E, 0x8F, 0x92, 0x78, 0xC4, 0xBF,
	0x8F, 0x50, 0xAC, 0x5A, 0xD0, 0x7B, 0x9A, 0x07,
	0xBF, 0x42, 0xFA, 0x85, 0x69, 0xED, 0x34, 0xF6,
	0x3D, 0xD5, 0x98, 0xBB, 0x4D, 0x6D, 0x84, 0x79,
	0xC7, 0x41, 0xCE, 0x38, 0x4E, 0x62, 0xE9, 0xB4,
	0x04, 0x18, 0x92, 0x1E,
};

static const u32 _bds_params10_di[] = {
	1232, 617, 309, 155, 78, 40, 21,
};

static const u32 _bds_params10_ri[] = {
	257, 129, 65, 33, 17,
};

/*
*******************************************************************************
Загрузка стандартных параметров
*******************************************************************************
*/

err_t stb99StdParams(stb99_params* params, stb99_seed* seed, const char* name)
{
	if (!memIsValid(params, sizeof(stb99_params)) ||
		!memIsNullOrValid(seed, sizeof(stb99_seed)))
		return ERR_BAD_INPUT;
	// подготовить params и seed
	memSetZero(params, sizeof(stb99_params));
	if (seed)
		memSetZero(seed, sizeof(stb99_seed));
	// найти params
	if (strEq(name, _test_params_name))
	{
		params->l = _test_params_l;
		params->r = _test_params_r;
		memCopy(params->p, _test_params_p, sizeof(_test_params_p));
		memCopy(params->q, _test_params_q, sizeof(_test_params_q));
		memCopy(params->a, _test_params_a, sizeof(_test_params_a));
		if (seed)
		{
			memCopy(seed->zi, _test_params_zi, sizeof(_test_params_zi));
			memCopy(seed->di, _test_params_di, sizeof(_test_params_di));
			memCopy(seed->ri, _test_params_ri, sizeof(_test_params_ri));
			memCopy(seed->d, _test_params_d, sizeof(_test_params_d));
		}
		return ERR_OK;
	}
	if (strEq(name, _bds_params3_name))
	{
		params->l = _bds_params3_l;
		params->r = _bds_params3_r;
		memCopy(params->p, _bds_params3_p, sizeof(_bds_params3_p));
		memCopy(params->q, _bds_params3_q, sizeof(_bds_params3_q));
		memCopy(params->a, _bds_params3_a, sizeof(_bds_params3_a));
		if (seed)
		{
			memCopy(seed->zi, _bds_params_zi, sizeof(_bds_params_zi));
			memCopy(seed->di, _bds_params3_di, sizeof(_bds_params3_di));
			memCopy(seed->ri, _bds_params3_ri, sizeof(_bds_params3_ri));
			memCopy(seed->d, _bds_params_d, sizeof(_bds_params_d));
		}
		return ERR_OK;
	}
	if (strEq(name, _bds_params6_name))
	{
		params->l = _bds_params6_l;
		params->r = _bds_params6_r;
		memCopy(params->p, _bds_params6_p, sizeof(_bds_params6_p));
		memCopy(params->q, _bds_params6_q, sizeof(_bds_params6_q));
		memCopy(params->a, _bds_params6_a, sizeof(_bds_params6_a));
		if (seed)
		{
			memCopy(seed->zi, _bds_params_zi, sizeof(_bds_params_zi));
			memCopy(seed->di, _bds_params6_di, sizeof(_bds_params6_di));
			memCopy(seed->ri, _bds_params6_ri, sizeof(_bds_params6_ri));
			memCopy(seed->d, _bds_params_d, sizeof(_bds_params_d));
		}
		return ERR_OK;
	}
	if (strEq(name, _bds_params10_name))
	{
		params->l = _bds_params10_l;
		params->r = _bds_params10_r;
		memCopy(params->p, _bds_params10_p, sizeof(_bds_params10_p));
		memCopy(params->q, _bds_params10_q, sizeof(_bds_params10_q));
		memCopy(params->a, _bds_params10_a, sizeof(_bds_params10_a));
		if (seed)
		{
			memCopy(seed->zi, _bds_params_zi, sizeof(_bds_params_zi));
			memCopy(seed->di, _bds_params10_di, sizeof(_bds_params10_di));
			memCopy(seed->ri, _bds_params10_ri, sizeof(_bds_params10_ri));
			memCopy(seed->d, _bds_params_d, sizeof(_bds_params_d));
		}
		return ERR_OK;
	}
	return ERR_FILE_NOT_FOUND;
}

/*
*******************************************************************************
Работоспособные параметры?

Не проверяется простота p и q и порядок a. Проверяется только то, что:
1)	битовая длина p равняется l;
2)	0 < a < p;
3)	битовая длина q равняется r.
*******************************************************************************
*/

static bool_t stb99IsOperableParams(const stb99_params* params)
{
	size_t n;
	ASSERT(memIsValid(params, sizeof(stb99_params)));
	// проверить размерности
	for (n = 0; n < COUNT_OF(_ls); ++n)
		if (_ls[n] == params->l)
			break;
	if (n == COUNT_OF(_ls) || _rs[n] != params->r)
		return FALSE;
	// проверить p (старшие 3 бита -- 001?)
	ASSERT((params->l + 2) % 8 == 0);
	n = O_OF_B(params->l);
	if (params->p[n - 1] >> 5 != 1)
		return FALSE;
	// проверить a
	if (memIsZero(params->a, n) || memCmpRev(params->a, params->p, n) >= 0)
		return FALSE;
	// проверить q
	n = O_OF_B(params->r);
	if (params->q[n - 1] >> (params->r - 1) % 8 != 1)
		return FALSE;
	// все хорошо
	return TRUE;
}

/*
*******************************************************************************
Генерация параметров

Схема генерации:
1. Построить простое g0, битовая длина которого близка снизу к l - r.
2. Построить простое q битовой длины r.
3. Выбрать псевдослучайное R так, чтобы битовая длина p = 2 * g0 * q * R + 1
   равнялась l.
4. Проверить простоту p и, если p оказывается составным, вернуться к шагу 2.
5. В группе Монтгомери B_p выбрать вычет a <- d^((p-1)/q), отличный от единицы.
   Этот вычет имеет порядок q в группе.
6. Возвратить p, q, a.
*******************************************************************************
*/

err_t stb99GenParams(stb99_params* params, stb99_seed* seed)
{
	size_t i;
	size_t n;
	size_t no;
	size_t m;
	size_t mo;
	const u32* di;
	const u32* ri;
	size_t gw;			/* число слов для хранения gi */
	size_t fw;			/* число слов для хранения fi */
	size_t offset;
	size_t trials;
	size_t base_count;
	// состояние 
	void* state;
	octet* stb_state;
	word* gi;			/* промежуточные простые при построении g0 */
	word* fi;			/* промежуточные простые при построении q */
	word* g0;
	word* p;
	word* d;
	word* a;
	qr_o* qr;
	void* stack;
	// проверить указатели
	if (!memIsValid(params, sizeof(stb99_params)) ||
		!memIsValid(seed, sizeof(stb99_seed)))
		return ERR_BAD_INPUT;
	// подготовить params
	memSetZero(params, sizeof(stb99_params));
	// проверить числа z[i]
	for (i = 0; i < 31; ++i)
		if (seed->zi[i] == 0 || seed->zi[i] >= 65257)
			return ERR_BAD_PARAMS;
	// проверить цепочку ri и одновременно определить l, r, fw
	for (i = 0, ri = seed->ri; i < COUNT_OF(_rs); ++i)
		if (ri[0] == _rs[i])
			break;
	if (i == COUNT_OF(_ls))
		return ERR_BAD_PARAMS;
	params->l = _ls[i], params->r = _rs[i];
	for (i = 1, fw = W_OF_B(ri[0]); ri[i] > 32; ++i)
	{
		if (ri[i - 1] > 2 * ri[i] ||
			ri[i] >= U32_MAX / 5 || 5 * ri[i] + 16 >= 4 * ri[i - 1])
			return ERR_BAD_PARAMS;
		fw += W_OF_B(ri[i]);
	}
	ASSERT(ri[i] > 16);
	ASSERT(W_OF_B(ri[i]) == 1);
	fw += 1;
	// проверить цепочку di и одновременно определить gw
	di = seed->di;
	if (params->l > 2 * di[0] ||
		di[0] >= U32_MAX / 8 || 8 * di[0] + params->r > 7 * params->l)
		return ERR_BAD_PARAMS;
	for (i = 1, gw = W_OF_B(di[0]); di[i] > 32; ++i)
	{
		if (di[i - 1] > 2 * di[i] ||
			di[i] >= U32_MAX / 5 || 5 * di[i] + 16 >= 4 * di[i - 1])
			return ERR_BAD_PARAMS;
		gw += W_OF_B(di[i]);
	}
	ASSERT(di[i] > 16);
	ASSERT(W_OF_B(di[i]) == 1);
	gw += 1;
	ASSERT(gw > fw);
	// размерности
	n = W_OF_B(params->l), no = O_OF_B(params->l);
	m = W_OF_B(params->r), mo = O_OF_B(params->r);
	// создать состояние
	state = blobCreate(
		prngSTB_keep() + O_OF_W(gw) +
		O_OF_W(W_OF_B(di[0]) + 2 * n) + zmMontCreate_keep(no) +
		utilMax(7,
			priNextPrimeW_deep(),
			priExtendPrime_deep(params->l, W_OF_B(di[1]), (di[0] + 3) / 4),
			priExtendPrime_deep(params->r, W_OF_B(ri[1]), (ri[0] + 3) / 4),
			priExtendPrime2_deep(params->l, W_OF_B(di[0]), W_OF_B(ri[1]),
			(params->l + 3) / 4),
			zmMontCreate_deep(no),
			zzDiv_deep(n, m),
			qrPower_deep(n, n, zmMontCreate_deep(no))));
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// раскладка состояния
	stb_state = (octet*)state;
	fi = gi = (word*)(stb_state + prngSTB_keep());
	g0 = gi + gw;
	p = g0 + W_OF_B(di[0]);
	a = p + n;
	qr = (qr_o*)(a + n);
	stack = (octet*)qr + zmMontCreate_keep(no);
	// запустить генератор
	prngSTBStart(stb_state, seed->zi);
	// построить цепочку gi
	offset = gw - 1;
	while (1)
	{
		// первое (минимальное) gi?
		if (di[i] <= 32)
		{
			ASSERT(offset == gw - 1);
			do
			{
				prngSTBStepR(gi + offset, O_OF_B(di[i]), stb_state);
				wwFrom(gi + offset, gi + offset, O_OF_B(di[i]));
				wwTrimHi(gi + offset, 1, di[i] - 1);
				wwSetBit(gi + offset, di[i] - 1, 1);
			}
			while (!priNextPrimeW(gi + offset, gi[offset], stack));
		}
		// обычное gi
		else
		{
			trials = 4 * di[i];
			base_count = (di[i] + 3) / 4;
			// потенциальное отступление от СТБ, не влияющее на результат
			if (base_count > priBaseSize())
				base_count = priBaseSize();
			// не удается построить новое простое?
			if (!priExtendPrime(gi + offset, di[i],
				gi + offset + W_OF_B(di[i]), W_OF_B(di[i + 1]),
				trials, base_count, prngSTBStepR, stb_state, stack))
			{
				// к предыдущему простому
				offset += W_OF_B(di[i++]);
				continue;
			}
		}
		// последнее простое?
		if (i == 0)
			break;
		// к следующему простому
		offset -= W_OF_B(di[--i]);
	}
	// сохранить g0
	wwCopy(g0, gi, W_OF_B(di[0]));
	// построить цепочку fi
	while (1)
	{
		for (i = 1; ri[i] > 32; ++i);
		offset = fw - 1;
		while (1)
		{
			// первое (минимальное) fi?
			if (ri[i] <= 32)
			{
				ASSERT(offset == fw - 1);
				do
				{
					prngSTBStepR(fi + offset, O_OF_B(ri[i]), stb_state);
					wwFrom(fi + offset, fi + offset, O_OF_B(ri[i]));
					wwTrimHi(fi + offset, 1, ri[i] - 1);
					wwSetBit(fi + offset, ri[i] - 1, 1);
				}
				while (!priNextPrimeW(fi + offset, fi[offset], stack));
			}
			// обычное fi
			else
			{
				trials = 4 * ri[i];
				base_count = (ri[i] + 3) / 4;
				// потенциальное отступление от СТБ, не влияющее на результат
				if (base_count > priBaseSize())
					base_count = priBaseSize();
				// не удается построить новое простое?
				if (!priExtendPrime(fi + offset, ri[i],
					fi + offset + W_OF_B(ri[i]), W_OF_B(ri[i + 1]),
					trials, base_count, prngSTBStepR, stb_state, stack))
				{
					// к предыдущему простому
					offset += W_OF_B(ri[i++]);
					continue;
				}
			}
			// последнее простое?
			if (i == 0)
				break;
			// к следующему простому
			offset -= W_OF_B(ri[--i]);
		}
		// построить p
		trials = 4 * di[0];
		base_count = (di[0] + 3) / 4;
		if (base_count > priBaseSize())
			base_count = priBaseSize();
		if (priExtendPrime2(p, params->l, g0, W_OF_B(di[0]),
			fi, W_OF_B(ri[0]), trials, base_count,
			prngSTBStepR, stb_state, stack))
			break;

	}
	// сохранить p и q
	wwTo(params->p, no, p);
	wwTo(params->q, mo, fi);
	// построить кольцо Монтгомери
	zmMontCreate(qr, params->p, no, params->l + 2, stack);
	// p <- (p - 1) / q
	zzSubW2(p, n, 1);
	zzDiv(p, a, p, n, gi, m, stack);
	// загрузить параметр d
	if (memIsZero(seed->d, no) || memCmpRev(seed->d, params->p, no) >= 0)
	{
		memSetZero(seed->d, no);
		seed->d[0] = 5;
	}
	d = gi;
	ASSERT(n <= gw);
	VERIFY(qrFrom(d, seed->d, qr, stack));
	// сгенерировать a
	while (1)
	{
		// a <- d^((p - 1)/2)
		qrPower(a, d, p, n - m + 1, qr, stack);
		// a != e?
		if (!qrIsUnity(a, qr))
			break;
		// d <- d + 1
		zzAddWMod(d, d, 1, qr->mod, n);
	}
	// сохранить a и d
	wwTo(params->a, no, a);
	wwTo(seed->d, no, d);
	// все нормально
	blobClose(state);
	return ERR_OK;
}

err_t stb99ValParams(const stb99_params* params)
{
	size_t n;
	size_t no;
	size_t m;
	size_t mo;
	// состояние 
	void* state;
	word* p;
	word* q;
	word* a;
	qr_o* qr;
	void* stack;
	// проверить указатели
	if (!memIsValid(params, sizeof(stb99_params)))
		return ERR_BAD_INPUT;
	// работоспособные параметры?
	if (!stb99IsOperableParams(params))
		return ERR_BAD_PARAMS;
	// размерности
	n = W_OF_B(params->l), no = O_OF_B(params->l);
	m = W_OF_B(params->r), mo = O_OF_B(params->r);
	// создать состояние
	state = blobCreate(
		O_OF_W(2 * n + m) + zmMontCreate_keep(no) +  
		utilMax(4,
			priIsPrime_deep(n),
			zzMod_deep(n, m),
			zmMontCreate_deep(no),
			qrPower_deep(n, n, zmMontCreate_deep(no))));
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// раскладка состояния
	p = (word*)state;
	q = p + n;
	a = q + m;
	qr = (qr_o*)(a + n);
	stack = (octet*)qr + zmMontCreate_keep(no);
	// p -- простое?
	wwFrom(p, params->p, no);
	if (!priIsPrime(p, n, stack))
	{
		blobClose(state);
		return ERR_BAD_PARAMS;
	}
	// q -- простое?
	wwFrom(q, params->q, mo);
	if (!priIsPrime(q, m, stack))
	{
		blobClose(state);
		return ERR_BAD_PARAMS;
	}
	// q |	p - 1?
	zzSubW2(p, n, 1);
	zzMod(p, p, n, q, m, stack);
	if (!wwIsZero(p, m))
	{
		blobClose(state);
		return ERR_BAD_PARAMS;
	}
	// построить кольцо Монтгомери
	zmMontCreate(qr, params->p, no, params->l + 2, stack);
	// проверить a
	qrFrom(a, params->a, qr, stack);
	qrPower(p, a, q, W_OF_B(params->r), qr, stack);
	if (!qrIsUnity(p, qr))
	{
		blobClose(state);
		return ERR_BAD_PARAMS;
	}
	// все нормально
	blobClose(state);
	return ERR_OK;
}
