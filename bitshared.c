/*
 * bitshared.c
 *
 *  Created on: 16.2.2017
 *      Author: jpuchky
 */

#include "bitshared.h"

uint32_t const m32_8[countSelector] = { 0xFF, 0x00FF, 0x0000FF, 0x000000FF };
uint32_t const m_32_8[countSelector] = { 0x000000FF, 0x0000FF00, 0x00FF0000, 0xFF000000 };
uint32_t const _m32_8[countSelector] = { 0x00FFFFFF, 0xFF00FFFF, 0xFFFF00FF, 0xFFFFFF00 };
uint32_t const o32_8[countSelector] = { 0, 8, 16, 24 };

uint32_t const lock_8[] = { 1, 2, 5, 8, 16, 32, 64, 128 };
uint32_t const unlock_8[] = { 0b11111110, 0b11111101, 0b11111011, 0b11110111, 0b11101111, 0b11011111, 0b10111111, 0b01111111 };

