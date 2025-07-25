/****************************************************************************************************
 * Pragma
 ****************************************************************************************************/

#pragma once

/****************************************************************************************************
 * Include
 ****************************************************************************************************/

#include <stddef.h>
#include <stdint.h>

/****************************************************************************************************
 * Function Prototype
 ****************************************************************************************************/

extern char *helper_convertByteArrayToHexString(const uint8_t * const ByteArray, const size_t ByteArrayLength);
extern size_t helper_convertHexStringToByteArray(const char * const HexString, uint8_t ** const byteArray);
extern char *helper_executeSystemCommand(const char * const Command, ...);
