/****************************************************************************************************
 * Define
 ****************************************************************************************************/

#define HELPER_MAX_STRING_SIZE (1024)

/****************************************************************************************************
 * Include
 ****************************************************************************************************/

#include "helper.h"
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/****************************************************************************************************
 * Function Definition (Public)
 ****************************************************************************************************/

/*** Convert Byte Array To Hexadecimal String ***/
char *helper_convertByteArrayToHexString(const uint8_t * const ByteArray, const size_t ByteArrayLength)
{
    char *hexString;
    
    /*** Convert Byte Array To Hexadecimal String ***/
    /* Set Up */
    hexString = malloc(((2 * ByteArrayLength) + 1) * sizeof(*hexString));
    
    /* Convert Byte Array To Hexadecimal String */
    for(size_t i = 0; i < ByteArrayLength; i++)
        (void)sprintf(&hexString[2 * i], "%02hhX", ByteArray[i]);
    
    return hexString;
}

/*** Convert Hexadecimal String To Byte Array ***/
size_t helper_convertHexStringToByteArray(const char * const HexString, uint8_t ** const byteArray)
{
    size_t length;
    
    /*** Convert Hexadecimal String To Byte Array ***/
    /* Set Up */
    length = strlen(HexString) / 2;
    *byteArray = malloc(length * sizeof(**byteArray));
    
    /* Convert Hexadecimal String To Byte Array */
    for(size_t i = 0; i < length; i++)
        (void)sscanf(&HexString[2 * i], "%02hhX", &(*byteArray)[i]);
    
    return length;
}

/*** Execute System Command ***/
char *helper_executeSystemCommand(const char * const Command, ...)
{
    /*** Execute System Command ***/
    /* Variable */
    va_list arguments;
    char command[HELPER_MAX_STRING_SIZE], *output;
    FILE *fp;   
    
    /* Set Up */
    va_start(arguments, Command);
    (void)vsnprintf(command, sizeof(command), Command, arguments);
    output = malloc(HELPER_MAX_STRING_SIZE * sizeof(*output));
    
    /* Send Command And Get Output */
    fp = popen(command, "r");
    (void)fgets(output, HELPER_MAX_STRING_SIZE, fp);
    
    /* Clean Up */
    (void)pclose(fp);
    
    return output;
}
