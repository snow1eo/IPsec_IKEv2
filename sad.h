/* SAD */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "definitions.h"
#include <gmp.h>

typedef struct sad_elements
{
    unsigned long SPI;  // List of security settings, 32-bit`s
    unsigned long long SN_counter; // Sequence Number Counter, 64-bit`s
    bool flag; // Sequence Number Overflow
    unsigned long long redo; // Redo prevention window
    int SA_lifetime; // lifetime of SA

    // Помимо прочего тут присутствую значения алгоритма ESP: алгоритм шифрования,
    // ключ, режим, IV и прочее. Алгоритм защиты уелостности, ключи и прочее. И для комбинированного
    // режима ESP все те же параметры.


}sad_elements;
