// Heuristic: FuzzerGenHeuristic6 :: Target: sql3parse_table
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "sql3parse_debug.h"
#include "sql3parse_table.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Null-terminate the input data
    char *input = (char *)malloc(size + 1);
    if (!input) {
        return 0;
    }
    memcpy(input, data, size);
    input[size] = '\0';

    sql3error_code error;
    sql3table *result = sql3parse_table((const char *)input, size, &error);
    
    free(input);
    
    return 0;
}
