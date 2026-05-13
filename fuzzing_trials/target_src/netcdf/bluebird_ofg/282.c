#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern int nc__create_mp(const char *str, int param1, size_t param2, int param3, size_t *param4, int *param5);

int LLVMFuzzerTestOneInput_282(const uint8_t *data, size_t size) {
    if (size < 10) {
        return 0; // Ensure there's enough data to work with
    }

    // Create a null-terminated string from the data
    char *str = (char *)malloc(size + 1);
    if (str == NULL) {
        return 0; // Handle allocation failure
    }
    memcpy(str, data, size);
    str[size] = '\0';

    // Initialize other parameters
    int param1 = (int)data[0]; // Use first byte for param1
    size_t param2 = (size_t)data[1]; // Use second byte for param2
    int param3 = (int)data[2]; // Use third byte for param3

    size_t param4_value = 0;
    size_t *param4 = &param4_value;

    int param5_value = 0;
    int *param5 = &param5_value;

    // Call the function-under-test
    nc__create_mp(str, param1, param2, param3, param4, param5);

    // Clean up

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from nc__create_mp to nc_abort


    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function nc_abort with nc_redef
    int ret_nc_abort_nfnce = nc_redef(*param5);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR


    if (ret_nc_abort_nfnce < 0){
    	return 0;
    }

    // End mutation: Producer.APPEND_MUTATOR

    free(str);

    return 0;
}