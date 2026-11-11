#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

// Assuming the function is defined in some library
extern const char * netlib_errstr(const int);

int LLVMFuzzerTestOneInput_22(const uint8_t *data, size_t size) {
    // Ensure that there is at least one byte to convert to an int
    if (size < sizeof(int)) {
        return 0;
    }

    // Interpret the first few bytes of data as an integer
    int error_code = 0;
    for (size_t i = 0; i < sizeof(int) && i < size; ++i) {
        error_code |= data[i] << (i * 8);
    }

    // Call the function-under-test
    const char *error_string = netlib_errstr(error_code);

    // Utilize the error_string to avoid unused variable warning
    if (error_string != NULL) {
        printf("Error string: %s\n", error_string);
    }

    return 0;
}