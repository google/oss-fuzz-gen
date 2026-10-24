#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Function-under-test declaration
int gdbmshell_setopt(char *, int, int);

int LLVMFuzzerTestOneInput_123(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient to extract parameters
    if (size < sizeof(int) * 2 + 1) {
        return 0;
    }

    // Extract the first byte for the string length
    size_t str_len = data[0] % (size - sizeof(int) * 2);
    char option_name[str_len + 1];
    
    // Copy the string and ensure it is null-terminated
    memcpy(option_name, &data[1], str_len);
    option_name[str_len] = '\0';

    // Extract integers from the data
    int option_value1 = *(int *)&data[1 + str_len];
    int option_value2 = *(int *)&data[1 + str_len + sizeof(int)];

    // Call the function-under-test
    gdbmshell_setopt(option_name, option_value1, option_value2);

    return 0;
}