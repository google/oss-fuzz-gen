#include <stddef.h>
#include <stdint.h>

// Assuming the function is declared in some header file
int nc_get_var_uchar(int, int, unsigned char *);

int LLVMFuzzerTestOneInput_253(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract two integers and a non-null pointer
    if (size < sizeof(int) * 2 + sizeof(unsigned char)) {
        return 0;
    }

    // Extract the first integer from the data
    int var1 = *(const int *)data;

    // Extract the second integer from the data
    int var2 = *(const int *)(data + sizeof(int));

    // Extract an unsigned char pointer from the data
    unsigned char *uchar_ptr = (unsigned char *)(data + sizeof(int) * 2);

    // Call the function-under-test
    nc_get_var_uchar(var1, var2, uchar_ptr);

    return 0;
}