#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <math.h> // Include math.h for isnan()

// Assume the function is defined elsewhere
void janet_addtimeout(double timeout);

int LLVMFuzzerTestOneInput_288(const uint8_t *data, size_t size) {
    // Ensure there is enough data to form a double
    if (size < sizeof(double)) {
        return 0;
    }

    // Copy the data into a double variable
    double timeout;
    // Assuming the data is in a format that can be directly interpreted as a double
    // This is a simple way to convert bytes to double
    memcpy(&timeout, data, sizeof(double));

    // Check if the timeout is a valid number and not NaN or negative
    // Adjust the condition to ensure timeout is positive and within a reasonable range
    if (isnan(timeout) || timeout <= 0 || timeout > 1e6) { // Ensure timeout is strictly positive and not excessively large
        return 0;
    }

    // Additional check to ensure the timeout is not an extremely small positive number
    // which might not be meaningful in the context of a timeout
    if (timeout < 1e-6) {
        return 0;
    }

    // Call the function-under-test
    janet_addtimeout(timeout);

    return 0;
}
#ifdef INC_MAIN
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int main(int argc, char *argv[])
{
    FILE *f;
    uint8_t *data = NULL;
    long size;

    if(argc < 2)
        exit(0);

    f = fopen(argv[1], "rb");
    if(f == NULL)
        exit(0);

    fseek(f, 0, SEEK_END);

    size = ftell(f);
    rewind(f);

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_288(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
