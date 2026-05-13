extern "C" {
    #include <tiffio.h>
}

extern "C" int LLVMFuzzerTestOneInput_27(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient to extract an integer
    if (size < sizeof(int)) {
        return 0;
    }

    // Use the first few bytes of data to construct an integer
    int input_value = *(reinterpret_cast<const int*>(data));

    // Ensure the input value is within the valid range for TIFFGetBitRevTable
    input_value = input_value % 256; // TIFFGetBitRevTable expects a value between 0 and 255

    // Call the function-under-test
    const unsigned char *result = TIFFGetBitRevTable(input_value);

    // Use the result in some way to prevent compiler optimizations from removing the call
    if (result != nullptr) {
        // Iterate over the entire bit reversal table to ensure code coverage
        for (int i = 0; i < 256; ++i) {
            volatile unsigned char dummy = result[i];
            (void)dummy;  // Suppress unused variable warning
        }
    }

    // Additional logic to ensure the function is utilized effectively
    // Simulate further operations that might be performed on the result
    if (result != nullptr) {
        unsigned char checksum = 0;
        for (int i = 0; i < 256; ++i) {
            checksum ^= result[i];  // Example operation on the result
        }
        // Use the checksum in some way
        volatile unsigned char final_result = checksum;
        (void)final_result;  // Suppress unused variable warning
    }

    // New logic to vary the input and increase coverage
    for (int i = 0; i < 256; ++i) {
        const unsigned char *temp_result = TIFFGetBitRevTable(i);
        if (temp_result != nullptr) {
            unsigned char temp_checksum = 0;
            for (int j = 0; j < 256; ++j) {
                temp_checksum ^= temp_result[j];
                volatile unsigned char temp_dummy = temp_result[j];
                (void)temp_dummy;
            }
            volatile unsigned char temp_final_result = temp_checksum;
            (void)temp_final_result;
        }
    }

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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_27(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
