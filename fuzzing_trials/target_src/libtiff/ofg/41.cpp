#include <cstddef>
#include <cstdint>
#include <tiffio.h>

extern "C" {
    void TIFFSwabArrayOfDouble(double *, tmsize_t);
}

extern "C" int LLVMFuzzerTestOneInput_41(const uint8_t *data, size_t size) {
    if (size < sizeof(double)) {
        return 0;
    }

    // Allocate memory for an array of doubles
    tmsize_t num_doubles = size / sizeof(double);
    double *double_array = new double[num_doubles];

    // Copy data into the double array
    for (tmsize_t i = 0; i < num_doubles; ++i) {
        double_array[i] = static_cast<double>(data[i % size]);
    }

    // Call the function-under-test
    TIFFSwabArrayOfDouble(double_array, num_doubles);

    // Clean up
    delete[] double_array;

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

    LLVMFuzzerTestOneInput_41(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
