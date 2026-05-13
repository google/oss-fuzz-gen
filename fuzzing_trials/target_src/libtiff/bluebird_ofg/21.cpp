#include <sys/stat.h>
#include <string.h>
#include "cstdint"
#include "cstring"
#include "tiffio.h"

extern "C" {
    // Function signatures for the functions-under-test
    TIFFCodec * TIFFRegisterCODEC(uint16_t scheme, const char *name, TIFFInitMethod initMethod);
    void TIFFUnRegisterCODEC(TIFFCodec *);
}

// Dummy TIFFInitMethod function for testing
static int DummyInitMethod(TIFF* tif, int scheme) {
    return 1; // Return success
}

extern "C" int LLVMFuzzerTestOneInput_21(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient to extract necessary parameters
    if (size < 4) {
        return 0; // Not enough data to proceed
    }

    // Extract a 16-bit scheme from the input data
    uint16_t scheme = static_cast<uint16_t>(data[0] | (data[1] << 8));

    // Calculate the length of the name string
    size_t nameLength = size - 2;

    // Create a buffer for the name string and ensure it's null-terminated
    char *name = new char[nameLength + 1];
    std::memcpy(name, data + 2, nameLength);
    name[nameLength] = '\0';

    // Call the function-under-test
    TIFFCodec *codec = TIFFRegisterCODEC(scheme, name, DummyInitMethod);

    // Check if the codec is registered successfully
    if (codec != nullptr) {
        // Correctly unregister the codec using the codec pointer
        TIFFUnRegisterCODEC(codec);
    } else {
        // If codec is not registered, attempt to handle the error case
        // This is important for code coverage as it exercises different paths
        // For example, log an error or handle it in a specific way if needed
    }

    // Clean up the allocated memory for the name
    delete[] name;

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

    LLVMFuzzerTestOneInput_21(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
