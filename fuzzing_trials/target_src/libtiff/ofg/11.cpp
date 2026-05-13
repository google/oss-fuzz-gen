#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include <tiffio.h>

    TIFFCodec *TIFFRegisterCODEC(uint16_t scheme, const char *name, TIFFInitMethod init);
    void TIFFUnRegisterCODEC(TIFFCodec *codec);
    int dummyInit(TIFF* tif, int scheme); // Dummy initialization function
}

extern "C" int LLVMFuzzerTestOneInput_11(const uint8_t *data, size_t size) {
    if (size < 4) {
        return 0; // Not enough data to extract meaningful inputs
    }

    // Use the input data to influence the parameters
    uint16_t scheme = data[0] | (data[1] << 8); // Use the first two bytes for scheme
    const char *name = reinterpret_cast<const char*>(data + 2); // Use the rest as the name

    // Ensure the name is null-terminated to prevent out-of-bounds access
    size_t name_length = size - 2;
    char *name_copy = new char[name_length + 1];
    std::memcpy(name_copy, name, name_length);
    name_copy[name_length] = '\0';

    // Use a dummy initialization function to ensure the init method is not null
    TIFFInitMethod init = dummyInit;

    // Call the function-under-test
    TIFFCodec *codec = TIFFRegisterCODEC(scheme, name_copy, init);

    // Check if the codec was successfully registered
    if (codec != nullptr) {
        // Optionally, perform additional operations with the codec
        // For example, unregister the codec to ensure proper cleanup
        TIFFUnRegisterCODEC(codec);
    }

    // Clean up
    delete[] name_copy;

    return 0;
}

extern "C" int dummyInit(TIFF* tif, int scheme) {
    // A simple dummy initialization function that does nothing
    return 1; // Return success
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

    LLVMFuzzerTestOneInput_11(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
