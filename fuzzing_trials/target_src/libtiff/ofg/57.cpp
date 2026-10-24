#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include <tiffio.h>
    #include <tiff.h> // This includes the definition of TIFFField

    // Declare the function signature correctly
    int TIFFFieldSetGetCountSize(const TIFFField *);
}

// Define a dummy structure to determine the size of TIFFField
struct DummyTIFFField {
    int field_tag;
    short field_readcount;
    short field_writecount;
    TIFFDataType field_type;
    unsigned short field_bit;
    unsigned char field_oktochange;
    unsigned char field_passcount;
    char* field_name;
    unsigned long field_subfields;
};

extern "C" int LLVMFuzzerTestOneInput_57(const uint8_t *data, size_t size) {
    // Use the size of the dummy structure
    const size_t min_size = sizeof(DummyTIFFField);

    // Check if the size is sufficient for a reasonable fuzz input
    if (size < min_size) {
        return 0;
    }

    // Allocate memory for a TIFFField and copy data into it
    DummyTIFFField dummy_field;
    std::memcpy(&dummy_field, data, min_size);

    // Cast the dummy field to TIFFField pointer
    TIFFField* field = reinterpret_cast<TIFFField*>(&dummy_field);

    // Call the function-under-test
    int result = TIFFFieldSetGetCountSize(field);

    // Use the result in some way to avoid compiler optimizations removing the call
    (void)result;

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

    LLVMFuzzerTestOneInput_57(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
