#include <sys/stat.h>
#include <string.h>
#include <iostream>
#include "sstream"
#include <string>
#include <vector>
#include "cstring"
#include "cstdlib"
#include <cstdio>
#include "cstdint"
#include <cstddef>
#include "cstdint"
#include <cstdio>
#include "cstdlib"
#include "tiffio.h"

// Define a minimal structure to match the expected TIFFField layout
struct MyTIFFField {
    uint32_t field_tag;
    short field_readcount;
    TIFFDataType field_type;
    unsigned short field_bit;
    unsigned char field_oktochange;
    const char *field_name;
    TIFFFieldArray *field_subfields;
};

static MyTIFFField* createTIFFField(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(MyTIFFField)) {
        return nullptr;
    }

    MyTIFFField *field = (MyTIFFField *)malloc(sizeof(MyTIFFField));
    if (!field) {
        return nullptr;
    }

    // Initialize the MyTIFFField with data from fuzzing input
    field->field_tag = *(uint32_t *)(Data);
    field->field_readcount = *(short *)(Data + 4);
    field->field_type = (TIFFDataType)*(Data + 6);
    field->field_bit = *(unsigned short *)(Data + 7);
    field->field_oktochange = *(unsigned char *)(Data + 9);
    field->field_name = "dummy_field";
    field->field_subfields = nullptr;

    return field;
}

extern "C" int LLVMFuzzerTestOneInput_31(const uint8_t *Data, size_t Size) {
    MyTIFFField *field = createTIFFField(Data, Size);
    if (!field) {
        return 0;
    }

    // Cast to TIFFField for API compatibility
    TIFFField *tiffField = reinterpret_cast<TIFFField *>(field);

    // Call the target API functions with the created TIFFField
    int passCount = TIFFFieldPassCount(tiffField);
    int writeCount = TIFFFieldWriteCount(tiffField);
    int readCount = TIFFFieldReadCount(tiffField);
    int setGetCountSize = TIFFFieldSetGetCountSize(tiffField);
    int isAnonymous = TIFFFieldIsAnonymous(tiffField);
    int setGetSize = TIFFFieldSetGetSize(tiffField);

    // Use the returned values to avoid any compiler optimizations
    volatile int dummy = passCount + writeCount + readCount +
                         setGetCountSize + isAnonymous + setGetSize;

    // Clean up
    free(field);

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

    LLVMFuzzerTestOneInput_31(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
