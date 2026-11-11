#include <cstdint>
#include <cstddef>

extern "C" {
    #include <tiffio.h>
}

extern "C" int LLVMFuzzerTestOneInput_90(const uint8_t *data, size_t size) {
    // Initialize a TIFF structure. Since the function requires a TIFF pointer,
    // we will create a dummy TIFF object using TIFFClientOpen for fuzzing.
    static const char *dummyName = "dummy";
    TIFF *tiff = TIFFClientOpen(
        dummyName, "r", static_cast<thandle_t>(nullptr),
        [](thandle_t, void* buf, tmsize_t size) -> tmsize_t { return size; },  // dummy read
        [](thandle_t, void* buf, tmsize_t size) -> tmsize_t { return size; },  // dummy write
        [](thandle_t, toff_t off, int whence) -> toff_t { return off; },       // dummy seek
        [](thandle_t) -> int { return 0; },                                    // dummy close
        [](thandle_t) -> toff_t { return 0; },                                 // dummy size
        [](thandle_t, void** pbase, toff_t* psize) -> int { return 0; },       // dummy map
        [](thandle_t, void* base, toff_t size) -> void {}                      // dummy unmap
    );

    if (tiff == nullptr) {
        return 0;
    }

    // Call the function-under-test with the TIFF pointer.
    tmsize_t rowSize = TIFFTileRowSize(tiff);

    // Clean up: close the TIFF object.
    TIFFClose(tiff);

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

    LLVMFuzzerTestOneInput_90(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
