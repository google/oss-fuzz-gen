// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// TIFFOpen at tif_unix.c:232:7 in tiffio.h
// TIFFGetField at tif_dir.c:1592:5 in tiffio.h
// TIFFSetSubDirectory at tif_dir.c:2163:5 in tiffio.h
// TIFFReadDirectory at tif_dirread.c:4323:5 in tiffio.h
// TIFFSetDirectory at tif_dir.c:2067:5 in tiffio.h
// TIFFSetSubDirectory at tif_dir.c:2163:5 in tiffio.h
// TIFFReadDirectory at tif_dirread.c:4323:5 in tiffio.h
// TIFFSetDirectory at tif_dir.c:2067:5 in tiffio.h
// TIFFReadDirectory at tif_dirread.c:4323:5 in tiffio.h
// TIFFCurrentDirectory at tif_open.c:874:8 in tiffio.h
// TIFFSetSubDirectory at tif_dir.c:2163:5 in tiffio.h
// TIFFNumberOfDirectories at tif_dir.c:2042:8 in tiffio.h
// TIFFCreateDirectory at tif_dir.c:1699:5 in tiffio.h
// TIFFSetField at tif_dir.c:1152:5 in tiffio.h
// TIFFWriteDirectory at tif_dirwrite.c:238:5 in tiffio.h
// TIFFSetField at tif_dir.c:1152:5 in tiffio.h
// TIFFCheckpointDirectory at tif_dirwrite.c:292:5 in tiffio.h
// TIFFWriteDirectory at tif_dirwrite.c:238:5 in tiffio.h
// TIFFCheckpointDirectory at tif_dirwrite.c:292:5 in tiffio.h
// TIFFWriteDirectory at tif_dirwrite.c:238:5 in tiffio.h
// TIFFClose at tif_close.c:155:6 in tiffio.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdarg>
#include <cstdlib>
#include <tiffio.h>

static TIFF* openDummyTIFF(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) return nullptr;
    fwrite(Data, 1, Size, file);
    fclose(file);

    return TIFFOpen("./dummy_file", "r+");
}

extern "C" int LLVMFuzzerTestOneInput_2(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    TIFF *tif = openDummyTIFF(Data, Size);
    if (!tif) return 0;

    uint32_t tag = Data[0]; // Simplified tag selection for fuzzing
    TIFFGetField(tif, tag);

    TIFFSetSubDirectory(tif, 0);
    TIFFReadDirectory(tif);
    TIFFSetDirectory(tif, 0);
    TIFFSetSubDirectory(tif, 0);
    TIFFReadDirectory(tif);
    TIFFSetDirectory(tif, 0);
    TIFFReadDirectory(tif);
    TIFFCurrentDirectory(tif);
    TIFFSetSubDirectory(tif, 0);
    TIFFNumberOfDirectories(tif);
    TIFFCreateDirectory(tif);
    TIFFSetField(tif, tag, 0);
    TIFFWriteDirectory(tif);
    TIFFSetField(tif, tag, 0);
    TIFFCheckpointDirectory(tif);
    TIFFWriteDirectory(tif);
    TIFFCheckpointDirectory(tif);
    TIFFWriteDirectory(tif);

    TIFFClose(tif); // Ensure proper cleanup
    tif = nullptr; // Avoid use-after-free by nullifying the pointer

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

        LLVMFuzzerTestOneInput_2(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    