// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// TIFFOpen at tif_unix.c:232:7 in tiffio.h
// TIFFMergeFieldInfo at tif_dirinfo.c:1238:5 in tiffio.h
// TIFFIsBigTIFF at tif_open.c:912:5 in tiffio.h
// TIFFFlushData at tif_flush.c:146:5 in tiffio.h
// TIFFWriteCheck at tif_write.c:605:5 in tiffio.h
// TIFFErrorExtR at tif_error.c:107:6 in tiffio.h
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
#include <cstdlib>
#include <cstdarg>
#include <cstring>
#include <tiffio.h>

static void WriteDummyFile(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

static TIFFFieldInfo* GenerateDummyFieldInfo(size_t count) {
    TIFFFieldInfo* fieldInfo = static_cast<TIFFFieldInfo*>(malloc(count * sizeof(TIFFFieldInfo)));
    if (fieldInfo) {
        memset(fieldInfo, 0, count * sizeof(TIFFFieldInfo));
    }
    return fieldInfo;
}

extern "C" int LLVMFuzzerTestOneInput_82(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    WriteDummyFile(Data, Size);

    TIFF *tif = TIFFOpen("./dummy_file", "r");
    if (!tif) {
        return 0;
    }

    TIFFFieldInfo* fieldInfo = GenerateDummyFieldInfo(1);
    if (fieldInfo) {
        TIFFMergeFieldInfo(tif, fieldInfo, 1);
        free(fieldInfo);
    }

    TIFFIsBigTIFF(tif);

    TIFFFlushData(tif);

    TIFFWriteCheck(tif, 1, "test");

    TIFFErrorExtR(tif, "test_module", "Test error message: %d", 123);

    TIFFClose(tif);

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

        LLVMFuzzerTestOneInput_82(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    