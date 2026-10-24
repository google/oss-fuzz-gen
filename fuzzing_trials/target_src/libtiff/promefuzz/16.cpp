// This fuzz driver is generated for library libtiff, aiming to fuzz the following functions:
// TIFFOpenOptionsAlloc at tif_open.c:80:18 in tiffio.h
// TIFFOpenOptionsSetMaxSingleMemAlloc at tif_open.c:94:6 in tiffio.h
// TIFFOpenOptionsFree at tif_open.c:87:6 in tiffio.h
// TIFFOpenExt at tif_unix.c:237:7 in tiffio.h
// TIFFOpenOptionsFree at tif_open.c:87:6 in tiffio.h
// TIFFSetField at tif_dir.c:1152:5 in tiffio.h
// TIFFSetField at tif_dir.c:1152:5 in tiffio.h
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
#include <tiffio.h>
#include <cstdint>
#include <cstdio>
#include <cstdarg>

extern "C" int LLVMFuzzerTestOneInput_16(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Step 1: Prepare environment
    TIFFOpenOptions *opts = TIFFOpenOptionsAlloc();
    if (!opts) {
        return 0; // Allocation failed, exit
    }

    // Set maximum single memory allocation
    tmsize_t max_single_mem_alloc = static_cast<tmsize_t>(Data[0]);
    TIFFOpenOptionsSetMaxSingleMemAlloc(opts, max_single_mem_alloc);

    // Write data to a dummy file
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) {
        TIFFOpenOptionsFree(opts);
        return 0;
    }
    fwrite(Data, 1, Size, file);
    fclose(file);

    // Step 2: Open the TIFF file
    TIFF *tif = TIFFOpenExt("./dummy_file", "r+", opts);
    TIFFOpenOptionsFree(opts); // Free options after use

    if (!tif) {
        return 0; // Failed to open, exit
    }

    // Step 3: Set fields with arbitrary tags and values
    TIFFSetField(tif, static_cast<uint32_t>(Data[0]), Data[0]);
    if (Size > 1) {
        TIFFSetField(tif, static_cast<uint32_t>(Data[1]), Data[1]);
    }

    // Step 4: Write directory
    TIFFWriteDirectory(tif);

    // Step 5: Close the TIFF file
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

        LLVMFuzzerTestOneInput_16(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    