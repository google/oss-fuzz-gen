#include <sys/stat.h>
#include <string.h>
#include "tiffio.h"
#include "cstdint"
#include "cstdlib"
#include <cstdio>
#include <unistd.h>  // Include this for the 'close' function

extern "C" {
    int LLVMFuzzerTestOneInput_42(const uint8_t *data, size_t size) {
        if (size == 0) {
            return 0;
        }

        // Create a temporary file to write the input data
        char tmpl[] = "/tmp/fuzzfileXXXXXX";
        int fd = mkstemp(tmpl);
        if (fd == -1) {
            return 0;
        }

        FILE *file = fdopen(fd, "wb");
        if (file == nullptr) {
            close(fd);
            return 0;
        }

        fwrite(data, 1, size, file);
        fclose(file);

        // Open the TIFF file
        TIFF *tiff = TIFFOpen(tmpl, "r");
        if (tiff != nullptr) {
            // Call the function-under-test
            int tiled = TIFFIsTiled(tiff);

            // Close the TIFF file

            // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from TIFFIsTiled to TIFFWriteRawStrip
            double ret_LogL10toY_eqewk = LogL10toY(V_NEU);
            if (ret_LogL10toY_eqewk < 0){
            	return 0;
            }
            // Ensure dataflow is valid (i.e., non-null)
            if (!tiff) {
            	return 0;
            }
            TIFFUnmapFileProc ret_TIFFGetUnmapFileProc_jrgkz = TIFFGetUnmapFileProc(tiff);
            // Ensure dataflow is valid (i.e., non-null)
            if (!tiff) {
            	return 0;
            }
            tmsize_t ret_TIFFStripSize_ntiyc = TIFFStripSize(tiff);
            // Ensure dataflow is valid (i.e., non-null)
            if (!tiff) {
            	return 0;
            }
            // Ensure dataflow is valid (i.e., non-null)
            if (!tiff) {
            	return 0;
            }
            tmsize_t ret_TIFFWriteRawStrip_jauyp = TIFFWriteRawStrip(tiff, (uint32_t )ret_LogL10toY_eqewk, (void *)tiff, ret_TIFFStripSize_ntiyc);
            // End mutation: Producer.APPEND_MUTATOR
            
            TIFFClose(tiff);
        }

        // Clean up the temporary file
        remove(tmpl);

        return 0;
    }
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

    LLVMFuzzerTestOneInput_42(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
