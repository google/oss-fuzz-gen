#include <sys/stat.h>
#include <string.h>
#include "cstdint"
#include "cstdlib"
#include <cstdio>
#include <unistd.h>
#include <fcntl.h>
#include "tiffio.h"

extern "C" {
    #include "tiffio.h"
}

extern "C" int LLVMFuzzerTestOneInput_9(const uint8_t *data, size_t size) {
    TIFF *tif = nullptr;
    uint32_t tile = 0;
    tmsize_t bufsize = 1024; // Arbitrary buffer size
    void *buf = malloc(bufsize);

    if (buf == nullptr) {
        return 0; // Exit if memory allocation fails
    }

    // Create a temporary TIFF file to read from
    char tmpl[] = "/tmp/fuzzfileXXXXXX.tiff";
    int fd = mkstemps(tmpl, 5);
    if (fd == -1) {
        free(buf);
        return 0; // Exit if file creation fails
    }

    // Write the fuzz data to the temporary file
    ssize_t written = write(fd, data, size);
    if (written != size) {
        close(fd);
        free(buf);
        return 0; // Exit if write fails
    }
    close(fd);

    // Open the TIFF file
    tif = TIFFOpen(tmpl, "r");
    if (tif == nullptr) {
        free(buf);
        return 0; // Exit if TIFFOpen fails
    }

    // Call the function-under-test
    TIFFReadEncodedTile(tif, tile, buf, bufsize);

    // Clean up

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from TIFFReadEncodedTile to TIFFReadRGBAImage
    double ret_LogL10toY_bulgn = LogL10toY(-1);
    if (ret_LogL10toY_bulgn < 0){
    	return 0;
    }
    double ret_LogL16toY_ytran = LogL16toY(0);
    if (ret_LogL16toY_ytran < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!tif) {
    	return 0;
    }

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from LogL16toY to uv_encode
    double ret_LogL10toY_onqxy = LogL10toY(0);
    if (ret_LogL10toY_onqxy < 0){
    	return 0;
    }
    double ret_LogL10toY_nlnag = LogL10toY(UVSCALE);
    if (ret_LogL10toY_nlnag < 0){
    	return 0;
    }
    int ret_uv_encode_dkbfd = uv_encode(ret_LogL10toY_onqxy, ret_LogL10toY_nlnag, (int )ret_LogL16toY_ytran);
    if (ret_uv_encode_dkbfd < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    uint64_t ret_TIFFRasterScanlineSize64_rvydi = TIFFRasterScanlineSize64(tif);
    if (ret_TIFFRasterScanlineSize64_rvydi < 0){
    	return 0;
    }
    double ret_LogL16toY_bkynl = LogL16toY(FIELD_CUSTOM);
    if (ret_LogL16toY_bkynl < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!tif) {
    	return 0;
    }
    int ret_TIFFReadRGBAImage_bguby = TIFFReadRGBAImage(tif, (uint32_t )ret_LogL10toY_bulgn, (uint32_t )ret_LogL16toY_ytran, (uint32_t *)&ret_TIFFRasterScanlineSize64_rvydi, (int )ret_LogL16toY_bkynl);
    if (ret_TIFFReadRGBAImage_bguby < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    TIFFClose(tif);
    free(buf);
    remove(tmpl);

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

    LLVMFuzzerTestOneInput_9(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
