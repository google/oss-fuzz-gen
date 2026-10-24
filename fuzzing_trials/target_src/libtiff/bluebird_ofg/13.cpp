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

extern "C" int LLVMFuzzerTestOneInput_13(const uint8_t *data, size_t size) {
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
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 0 of LogL16toY

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from LogL10toY to TIFFReadRGBAStrip
    // Ensure dataflow is valid (i.e., non-null)
    if (!tif) {
    	return 0;
    }
    int ret_TIFFCreateEXIFDirectory_dxije = TIFFCreateEXIFDirectory(tif);
    if (ret_TIFFCreateEXIFDirectory_dxije < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!tif) {
    	return 0;
    }
    uint64_t ret_TIFFScanlineSize64_twhtx = TIFFScanlineSize64(tif);
    if (ret_TIFFScanlineSize64_twhtx < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!tif) {
    	return 0;
    }
    int ret_TIFFReadRGBAStrip_uniea = TIFFReadRGBAStrip(tif, (uint32_t )ret_TIFFScanlineSize64_twhtx, (uint32_t *)&ret_LogL10toY_bulgn);
    if (ret_TIFFReadRGBAStrip_uniea < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    double ret_LogL16toY_ytran = LogL16toY((int )ret_LogL16toY_ytran);
    // End mutation: Producer.REPLACE_ARG_MUTATOR
    if (ret_LogL16toY_ytran < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!tif) {
    	return 0;
    }
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

    LLVMFuzzerTestOneInput_13(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
