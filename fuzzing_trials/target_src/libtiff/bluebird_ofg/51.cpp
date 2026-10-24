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

extern "C" int LLVMFuzzerTestOneInput_51(const uint8_t *data, size_t size) {
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

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from TIFFReadEncodedTile to TIFFReadTile
    // Ensure dataflow is valid (i.e., non-null)
    if (!tif) {
    	return 0;
    }
    int ret_TIFFIsBigEndian_nczxc = TIFFIsBigEndian(tif);
    if (ret_TIFFIsBigEndian_nczxc < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!tif) {
    	return 0;
    }
    uint32_t ret_TIFFNumberOfStrips_zdqup = TIFFNumberOfStrips(tif);
    if (ret_TIFFNumberOfStrips_zdqup < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!tif) {
    	return 0;
    }
    uint64_t ret_TIFFRasterScanlineSize64_oukjc = TIFFRasterScanlineSize64(tif);
    if (ret_TIFFRasterScanlineSize64_oukjc < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!tif) {
    	return 0;
    }
    uint32_t ret_TIFFNumberOfStrips_ieose = TIFFNumberOfStrips(tif);
    if (ret_TIFFNumberOfStrips_ieose < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!tif) {
    	return 0;
    }
    uint64_t ret_TIFFTileSize64_ktmpy = TIFFTileSize64(tif);
    if (ret_TIFFTileSize64_ktmpy < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!tif) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!buf) {
    	return 0;
    }
    tmsize_t ret_TIFFReadTile_mekrj = TIFFReadTile(tif, buf, ret_TIFFNumberOfStrips_zdqup, (uint32_t )ret_TIFFRasterScanlineSize64_oukjc, ret_TIFFNumberOfStrips_ieose, (uint16_t )ret_TIFFTileSize64_ktmpy);
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

    LLVMFuzzerTestOneInput_51(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
