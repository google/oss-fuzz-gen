#include <string.h>
#include <sys/stat.h>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <unistd.h> // For close and remove
#include <fcntl.h>  // For mkstemp
#include <sys/types.h> // For ssize_t
#include <sys/stat.h>  // For open

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "../src/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_44(const uint8_t *data, size_t size) {
    // Create a temporary file to write the input data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the data to the temporary file
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        return 0;
    }
    close(fd);

    // Initialize variables for tjLoadImage parameters
    int width = 0;
    int height = 0;
    int pixelFormat = TJPF_RGB; // Use a valid pixel format
    int flags = 0; // No specific flags

    // Call the function-under-test
    unsigned char *imageBuffer = tjLoadImage(tmpl, &width, 1, &height, &pixelFormat, flags);

    // Clean up
    if (imageBuffer != NULL) {
        tjFree(imageBuffer);
    }

    // Remove the temporary file

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from tjLoadImage to tj3CompressFromYUVPlanes8
    tjhandle ret_tjInitDecompress_iujqx = tjInitDecompress();
    unsigned char* ret_tjAlloc_zoojn = tjAlloc(TJXOPT_GRAY);
    if (ret_tjAlloc_zoojn == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!imageBuffer) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_tjAlloc_zoojn) {
    	return 0;
    }
    int ret_tj3CompressFromYUVPlanes8_fwioj = tj3CompressFromYUVPlanes8(ret_tjInitDecompress_iujqx, &imageBuffer, TJXOPT_PERFECT, NULL, TJFLAG_LIMITSCANS, &ret_tjAlloc_zoojn, NULL);
    if (ret_tj3CompressFromYUVPlanes8_fwioj < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
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

    LLVMFuzzerTestOneInput_44(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
