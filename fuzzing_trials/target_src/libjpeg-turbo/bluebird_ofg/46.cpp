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

extern "C" int LLVMFuzzerTestOneInput_46(const uint8_t *data, size_t size) {
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

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from tjLoadImage to tjDecodeYUV
    tjhandle ret_tj3Init_qzegd = tj3Init(TJ_NUMERR);
    unsigned char* ret_tjAlloc_aowlf = tjAlloc(TJXOPT_ARITHMETIC);
    if (ret_tjAlloc_aowlf == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_tjAlloc_aowlf) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!imageBuffer) {
    	return 0;
    }
    int ret_tjDecodeYUV_tkmvz = tjDecodeYUV(ret_tj3Init_qzegd, ret_tjAlloc_aowlf, TJ_NUMINIT, TJ_NUMINIT, imageBuffer, TJ_NUMINIT, TJ_NUMXOP, TJ_BGR, TJ_NUMINIT, TJFLAG_FORCEMMX);
    if (ret_tjDecodeYUV_tkmvz < 0){
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

    LLVMFuzzerTestOneInput_46(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
