#include <string.h>
#include <sys/stat.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "../src/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_3(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    // Initialize TurboJPEG handle
    tjhandle handle = tjInitTransform();
    if (handle == nullptr) {
        return 0;
    }

    // Allocate memory for the destination buffer
    unsigned char *dstBuf = nullptr;
    unsigned long dstSize = 0;

    // Initialize transformation parameters
    tjtransform transform;
    memset(&transform, 0, sizeof(tjtransform)); // Zero out the structure

    // Set some transformation options for fuzzing
    transform.op = TJXOP_NONE;  // No transformation
    transform.options = 0;      // No options

    // Call the function-under-test
    int result = tjTransform(handle, data, (unsigned long)size, 1, &dstBuf, &dstSize, &transform, 0);

    // Clean up
    if (dstBuf != nullptr) {
        tjFree(dstBuf);
    }

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from tjTransform to tjCompress
    tjhandle ret_tj3Init_wmbsg = tj3Init(TJXOPT_GRAY);
    unsigned char* ret_tjAlloc_mgrdn = tjAlloc(TJ_NUMCS);
    if (ret_tjAlloc_mgrdn == NULL){
    	return 0;
    }
    unsigned char* ret_tjAlloc_elcvn = tjAlloc(TJFLAG_ACCURATEDCT);
    if (ret_tjAlloc_elcvn == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_tjAlloc_mgrdn) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_tjAlloc_elcvn) {
    	return 0;
    }
    int ret_tjCompress_zuhze = tjCompress(ret_tj3Init_wmbsg, ret_tjAlloc_mgrdn, (int )dstSize, (int )dstSize, (int )dstSize, (int )dstSize, ret_tjAlloc_elcvn, &dstSize, (int )dstSize, (int )dstSize, (int )dstSize);
    if (ret_tjCompress_zuhze < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    tjDestroy(handle);

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

    LLVMFuzzerTestOneInput_3(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
