#include <sys/stat.h>
#include <string.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include "../src/turbojpeg.h"
#include <cstdint>
#include <cstdlib>
#include <cstring>

static void writeDummyFile(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

extern "C" int LLVMFuzzerTestOneInput_28(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    } // Not enough data to proceed

    // Step 1: Prepare environment
    tjhandle handle = tj3Init(TJINIT_TRANSFORM);
    if (!handle) {
        return 0;
    }

    // Allocate a buffer

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from tj3Init to tjCompress
    unsigned char* ret_tjAlloc_rpulx = tjAlloc(TJFLAG_FORCESSE2);
    if (ret_tjAlloc_rpulx == NULL){
    	return 0;
    }
    unsigned char* ret_tjAlloc_ksnjb = tjAlloc(TJFLAG_PROGRESSIVE);
    if (ret_tjAlloc_ksnjb == NULL){
    	return 0;
    }
    unsigned long bexgyffd = -1;
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_tjAlloc_rpulx) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_tjAlloc_ksnjb) {
    	return 0;
    }
    int ret_tjCompress_cpyvf = tjCompress(handle, ret_tjAlloc_rpulx, TJ_ALPHAFIRST, 1, TJFLAG_ACCURATEDCT, TJFLAG_FORCESSE3, ret_tjAlloc_ksnjb, &bexgyffd, TJXOPT_TRIM, TJ_BGR, Size);
    if (ret_tjCompress_cpyvf < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    void *buffer = tj3Alloc(Size);
    if (!buffer) {
        tj3Destroy(handle);
        return 0;
    }

    // Step 2: Invoke tj3Free
    tj3Free(buffer);

    // Step 3: Determine buffer size
    tjtransform transform;
    memset(&transform, 0, sizeof(tjtransform));
    size_t bufSize = tj3TransformBufSize(handle, &transform);

    // Step 4: Allocate destination buffer
    unsigned char *dstBuf = static_cast<unsigned char*>(tj3Alloc(bufSize));
    if (!dstBuf) {
        tj3Destroy(handle);
        return 0;
    }

    // Step 5: Perform transformation
    unsigned char *dstBufs[1] = { dstBuf };
    size_t dstSizes[1] = { bufSize };
    int result = tj3Transform(handle, Data, Size, 1, dstBufs, dstSizes, &transform);

    // Step 6: Get error string if needed
    if (result < 0) {
        char *errorStr = tj3GetErrorStr(handle);
        if (errorStr) {
            // Handle error string if necessary
        }
    }

    // Step 7: Set a parameter
    tj3Set(handle, TJPARAM_NOREALLOC, 1);

    // Step 8: Perform another transformation
    result = tj3Transform(handle, Data, Size, 1, dstBufs, dstSizes, &transform);

    // Step 9: Get error string if needed
    if (result < 0) {
        char *errorStr = tj3GetErrorStr(handle);
        if (errorStr) {
            // Handle error string if necessary
        }
    }

    // Step 10: Free the buffer once
    tj3Free(dstBuf);

    // Step 11: Destroy the handle
    tj3Destroy(handle);

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

    LLVMFuzzerTestOneInput_28(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
