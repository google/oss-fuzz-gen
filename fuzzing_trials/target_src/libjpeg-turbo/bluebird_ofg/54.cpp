#include <string.h>
#include <sys/stat.h>
#include <cstdint>
#include <cstdlib>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "../src/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_54(const uint8_t *data, size_t size) {
    if (size < sizeof(int)) {
        return 0; // Ensure there is enough data to extract an integer
    }

    // Extract an integer from the data
    int initOption = *(reinterpret_cast<const int*>(data));

    // Call the function-under-test
    tjhandle handle = tj3Init(initOption);

    // Clean up if initialization was successful
    if (handle != nullptr) {
        tj3Destroy(handle);
    }


    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from tj3Init to tjEncodeYUVPlanes
    unsigned char* ret_tjAlloc_rkous = tjAlloc(TJXOPT_COPYNONE);
    if (ret_tjAlloc_rkous == NULL){
    	return 0;
    }
    void* ret_tj3Alloc_mkeaq = tj3Alloc(TJFLAG_STOPONWARNING);
    if (ret_tj3Alloc_mkeaq == NULL){
    	return 0;
    }
    int wqgngszh = 0;
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_tjAlloc_rkous) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_tj3Alloc_mkeaq) {
    	return 0;
    }
    int ret_tjEncodeYUVPlanes_hhino = tjEncodeYUVPlanes(handle, ret_tjAlloc_rkous, TJ_NUMCS, TJXOPT_NOOUTPUT, TJXOPT_ARITHMETIC, TJFLAG_FORCESSE3, (unsigned char **)&ret_tj3Alloc_mkeaq, &wqgngszh, TJFLAG_FORCESSE3, TJXOPT_COPYNONE);
    if (ret_tjEncodeYUVPlanes_hhino < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
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

    LLVMFuzzerTestOneInput_54(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
