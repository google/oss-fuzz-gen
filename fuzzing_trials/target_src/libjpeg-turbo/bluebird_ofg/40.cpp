#include <string.h>
#include <sys/stat.h>
#include <cstdint>
#include <cstdlib>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "../src/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_40(const uint8_t *data, size_t size) {
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


    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from tj3Init to tjDecodeYUVPlanes
    void* ret_tj3Alloc_zlqoh = tj3Alloc(TJFLAG_FORCESSE);
    if (ret_tj3Alloc_zlqoh == NULL){
    	return 0;
    }
    void* ret_tj3Alloc_yimxn = tj3Alloc(TJXOPT_PERFECT);
    if (ret_tj3Alloc_yimxn == NULL){
    	return 0;
    }
    const int reqtqtqr = 0;
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_tj3Alloc_zlqoh) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_tj3Alloc_yimxn) {
    	return 0;
    }
    int ret_tjDecodeYUVPlanes_zsack = tjDecodeYUVPlanes(handle, (const unsigned char **)&ret_tj3Alloc_zlqoh, &reqtqtqr, TJFLAG_BOTTOMUP, (unsigned char *)ret_tj3Alloc_yimxn, TJFLAG_ACCURATEDCT, TJFLAG_LIMITSCANS, TJ_NUMPF, TJXOPT_OPTIMIZE, TJ_NUMCS);
    if (ret_tjDecodeYUVPlanes_zsack < 0){
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

    LLVMFuzzerTestOneInput_40(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
