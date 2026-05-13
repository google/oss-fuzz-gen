#include <stdint.h>
#include <stddef.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_3(const uint8_t *data, size_t size) {
    tjhandle handle = tj3Init(TJINIT_COMPRESS);
    if (handle == NULL) {
        return 0;
    }

    unsigned char *iccProfile = nullptr;
    size_t iccProfileSize = 0;

    if (size > 0) {
        iccProfile = const_cast<unsigned char*>(data);
        iccProfileSize = size;
    } else {
        // Provide a default non-NULL iccProfile if size is 0
        static unsigned char defaultProfile[] = {0x00, 0x01, 0x02, 0x03};
        iccProfile = defaultProfile;
        iccProfileSize = sizeof(defaultProfile);
    }

    tj3SetICCProfile(handle, iccProfile, iccProfileSize);

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

    LLVMFuzzerTestOneInput_3(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
