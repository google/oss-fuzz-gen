#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "lcms2.h"

int LLVMFuzzerTestOneInput_75(const uint8_t *data, size_t size) {
    if (size < sizeof(cmsUInt32Number) * 3) {
        return 0;
    }

    cmsContext context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0;
    }

    cmsHPROFILE hProfile = cmsOpenProfileFromMem(data, size);
    if (hProfile == NULL) {
        cmsDeleteContext(context);
        return 0;
    }

    cmsUInt32Number intent = *(cmsUInt32Number *)data;
    cmsUInt32Number flags = *((cmsUInt32Number *)data + 1);
    cmsUInt32Number bufferSize = *((cmsUInt32Number *)data + 2);

    if (bufferSize == 0) {
        cmsCloseProfile(hProfile);
        cmsDeleteContext(context);
        return 0;
    }

    void *buffer = malloc(bufferSize);
    if (buffer == NULL) {
        cmsCloseProfile(hProfile);
        cmsDeleteContext(context);
        return 0;
    }

    cmsUInt32Number result = cmsGetPostScriptCSA(context, hProfile, intent, flags, buffer, bufferSize);

    free(buffer);
    cmsCloseProfile(hProfile);
    cmsDeleteContext(context);

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

    LLVMFuzzerTestOneInput_75(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
