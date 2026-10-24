#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_341(const uint8_t *data, size_t size) {
    cmsContext context;
    cmsHPROFILE hProfile;
    cmsUInt32Number intent;
    cmsUInt32Number flags;
    void *buffer;
    cmsUInt32Number bufferSize;

    // Initialize variables
    context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0;
    }

    hProfile = cmsOpenProfileFromMem(data, size);
    if (hProfile == NULL) {
        cmsDeleteContext(context);
        return 0;
    }

    intent = (cmsUInt32Number)(size % 4); // Use a simple modulo to get a valid intent value
    flags = (cmsUInt32Number)(size % 8); // Use a simple modulo to get a valid flags value
    bufferSize = 1024; // Define a reasonable buffer size
    buffer = malloc(bufferSize);
    if (buffer == NULL) {
        cmsCloseProfile(hProfile);
        cmsDeleteContext(context);
        return 0;
    }

    // Call the function-under-test
    cmsUInt32Number result = cmsGetPostScriptCSA(context, hProfile, intent, flags, buffer, bufferSize);

    // Clean up
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_341(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
