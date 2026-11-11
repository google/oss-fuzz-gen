#include <stdint.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_417(const uint8_t *data, size_t size) {
    if (size < 9 * sizeof(cmsUInt32Number)) {
        return 0;
    }

    cmsContext context = cmsCreateContext(NULL, NULL);

    cmsHPROFILE inputProfile = cmsOpenProfileFromMem(data, size / 3);
    cmsHPROFILE outputProfile = cmsOpenProfileFromMem(data + size / 3, size / 3);
    cmsHPROFILE proofingProfile = cmsOpenProfileFromMem(data + 2 * (size / 3), size / 3);

    cmsUInt32Number inputFormat = *(cmsUInt32Number *)(data + size - 5 * sizeof(cmsUInt32Number));
    cmsUInt32Number outputFormat = *(cmsUInt32Number *)(data + size - 4 * sizeof(cmsUInt32Number));
    cmsUInt32Number proofingIntent = *(cmsUInt32Number *)(data + size - 3 * sizeof(cmsUInt32Number));
    cmsUInt32Number flags = *(cmsUInt32Number *)(data + size - 2 * sizeof(cmsUInt32Number));
    cmsUInt32Number intent = *(cmsUInt32Number *)(data + size - sizeof(cmsUInt32Number));

    if (inputProfile && outputProfile && proofingProfile) {
        cmsHTRANSFORM transform = cmsCreateProofingTransformTHR(
            context,
            inputProfile,
            inputFormat,
            outputProfile,
            outputFormat,
            proofingProfile,
            proofingIntent,
            intent,
            flags
        );

        if (transform) {
            cmsDeleteTransform(transform);
        }
    }

    if (inputProfile) {
        cmsCloseProfile(inputProfile);
    }
    if (outputProfile) {
        cmsCloseProfile(outputProfile);
    }
    if (proofingProfile) {
        cmsCloseProfile(proofingProfile);
    }

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

    LLVMFuzzerTestOneInput_417(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
