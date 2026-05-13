#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_479(const uint8_t *data, size_t size) {
    cmsToneCurve *curve = NULL;
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Create a tone curve for testing
    if (size > 0) {
        // Use the data to determine the number of segments in the tone curve
        int nSegments = data[0] % 10 + 1;  // Limit segments to avoid excessive resource use
        int *segments = (int *)malloc(nSegments * sizeof(int));

        for (int i = 0; i < nSegments; i++) {
            segments[i] = (i < size) ? data[i] : (i + 1) * 1000;
        }

        curve = cmsBuildTabulatedToneCurve16(context, nSegments, (const cmsUInt16Number *)segments);
        free(segments);
    }

    // Call the function-under-test
    cmsFreeToneCurve(curve);

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

    LLVMFuzzerTestOneInput_479(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
