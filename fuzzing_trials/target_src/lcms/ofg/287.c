#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_287(const uint8_t *data, size_t size) {
    cmsToneCurve *toneCurve = NULL;
    cmsContext contextID = cmsCreateContext(NULL, NULL);
    
    // Ensure there is enough data to create a tone curve
    if (size >= sizeof(cmsFloat32Number) * 2) {
        // Use the data to create a simple tone curve with two points
        cmsFloat32Number points[2];
        points[0] = *((cmsFloat32Number *)data);
        points[1] = *((cmsFloat32Number *)(data + sizeof(cmsFloat32Number)));
        
        toneCurve = cmsBuildTabulatedToneCurve16(contextID, 2, points);
    }
    
    if (toneCurve != NULL) {
        // Call the function-under-test
        cmsInt32Number parametricType = cmsGetToneCurveParametricType(toneCurve);
        
        // Clean up
        cmsFreeToneCurve(toneCurve);
    }
    
    cmsDeleteContext(contextID);
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

    LLVMFuzzerTestOneInput_287(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
