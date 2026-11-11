#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "lcms2.h"

int LLVMFuzzerTestOneInput_76(const uint8_t *data, size_t size) {
    // Check if the input size is sufficient for creating a profile
    if (size < sizeof(cmsHPROFILE)) {
        return 0;
    }

    // Create a profile from the input data
    cmsHPROFILE profile = cmsOpenProfileFromMem(data, size);

    // Ensure the profile is valid
    if (profile == NULL) {
        return 0;
    }

    // Buffer to store the profile information
    wchar_t buffer[256];
    cmsUInt32Number bufferSize = sizeof(buffer) / sizeof(buffer[0]);

    // Call the function-under-test
    cmsGetProfileInfo(profile, cmsInfoDescription, "en", "US", buffer, bufferSize);

    // Free the dictionary if needed (not applicable here as cmsGetProfileInfo does not return a dictionary)
    // cmsDictFree(dict);

    // Close the profile

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from cmsGetProfileInfo to cmsIT8GetPatchName
    cmsHANDLE ret_cmsIT8Alloc_xywut = cmsIT8Alloc(0);
    cmsFloat64Number ret_cmsSetAdaptationState_seygc = cmsSetAdaptationState(INTENT_ABSOLUTE_COLORIMETRIC);
    if (ret_cmsSetAdaptationState_seygc < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!buffer) {
    	return 0;
    }
    const char* ret_cmsIT8GetPatchName_aqxqn = cmsIT8GetPatchName(ret_cmsIT8Alloc_xywut, (int )ret_cmsSetAdaptationState_seygc, (char *)buffer);
    if (ret_cmsIT8GetPatchName_aqxqn == NULL){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    cmsCloseProfile(profile);

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

    LLVMFuzzerTestOneInput_76(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
