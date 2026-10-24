#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "lcms2.h"  // Assuming the header file for cmsNAMEDCOLORLIST is lcms2.h

// Declare the cmsNAMEDCOLOR structure as it seems to be missing
typedef struct {
    char Name[32];               // Name of the color
    uint16_t PCS[3];             // Profile Connection Space values
    uint8_t DeviceColorant[4];   // Device colorant values
} cmsNAMEDCOLOR;

int LLVMFuzzerTestOneInput_44(const uint8_t *data, size_t size) {
    // Initialize a cmsNAMEDCOLORLIST structure
    cmsNAMEDCOLORLIST *originalList = cmsAllocNamedColorList(NULL, 1, 1, "Prefix", "Suffix");

    if (originalList == NULL) {
        return 0; // If allocation fails, exit early
    }

    // Add a named color to the list
    cmsNAMEDCOLOR namedColor;
    strcpy(namedColor.Name, "Red");
    namedColor.PCS[0] = 100;
    namedColor.PCS[1] = 0;
    namedColor.PCS[2] = 0;
    namedColor.DeviceColorant[0] = 255;
    namedColor.DeviceColorant[1] = 0;
    namedColor.DeviceColorant[2] = 0;
    namedColor.DeviceColorant[3] = 0;

    // Fix the function call to match the expected signature
    cmsAppendNamedColor(originalList, namedColor.Name, namedColor.PCS, namedColor.DeviceColorant);

    // Call the function-under-test
    cmsNAMEDCOLORLIST *dupList = cmsDupNamedColorList(originalList);

    // Clean up
    if (originalList != NULL) {
        cmsFreeNamedColorList(originalList);
    }
    if (dupList != NULL) {
        cmsFreeNamedColorList(dupList);
    }

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

    LLVMFuzzerTestOneInput_44(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
