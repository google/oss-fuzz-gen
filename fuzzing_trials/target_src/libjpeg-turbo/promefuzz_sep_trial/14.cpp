// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// tj3Init at turbojpeg.c:538:20 in turbojpeg.h
// tj3GetErrorStr at turbojpeg.c:618:17 in turbojpeg.h
// tj3Set at turbojpeg.c:671:15 in turbojpeg.h
// tj3GetErrorStr at turbojpeg.c:618:17 in turbojpeg.h
// tj3SetCroppingRegion at turbojpeg.c:2006:15 in turbojpeg.h
// tj3GetErrorStr at turbojpeg.c:618:17 in turbojpeg.h
// tj3Destroy at turbojpeg.c:580:16 in turbojpeg.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <turbojpeg.h>
#include <cstdint>
#include <cstdio>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_14(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int) * 7) return 0;

    // Extracting values from the input data
    int initType;
    memcpy(&initType, Data, sizeof(int));
    Data += sizeof(int);
    Size -= sizeof(int);

    int param;
    memcpy(&param, Data, sizeof(int));
    Data += sizeof(int);
    Size -= sizeof(int);

    int value;
    memcpy(&value, Data, sizeof(int));
    Data += sizeof(int);
    Size -= sizeof(int);

    int regionX, regionY, regionW, regionH;
    memcpy(&regionX, Data, sizeof(int));
    Data += sizeof(int);
    Size -= sizeof(int);
    memcpy(&regionY, Data, sizeof(int));
    Data += sizeof(int);
    Size -= sizeof(int);
    memcpy(&regionW, Data, sizeof(int));
    Data += sizeof(int);
    Size -= sizeof(int);
    memcpy(&regionH, Data, sizeof(int));
    Data += sizeof(int);
    Size -= sizeof(int);

    // Initialize TurboJPEG instance
    tjhandle handle = tj3Init(initType);
    if (!handle) {
        tj3GetErrorStr(NULL);
        return 0;
    }

    // Set a parameter
    if (tj3Set(handle, param, value) == -1) {
        tj3GetErrorStr(handle);
    }

    // Define a cropping region
    tjregion croppingRegion;
    croppingRegion.x = regionX;
    croppingRegion.y = regionY;
    croppingRegion.w = regionW;
    croppingRegion.h = regionH;

    // Set the cropping region
    if (tj3SetCroppingRegion(handle, croppingRegion) == -1) {
        tj3GetErrorStr(handle);
    }

    // Cleanup
    tj3Destroy(handle);

    return 0;
}