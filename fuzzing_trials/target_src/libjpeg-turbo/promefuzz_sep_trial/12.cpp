// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// tj3Init at turbojpeg.c:538:20 in turbojpeg.h
// tj3Destroy at turbojpeg.c:580:16 in turbojpeg.h
// tj3GetErrorStr at turbojpeg.c:618:17 in turbojpeg.h
// tj3SetScalingFactor at turbojpeg.c:1981:15 in turbojpeg.h
// tj3GetErrorStr at turbojpeg.c:618:17 in turbojpeg.h
// tj3Set at turbojpeg.c:671:15 in turbojpeg.h
// tj3GetErrorStr at turbojpeg.c:618:17 in turbojpeg.h
// tj3SetCroppingRegion at turbojpeg.c:2006:15 in turbojpeg.h
// tj3GetErrorStr at turbojpeg.c:618:17 in turbojpeg.h
// tj3Init at turbojpeg.c:538:20 in turbojpeg.h
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
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <turbojpeg.h>

static void fuzz_tj3Init(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return; // Ensure enough data for an int
    int initType;
    memcpy(&initType, Data, sizeof(int));
    
    tjhandle handle = tj3Init(initType);
    if (handle) {
        tj3Destroy(handle);
    } else {
        tj3GetErrorStr(NULL);
    }
}

static void fuzz_tj3SetScalingFactor(tjhandle handle, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(tjscalingfactor)) return; // Ensure enough data for tjscalingfactor
    tjscalingfactor scalingFactor;
    memcpy(&scalingFactor, Data, sizeof(tjscalingfactor));

    tj3SetScalingFactor(handle, scalingFactor);
    tj3GetErrorStr(handle);
}

static void fuzz_tj3Set(tjhandle handle, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int) * 2) return; // Ensure enough data for two ints
    int param, value;
    memcpy(&param, Data, sizeof(int));
    memcpy(&value, Data + sizeof(int), sizeof(int));

    tj3Set(handle, param, value);
    tj3GetErrorStr(handle);
}

static void fuzz_tj3SetCroppingRegion(tjhandle handle, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(tjregion)) return; // Ensure enough data for tjregion
    tjregion croppingRegion;
    memcpy(&croppingRegion, Data, sizeof(tjregion));

    tj3SetCroppingRegion(handle, croppingRegion);
    tj3GetErrorStr(handle);
}

extern "C" int LLVMFuzzerTestOneInput_12(const uint8_t *Data, size_t Size) {
    fuzz_tj3Init(Data, Size);

    tjhandle handle = tj3Init(TJINIT_DECOMPRESS);
    if (handle) {
        fuzz_tj3SetScalingFactor(handle, Data, Size);
        fuzz_tj3Set(handle, Data, Size);
        fuzz_tj3SetCroppingRegion(handle, Data, Size);
        tj3Destroy(handle);
    }

    return 0;
}