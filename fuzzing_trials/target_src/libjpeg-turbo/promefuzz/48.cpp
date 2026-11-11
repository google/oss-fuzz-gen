// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// tjInitDecompress at turbojpeg.c:1808:20 in turbojpeg.h
// tj3SetCroppingRegion at turbojpeg.c:2006:15 in turbojpeg.h
// tj3Get at turbojpeg.c:807:15 in turbojpeg.h
// tj3GetErrorCode at turbojpeg.c:643:15 in turbojpeg.h
// tj3SetScalingFactor at turbojpeg.c:1981:15 in turbojpeg.h
// tj3Set at turbojpeg.c:671:15 in turbojpeg.h
// tjGetErrorCode at turbojpeg.c:652:15 in turbojpeg.h
// tjDestroy at turbojpeg.c:601:15 in turbojpeg.h
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
#include <stdint.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <cstring>

static void writeDummyFile(const uint8_t* data, size_t size) {
    std::ofstream ofs("./dummy_file", std::ios::binary);
    ofs.write(reinterpret_cast<const char*>(data), size);
    ofs.close();
}

extern "C" int LLVMFuzzerTestOneInput_48(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(tjregion) + sizeof(tjscalingfactor) + 2 * sizeof(int)) {
        return 0;
    }

    tjhandle handle = tjInitDecompress();
    if (!handle) {
        return 0;
    }

    tjregion croppingRegion;
    memcpy(&croppingRegion, Data, sizeof(tjregion));
    Data += sizeof(tjregion);
    Size -= sizeof(tjregion);

    tjscalingfactor scalingFactor;
    memcpy(&scalingFactor, Data, sizeof(tjscalingfactor));
    Data += sizeof(tjscalingfactor);
    Size -= sizeof(tjscalingfactor);

    int param;
    memcpy(&param, Data, sizeof(int));
    Data += sizeof(int);
    Size -= sizeof(int);

    int value;
    memcpy(&value, Data, sizeof(int));
    Data += sizeof(int);
    Size -= sizeof(int);

    // Test tj3SetCroppingRegion
    tj3SetCroppingRegion(handle, croppingRegion);

    // Test tj3Get
    tj3Get(handle, param);

    // Test tj3GetErrorCode
    tj3GetErrorCode(handle);

    // Test tj3SetScalingFactor
    tj3SetScalingFactor(handle, scalingFactor);

    // Test tj3Set
    tj3Set(handle, param, value);

    // Test tjGetErrorCode
    tjGetErrorCode(handle);

    // Write remaining data to a dummy file for any file-based operations
    writeDummyFile(Data, Size);

    tjDestroy(handle);
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

        LLVMFuzzerTestOneInput_48(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    