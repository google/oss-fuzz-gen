#include <cstdint>
#include <cstdlib>
#include <cstdio>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_64(const uint8_t *data, size_t size) {
    // Call the function-under-test
    char *errorStr = tjGetErrorStr();

    // Check if the error string is not NULL and print it
    if (errorStr != NULL) {
        printf("Error String: %s\n", errorStr);
    }

    return 0;
}