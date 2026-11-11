// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_vanew at icalcomponent.c:113:16 in icalcomponent.h
// icalcomponent_new at icalcomponent.c:108:16 in icalcomponent.h
// icalcomponent_new_vvoter at icalcomponent.c:2164:16 in icalcomponent.h
// icalcomponent_new_vpoll at icalcomponent.c:2159:16 in icalcomponent.h
// icalcomponent_new_xstandard at icalcomponent.c:2124:16 in icalcomponent.h
// icalcomponent_new_xvote at icalcomponent.c:2169:16 in icalcomponent.h
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
#include <cstdarg>
#include <cstdio>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include <icalcomponent.h>

static void fuzz_icalcomponent_new(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(icalcomponent_kind)) return;

    icalcomponent_kind kind = static_cast<icalcomponent_kind>(*Data);
    icalcomponent *component = icalcomponent_new(kind);
    if (component) {
        icalcomponent_free(component);
    }
}

static void fuzz_icalcomponent_new_vvoter() {
    icalcomponent *component = icalcomponent_new_vvoter();
    if (component) {
        icalcomponent_free(component);
    }
}

static void fuzz_icalcomponent_vanew(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(icalcomponent_kind)) return;

    icalcomponent_kind kind = static_cast<icalcomponent_kind>(*Data);
    icalcomponent *component = icalcomponent_vanew(kind, nullptr);
    if (component) {
        icalcomponent_free(component);
    }
}

static void fuzz_icalcomponent_new_xstandard() {
    icalcomponent *component = icalcomponent_new_xstandard();
    if (component) {
        icalcomponent_free(component);
    }
}

static void fuzz_icalcomponent_new_xvote() {
    icalcomponent *component = icalcomponent_new_xvote();
    if (component) {
        icalcomponent_free(component);
    }
}

static void fuzz_icalcomponent_new_vpoll() {
    icalcomponent *component = icalcomponent_new_vpoll();
    if (component) {
        icalcomponent_free(component);
    }
}

extern "C" int LLVMFuzzerTestOneInput_53(const uint8_t *Data, size_t Size) {
    fuzz_icalcomponent_new(Data, Size);
    fuzz_icalcomponent_new_vvoter();
    fuzz_icalcomponent_vanew(Data, Size);
    fuzz_icalcomponent_new_xstandard();
    fuzz_icalcomponent_new_xvote();
    fuzz_icalcomponent_new_vpoll();
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

        LLVMFuzzerTestOneInput_53(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    