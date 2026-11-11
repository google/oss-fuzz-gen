// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_get_status at icalcomponent.c:2066:26 in icalcomponent.h
// icalcomponent_set_status at icalcomponent.c:2054:6 in icalcomponent.h
// icalcomponent_new_vtodo at icalcomponent.c:2099:16 in icalcomponent.h
// icalcomponent_convert_errors at icalcomponent.c:1211:6 in icalcomponent.h
// icalcomponent_set_sequence at icalcomponent.c:2019:6 in icalcomponent.h
// icalcomponent_clone at icalcomponent.c:137:16 in icalcomponent.h
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
#include <cstdlib>
#include <fstream>
#include <iostream>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "icalcomponent.h"

static void fuzz_icalcomponent_set_sequence(icalcomponent *comp, const uint8_t *data, size_t size) {
    if (size < sizeof(int)) return;
    int sequence = *reinterpret_cast<const int*>(data);
    icalcomponent_set_sequence(comp, sequence);
}

static void fuzz_icalcomponent_clone(icalcomponent *comp) {
    icalcomponent *clone = icalcomponent_clone(comp);
    if (clone) {
        icalcomponent_free(clone);
    }
}

static void fuzz_icalcomponent_get_status(icalcomponent *comp) {
    icalproperty_status status = icalcomponent_get_status(comp);
    (void)status; // Suppress unused variable warning
}

static void fuzz_icalcomponent_set_status(icalcomponent *comp, const uint8_t *data, size_t size) {
    if (size < sizeof(icalproperty_status)) return;
    icalproperty_status status = *reinterpret_cast<const icalproperty_status*>(data);
    icalcomponent_set_status(comp, status);
}

static void fuzz_icalcomponent_convert_errors(icalcomponent *comp) {
    icalcomponent_convert_errors(comp);
}

extern "C" int LLVMFuzzerTestOneInput_14(const uint8_t *Data, size_t Size) {
    // Create a new VTODO component
    icalcomponent *comp = icalcomponent_new_vtodo();
    if (!comp) return 0;

    // Fuzz each function with the input data
    fuzz_icalcomponent_set_sequence(comp, Data, Size);
    fuzz_icalcomponent_clone(comp);
    fuzz_icalcomponent_get_status(comp);
    fuzz_icalcomponent_set_status(comp, Data, Size);
    fuzz_icalcomponent_convert_errors(comp);

    // Cleanup
    icalcomponent_free(comp);

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

        LLVMFuzzerTestOneInput_14(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    