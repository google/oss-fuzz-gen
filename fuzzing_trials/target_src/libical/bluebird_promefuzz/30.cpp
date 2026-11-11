#include <sys/stat.h>
#include <string.h>
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
#include <cstring>
#include "libical/ical.h"
#include "libical/ical.h"
#include "libical/ical.h"
#include "/src/libical/src/libical/icalcomponent.h"

static void fuzz_icalcomponent_set_sequence(icalcomponent *comp, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return;
    int sequence = *reinterpret_cast<const int*>(Data);
    icalcomponent_set_sequence(comp, sequence);
}

static void fuzz_icalcomponent_get_sequence(icalcomponent *comp) {
    int sequence = icalcomponent_get_sequence(comp);
    (void)sequence; // Suppress unused variable warning
}

static void fuzz_icalcomponent_count_properties(icalcomponent *comp, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(icalproperty_kind)) return;
    icalproperty_kind kind = *reinterpret_cast<const icalproperty_kind*>(Data);
    int count = icalcomponent_count_properties(comp, kind);
    (void)count; // Suppress unused variable warning
}

static void fuzz_icalcomponent_new_x(const uint8_t *Data, size_t Size) {
    char *x_name = static_cast<char*>(malloc(Size + 1));
    if (!x_name) return;
    memcpy(x_name, Data, Size);
    x_name[Size] = '\0';
    icalcomponent *comp = icalcomponent_new_x(x_name);
    if (comp) {
        icalcomponent_free(comp);
    }
    free(x_name);
}

static void fuzz_icalcomponent_new_vpoll() {
    icalcomponent *comp = icalcomponent_new_vpoll();
    if (comp) {
        icalcomponent_free(comp);
    }
}

static void fuzz_icalcomponent_new_vfreebusy() {
    icalcomponent *comp = icalcomponent_new_vfreebusy();
    if (comp) {
        icalcomponent_free(comp);
    }
}

extern "C" int LLVMFuzzerTestOneInput_30(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Fuzz icalcomponent_new_vpoll
    fuzz_icalcomponent_new_vpoll();

    // Fuzz icalcomponent_new_vfreebusy
    fuzz_icalcomponent_new_vfreebusy();

    // Fuzz icalcomponent_new_x
    fuzz_icalcomponent_new_x(Data, Size);

    // Create a new dummy component
    icalcomponent *comp = icalcomponent_new_vpoll();
    if (!comp) return 0;

    // Fuzz icalcomponent_set_sequence
    fuzz_icalcomponent_set_sequence(comp, Data, Size);

    // Fuzz icalcomponent_get_sequence
    fuzz_icalcomponent_get_sequence(comp);

    // Fuzz icalcomponent_count_properties
    fuzz_icalcomponent_count_properties(comp, Data, Size);

    // Clean up
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

    LLVMFuzzerTestOneInput_30(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
