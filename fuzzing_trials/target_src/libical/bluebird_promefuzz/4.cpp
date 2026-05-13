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
#include "libical/ical.h"
#include "libical/ical.h"
#include "libical/ical.h"
#include "/src/libical/src/libical/icalcomponent.h"
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

static void fuzz_icalcomponent_clone(icalcomponent *component) {
    if (component) {
        icalcomponent *cloned = icalcomponent_clone(component);
        if (cloned) {
            icalcomponent_free(cloned);
        }
    }
}

static void fuzz_icalcomponent_kind_to_string(icalcomponent_kind kind) {
    const char *kind_str = icalcomponent_kind_to_string(kind);
    if (kind_str) {
        // Use the string for further operations if needed
    }
}

static void fuzz_icalcomponent_isa(icalcomponent *component) {
    if (component) {
        icalcomponent_kind kind = icalcomponent_isa(component);
        fuzz_icalcomponent_kind_to_string(kind);
    }
}

static void fuzz_icalcomponent_string_to_kind(const char *string) {
    icalcomponent_kind kind = icalcomponent_string_to_kind(string);
    fuzz_icalcomponent_kind_to_string(kind);
}

static void fuzz_icalcomponent_get_component_name(icalcomponent *component) {
    if (component) {
        const char *name = icalcomponent_get_component_name(component);
        if (name) {
            // Use the name for further operations if needed
        }
    }
}

static void fuzz_icalcomponent_new_from_string(const char *str) {
    icalcomponent *component = icalcomponent_new_from_string(str);
    if (component) {
        fuzz_icalcomponent_clone(component);
        fuzz_icalcomponent_isa(component);
        fuzz_icalcomponent_get_component_name(component);
        icalcomponent_free(component);
    }
}

extern "C" int LLVMFuzzerTestOneInput_4(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Create a null-terminated string from the input data
    char *input = static_cast<char *>(malloc(Size + 1));
    if (!input) return 0;
    memcpy(input, Data, Size);
    input[Size] = '\0';

    // Fuzz different functions
    fuzz_icalcomponent_string_to_kind(input);
    fuzz_icalcomponent_new_from_string(input);

    // Clean up
    free(input);
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

    LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
