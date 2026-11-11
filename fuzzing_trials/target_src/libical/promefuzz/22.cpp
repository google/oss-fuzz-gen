// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_set_location at icalcomponent.c:1984:6 in icalcomponent.h
// icalcomponent_set_comment at icalcomponent.c:1833:6 in icalcomponent.h
// icalcomponent_set_relcalid at icalcomponent.c:2627:6 in icalcomponent.h
// icalcomponent_set_description at icalcomponent.c:1949:6 in icalcomponent.h
// icalcomponent_set_summary at icalcomponent.c:1798:6 in icalcomponent.h
// icalcomponent_set_uid at icalcomponent.c:1868:6 in icalcomponent.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <iostream>
#include <string>
#include <cstdlib>
#include <cstring>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "icalcomponent.h"

static icalcomponent* create_random_component() {
    int kind_index = rand() % ICAL_NUM_COMPONENT_TYPES;
    icalcomponent_kind kind = static_cast<icalcomponent_kind>(kind_index);
    return icalcomponent_new(kind);
}

static void set_random_property(icalcomponent* comp, const char* data, size_t size) {
    if (size == 0) return;

    switch (rand() % 6) {
        case 0:
            icalcomponent_set_location(comp, data);
            break;
        case 1:
            icalcomponent_set_description(comp, data);
            break;
        case 2:
            icalcomponent_set_comment(comp, data);
            break;
        case 3:
            icalcomponent_set_summary(comp, data);
            break;
        case 4:
            icalcomponent_set_relcalid(comp, data);
            break;
        case 5:
            icalcomponent_set_uid(comp, data);
            break;
    }
}

extern "C" int LLVMFuzzerTestOneInput_22(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    char* buffer = new char[Size + 1];
    memcpy(buffer, Data, Size);
    buffer[Size] = '\0';

    icalcomponent* comp = create_random_component();
    if (comp != nullptr) {
        set_random_property(comp, buffer, Size);
        icalcomponent_free(comp);
    }

    delete[] buffer;
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

        LLVMFuzzerTestOneInput_22(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    