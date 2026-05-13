// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_new_x at icalcomponent.c:169:16 in icalcomponent.h
// icalcomponent_get_component_name_r at icalcomponent.c:395:7 in icalcomponent.h
// icalcomponent_set_relcalid at icalcomponent.c:2627:6 in icalcomponent.h
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
#include <cstring>
#include <iostream>
#include <fstream>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "icalcomponent.h"

static void fuzz_icalcomponent_set_x_name(icalcomponent *comp, const uint8_t *Data, size_t Size) {
    if (Size > 0) {
        char *name = new char[Size + 1];
        memcpy(name, Data, Size);
        name[Size] = '\0';
        icalcomponent_set_x_name(comp, name);
        delete[] name;
    }
}

static void fuzz_icalcomponent_get_x_name(const icalcomponent *comp) {
    const char *name = icalcomponent_get_x_name(comp);
    if (name) {
        std::cout << "X Name: " << name << std::endl;
    }
}

static icalcomponent* fuzz_icalcomponent_new_x(const uint8_t *Data, size_t Size) {
    if (Size > 0) {
        char *x_name = new char[Size + 1];
        memcpy(x_name, Data, Size);
        x_name[Size] = '\0';
        icalcomponent *comp = icalcomponent_new_x(x_name);
        delete[] x_name;
        return comp;
    }
    return nullptr;
}

static void fuzz_icalcomponent_set_relcalid(icalcomponent *comp, const uint8_t *Data, size_t Size) {
    if (Size > 0) {
        char *relcalid = new char[Size + 1];
        memcpy(relcalid, Data, Size);
        relcalid[Size] = '\0';
        icalcomponent_set_relcalid(comp, relcalid);
        delete[] relcalid;
    }
}

static void fuzz_icalcomponent_get_component_name_r(const icalcomponent *comp) {
    char *name = icalcomponent_get_component_name_r(comp);
    if (name) {
        std::cout << "Component Name: " << name << std::endl;
        free(name);
    }
}

extern "C" int LLVMFuzzerTestOneInput_43(const uint8_t *Data, size_t Size) {
    // Fuzz icalcomponent_new_x
    icalcomponent *comp_x = fuzz_icalcomponent_new_x(Data, Size);
    if (comp_x) {
        fuzz_icalcomponent_set_x_name(comp_x, Data, Size);
        fuzz_icalcomponent_get_x_name(comp_x);
        fuzz_icalcomponent_set_relcalid(comp_x, Data, Size);
        fuzz_icalcomponent_get_component_name_r(comp_x);
        icalcomponent_free(comp_x);
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

        if(size < 1 + 1)
            exit(0);

        data = (uint8_t *)malloc((size_t)size);
        if(data == NULL)
            exit(0);

        if(fread(data, (size_t)size, 1, f) != 1)
            exit(0);

        LLVMFuzzerTestOneInput_43(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    