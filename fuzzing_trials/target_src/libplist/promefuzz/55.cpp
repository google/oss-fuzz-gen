// This fuzz driver is generated for library libplist, aiming to fuzz the following functions:
// plist_from_memory at plist.c:225:13 in plist.h
// plist_free at plist.c:712:6 in plist.h
// plist_from_openstep at oplist.c:1013:13 in plist.h
// plist_free at plist.c:712:6 in plist.h
// plist_from_bin at bplist.c:905:13 in plist.h
// plist_free at plist.c:712:6 in plist.h
// plist_from_json at jplist.c:954:13 in plist.h
// plist_free at plist.c:712:6 in plist.h
// plist_from_xml at xplist.c:1637:13 in plist.h
// plist_free at plist.c:712:6 in plist.h
// plist_read_from_file at plist.c:306:13 in plist.h
// plist_free at plist.c:712:6 in plist.h
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
#include "plist/plist.h"

extern "C" int LLVMFuzzerTestOneInput_55(const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return 0;
    }

    // Prepare variables for plist and format
    plist_t plist = nullptr;
    plist_format_t format;

    // Fuzz plist_from_memory
    plist_from_memory(reinterpret_cast<const char *>(Data), static_cast<uint32_t>(Size), &plist, &format);
    if (plist) {
        plist_free(plist);
        plist = nullptr;
    }

    // Fuzz plist_from_openstep
    plist_from_openstep(reinterpret_cast<const char *>(Data), static_cast<uint32_t>(Size), &plist);
    if (plist) {
        plist_free(plist);
        plist = nullptr;
    }

    // Fuzz plist_from_bin
    plist_from_bin(reinterpret_cast<const char *>(Data), static_cast<uint32_t>(Size), &plist);
    if (plist) {
        plist_free(plist);
        plist = nullptr;
    }

    // Fuzz plist_from_json
    plist_from_json(reinterpret_cast<const char *>(Data), static_cast<uint32_t>(Size), &plist);
    if (plist) {
        plist_free(plist);
        plist = nullptr;
    }

    // Fuzz plist_from_xml
    plist_from_xml(reinterpret_cast<const char *>(Data), static_cast<uint32_t>(Size), &plist);
    if (plist) {
        plist_free(plist);
        plist = nullptr;
    }

    // Fuzz plist_read_from_file
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);

        plist_read_from_file("./dummy_file", &plist, &format);
        if (plist) {
            plist_free(plist);
            plist = nullptr;
        }
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

        LLVMFuzzerTestOneInput_55(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    