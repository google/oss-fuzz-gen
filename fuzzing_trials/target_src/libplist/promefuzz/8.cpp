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
// plist_from_memory at plist.c:225:13 in plist.h
// plist_write_to_file at plist.c:2473:13 in plist.h
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
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_8(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Prepare data for plist_from_memory
    plist_t plist_mem = nullptr;
    plist_format_t format_mem;
    plist_err_t err_mem = plist_from_memory(reinterpret_cast<const char*>(Data), static_cast<uint32_t>(Size), &plist_mem, &format_mem);
    if (err_mem == PLIST_ERR_SUCCESS) {
        plist_free(plist_mem);
    }

    // Prepare data for plist_from_openstep
    plist_t plist_openstep = nullptr;
    plist_err_t err_openstep = plist_from_openstep(reinterpret_cast<const char*>(Data), static_cast<uint32_t>(Size), &plist_openstep);
    if (err_openstep == PLIST_ERR_SUCCESS) {
        plist_free(plist_openstep);
    }

    // Prepare data for plist_from_bin
    plist_t plist_bin = nullptr;
    plist_err_t err_bin = plist_from_bin(reinterpret_cast<const char*>(Data), static_cast<uint32_t>(Size), &plist_bin);
    if (err_bin == PLIST_ERR_SUCCESS) {
        plist_free(plist_bin);
    }

    // Prepare data for plist_from_json
    plist_t plist_json = nullptr;
    plist_err_t err_json = plist_from_json(reinterpret_cast<const char*>(Data), static_cast<uint32_t>(Size), &plist_json);
    if (err_json == PLIST_ERR_SUCCESS) {
        plist_free(plist_json);
    }

    // Prepare data for plist_from_xml
    plist_t plist_xml = nullptr;
    plist_err_t err_xml = plist_from_xml(reinterpret_cast<const char*>(Data), static_cast<uint32_t>(Size), &plist_xml);
    if (err_xml == PLIST_ERR_SUCCESS) {
        plist_free(plist_xml);
    }

    // If data is large enough, attempt to write to a file
    if (Size > 1) {
        plist_t plist_file = nullptr;
        plist_err_t err_file = plist_from_memory(reinterpret_cast<const char*>(Data), static_cast<uint32_t>(Size), &plist_file, nullptr);
        if (err_file == PLIST_ERR_SUCCESS) {
            plist_write_to_file(plist_file, "./dummy_file", PLIST_FORMAT_XML, PLIST_OPT_NONE);
            plist_free(plist_file);
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

        LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    