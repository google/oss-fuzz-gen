// This fuzz driver is generated for library libplist, aiming to fuzz the following functions:
// plist_set_debug at plist.c:2321:6 in plist.h
// plist_from_bin at bplist.c:905:13 in plist.h
// plist_to_xml at xplist.c:574:13 in plist.h
// plist_mem_free at plist.c:720:6 in plist.h
// plist_to_openstep at oplist.c:551:13 in plist.h
// plist_mem_free at plist.c:720:6 in plist.h
// plist_print at plist.c:2487:6 in plist.h
// plist_write_to_stream at plist.c:2429:13 in plist.h
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
#include <cstdio>
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_40(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Fuzz plist_set_debug
    int debug_level = Data[0] % 2; // 0 or 1
    plist_set_debug(debug_level);

    // Fuzz plist_from_bin
    plist_t plist = nullptr;
    plist_err_t err = plist_from_bin(reinterpret_cast<const char*>(Data), static_cast<uint32_t>(Size), &plist);
    if (err != PLIST_ERR_SUCCESS) {
        return 0;
    }

    // Fuzz plist_to_xml
    char *plist_xml = nullptr;
    uint32_t xml_length = 0;
    err = plist_to_xml(plist, &plist_xml, &xml_length);
    if (err == PLIST_ERR_SUCCESS && plist_xml) {
        plist_mem_free(plist_xml);
    }

    // Fuzz plist_to_openstep
    char *plist_openstep = nullptr;
    uint32_t openstep_length = 0;
    int prettify = Data[0] % 2; // 0 or 1
    err = plist_to_openstep(plist, &plist_openstep, &openstep_length, prettify);
    if (err == PLIST_ERR_SUCCESS && plist_openstep) {
        plist_mem_free(plist_openstep);
    }

    // Fuzz plist_print
    plist_print(plist);

    // Fuzz plist_write_to_stream
    FILE *dummy_file = fopen("./dummy_file", "w");
    if (dummy_file) {
        plist_format_t format = static_cast<plist_format_t>(Data[0] % 13); // 0 to 12
        plist_write_options_t options = static_cast<plist_write_options_t>(Data[0] % 32); // 0 to 31
        err = plist_write_to_stream(plist, dummy_file, format, options);
        fclose(dummy_file);
    }

    // Clean up
    if (plist) {
        plist_free(plist);
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

        LLVMFuzzerTestOneInput_40(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    