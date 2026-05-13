// This fuzz driver is generated for library libplist, aiming to fuzz the following functions:
// plist_from_bin at bplist.c:905:13 in plist.h
// plist_to_bin at bplist.c:1360:13 in plist.h
// plist_mem_free at plist.c:720:6 in plist.h
// plist_to_xml at xplist.c:574:13 in plist.h
// plist_mem_free at plist.c:720:6 in plist.h
// plist_to_openstep at oplist.c:551:13 in plist.h
// plist_mem_free at plist.c:720:6 in plist.h
// plist_free at plist.c:712:6 in plist.h
// plist_set_debug at plist.c:2321:6 in plist.h
// plist_from_bin at bplist.c:905:13 in plist.h
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
extern "C" {
#include "plist.h"
}

#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>

static void handle_plist_from_bin(const uint8_t *Data, size_t Size) {
    plist_t plist = nullptr;
    plist_err_t result = plist_from_bin(reinterpret_cast<const char*>(Data), static_cast<uint32_t>(Size), &plist);
    if (result == PLIST_ERR_SUCCESS && plist) {
        char *plist_bin = nullptr;
        uint32_t length = 0;
        
        // Convert back to binary to test plist_to_bin
        result = plist_to_bin(plist, &plist_bin, &length);
        if (result == PLIST_ERR_SUCCESS && plist_bin) {
            plist_mem_free(plist_bin);
        }

        // Convert to XML to test plist_to_xml
        char *plist_xml = nullptr;
        result = plist_to_xml(plist, &plist_xml, &length);
        if (result == PLIST_ERR_SUCCESS && plist_xml) {
            plist_mem_free(plist_xml);
        }

        // Convert to OpenStep to test plist_to_openstep
        char *plist_openstep = nullptr;
        result = plist_to_openstep(plist, &plist_openstep, &length, 0);
        if (result == PLIST_ERR_SUCCESS && plist_openstep) {
            plist_mem_free(plist_openstep);
        }

        plist_free(plist);
    }
}

static void handle_plist_set_debug(const uint8_t *Data, size_t Size) {
    if (Size > 0) {
        int debug_level = Data[0] % 2; // Only 0 or 1 are valid
        plist_set_debug(debug_level);
    }
}

static void handle_plist_write_to_stream(const uint8_t *Data, size_t Size) {
    plist_t plist = nullptr;
    plist_err_t result = plist_from_bin(reinterpret_cast<const char*>(Data), static_cast<uint32_t>(Size), &plist);
    if (result == PLIST_ERR_SUCCESS && plist) {
        FILE *stream = fopen("./dummy_file", "w");
        if (stream) {
            plist_format_t format = static_cast<plist_format_t>(Data[0] % 13); // Use a valid format enum value
            plist_write_options_t options = static_cast<plist_write_options_t>(Data[0] % 32); // Use a valid option enum value
            plist_write_to_stream(plist, stream, format, options);
            fclose(stream);
        }
        plist_free(plist);
    }
}

extern "C" int LLVMFuzzerTestOneInput_13(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    handle_plist_from_bin(Data, Size);
    handle_plist_set_debug(Data, Size);
    handle_plist_write_to_stream(Data, Size);

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

        LLVMFuzzerTestOneInput_13(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    