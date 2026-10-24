// This fuzz driver is generated for library libplist, aiming to fuzz the following functions:
// plist_from_bin at bplist.c:905:13 in plist.h
// plist_to_bin at bplist.c:1360:13 in plist.h
// plist_mem_free at plist.c:720:6 in plist.h
// plist_to_openstep_with_options at oplist.c:557:13 in plist.h
// plist_mem_free at plist.c:720:6 in plist.h
// plist_to_openstep_with_options at oplist.c:557:13 in plist.h
// plist_mem_free at plist.c:720:6 in plist.h
// plist_to_json at jplist.c:495:13 in plist.h
// plist_mem_free at plist.c:720:6 in plist.h
// plist_write_to_stream at plist.c:2429:13 in plist.h
// plist_write_to_string at plist.c:2399:13 in plist.h
// plist_mem_free at plist.c:720:6 in plist.h
// plist_to_json_with_options at jplist.c:501:13 in plist.h
// plist_mem_free at plist.c:720:6 in plist.h
// plist_to_json_with_options at jplist.c:501:13 in plist.h
// plist_mem_free at plist.c:720:6 in plist.h
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
#include <cstdio>
#include <cstdlib>
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_33(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    plist_t plist = nullptr;
    plist_from_bin(reinterpret_cast<const char*>(Data), Size, &plist);

    if (plist) {
        char *output = nullptr;
        uint32_t length = 0;
        plist_err_t result;

        // Test plist_to_bin
        result = plist_to_bin(plist, &output, &length);
        if (result == PLIST_ERR_SUCCESS) {
            plist_mem_free(output);
        }

        // Test plist_to_openstep_with_options with different options
        result = plist_to_openstep_with_options(plist, &output, &length, PLIST_OPT_COMPACT);
        if (result == PLIST_ERR_SUCCESS) {
            plist_mem_free(output);
        }

        result = plist_to_openstep_with_options(plist, &output, &length, PLIST_OPT_COERCE);
        if (result == PLIST_ERR_SUCCESS) {
            plist_mem_free(output);
        }

        // Test plist_to_json
        result = plist_to_json(plist, &output, &length, 1);
        if (result == PLIST_ERR_SUCCESS) {
            plist_mem_free(output);
        }

        // Test plist_write_to_stream
        FILE *file = fopen("./dummy_file", "wb");
        if (file) {
            result = plist_write_to_stream(plist, file, PLIST_FORMAT_JSON, PLIST_OPT_NONE);
            fclose(file);
        }

        // Test plist_write_to_string
        result = plist_write_to_string(plist, &output, &length, PLIST_FORMAT_XML, PLIST_OPT_NONE);
        if (result == PLIST_ERR_SUCCESS) {
            plist_mem_free(output);
        }

        // Test plist_to_json_with_options with different options
        result = plist_to_json_with_options(plist, &output, &length, PLIST_OPT_COMPACT);
        if (result == PLIST_ERR_SUCCESS) {
            plist_mem_free(output);
        }

        result = plist_to_json_with_options(plist, &output, &length, PLIST_OPT_COERCE);
        if (result == PLIST_ERR_SUCCESS) {
            plist_mem_free(output);
        }

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

        LLVMFuzzerTestOneInput_33(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    