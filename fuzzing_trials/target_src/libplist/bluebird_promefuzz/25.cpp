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
#include <cstdio>
#include <cstdlib>
#include "plist/plist.h"

extern "C" int LLVMFuzzerTestOneInput_25(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    plist_t plist = nullptr;
    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function plist_from_bin with plist_from_xml
    plist_from_xml(reinterpret_cast<const char*>(Data), Size, &plist);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR

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

        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from plist_to_bin to plist_set_date_val
        plist_t ret_plist_copy_rgead = plist_copy(plist);
        uint32_t ret_plist_array_get_size_uqczg = plist_array_get_size(plist);
        if (ret_plist_array_get_size_uqczg < 0){
        	return 0;
        }
        plist_set_date_val(ret_plist_copy_rgead, (int32_t )length, (int32_t )ret_plist_array_get_size_uqczg);
        // End mutation: Producer.APPEND_MUTATOR
        
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

    LLVMFuzzerTestOneInput_25(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
