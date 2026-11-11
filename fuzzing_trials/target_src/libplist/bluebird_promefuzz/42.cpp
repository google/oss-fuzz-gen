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
#include "plist/plist.h"

extern "C" int LLVMFuzzerTestOneInput_42(const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return 0;
    }

    // Testing plist_from_memory
    {
        plist_t plist = nullptr;
        plist_format_t format;
        plist_err_t err = plist_from_memory(reinterpret_cast<const char*>(Data), Size, &plist, &format);
        if (err == PLIST_ERR_SUCCESS && plist) {
            plist_free(plist);
        }
    }

    // Testing plist_from_openstep
    {
        plist_t plist = nullptr;
        plist_err_t err = plist_from_openstep(reinterpret_cast<const char*>(Data), Size, &plist);
        if (err == PLIST_ERR_SUCCESS && plist) {
            plist_free(plist);
        }
    }

    // Testing plist_from_bin
    {
        plist_t plist = nullptr;
        plist_err_t err = plist_from_bin(reinterpret_cast<const char*>(Data), Size, &plist);
        if (err == PLIST_ERR_SUCCESS && plist) {
            plist_free(plist);
        }
    
        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from plist_from_bin to plist_data_val_contains
        uint32_t ret_plist_array_get_size_rrbfv = plist_array_get_size(plist);
        if (ret_plist_array_get_size_rrbfv < 0){
        	return 0;
        }
        uint32_t ret_plist_array_get_item_index_jnlli = plist_array_get_item_index(0);
        if (ret_plist_array_get_item_index_jnlli < 0){
        	return 0;
        }
        int ret_plist_data_val_contains_fpsye = plist_data_val_contains(plist, (const uint8_t *)&ret_plist_array_get_size_rrbfv, (size_t )ret_plist_array_get_item_index_jnlli);
        if (ret_plist_data_val_contains_fpsye < 0){
        	return 0;
        }
        // End mutation: Producer.APPEND_MUTATOR
        
}

    // Testing plist_from_json
    {
        plist_t plist = nullptr;
        plist_err_t err = plist_from_json(reinterpret_cast<const char*>(Data), Size, &plist);
        if (err == PLIST_ERR_SUCCESS && plist) {
            plist_free(plist);
        }
    }

    // Testing plist_from_xml
    {
        plist_t plist = nullptr;
        plist_err_t err = plist_from_xml(reinterpret_cast<const char*>(Data), Size, &plist);
        if (err == PLIST_ERR_SUCCESS && plist) {
            plist_free(plist);
        }
    }

    // Testing plist_write_to_file
    {
        plist_t plist = nullptr;
        plist_err_t err = plist_from_memory(reinterpret_cast<const char*>(Data), Size, &plist, nullptr);
        if (err == PLIST_ERR_SUCCESS && plist) {
            const char *filename = "./dummy_file";
            plist_err_t write_err = plist_write_to_file(plist, filename, PLIST_FORMAT_XML, PLIST_OPT_NONE);
            if (write_err == PLIST_ERR_SUCCESS) {
                // File written successfully, handle further if needed
            }
            plist_free(plist);
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

    LLVMFuzzerTestOneInput_42(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
