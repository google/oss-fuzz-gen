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
#include <cstdarg>
#include "plist/plist.h"

static plist_t access_pathv_wrapper(plist_t node, uint32_t length, ...) {
    va_list args;
    va_start(args, length);
    plist_t result = plist_access_pathv(node, length, args);
    va_end(args);
    return result;
}

extern "C" int LLVMFuzzerTestOneInput_39(const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return 0;
    }

    // Create a plist node from input data
    plist_t node = nullptr;
    plist_from_bin((const char *)Data, Size, &node);

    if (node == nullptr) {
        return 0;
    }

    // Test plist_copy

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from plist_from_bin to plist_from_xml
    uint32_t ret_plist_dict_get_size_xrdfs = plist_dict_get_size(0);
    if (ret_plist_dict_get_size_xrdfs < 0){
    	return 0;
    }
    plist_err_t ret_plist_from_xml_ydbvm = plist_from_xml((const char *)"w", ret_plist_dict_get_size_xrdfs, &node);
    // End mutation: Producer.APPEND_MUTATOR
    
    plist_t copied_node = plist_copy(node);
    if (copied_node != nullptr) {
        plist_free(copied_node);
    }

    // Test plist_to_bin
    char *plist_bin = nullptr;
    uint32_t bin_length = 0;
    plist_err_t bin_err = plist_to_bin(node, &plist_bin, &bin_length);
    if (bin_err == PLIST_ERR_SUCCESS) {
        plist_mem_free(plist_bin);
    }

    // Test plist_to_xml
    char *plist_xml = nullptr;
    uint32_t xml_length = 0;
    plist_err_t xml_err = plist_to_xml(node, &plist_xml, &xml_length);
    if (xml_err == PLIST_ERR_SUCCESS) {
        plist_mem_free(plist_xml);
    }

    // Test plist_get_data_val
    char *data_val = nullptr;
    uint64_t data_length = 0;
    plist_get_data_val(node, &data_val, &data_length);
    if (data_val != nullptr) {
        plist_mem_free(data_val);
    }

    // Test plist_access_pathv with fixed keys
    plist_t accessed_node = access_pathv_wrapper(node, 2, "key1", "key2");

    // Test plist_write_to_file
    plist_err_t write_err = plist_write_to_file(node, "./dummy_file", PLIST_FORMAT_XML, PLIST_OPT_NONE);

    plist_free(node);
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

    LLVMFuzzerTestOneInput_39(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
