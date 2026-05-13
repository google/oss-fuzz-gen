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
#include <fstream>
#include "plist/plist.h"

static void fuzz_plist_from_memory(const uint8_t *Data, size_t Size) {
    plist_t plist = nullptr;
    plist_format_t format;
    plist_err_t err = plist_from_memory(reinterpret_cast<const char*>(Data), static_cast<uint32_t>(Size), &plist, &format);
    if (err == PLIST_ERR_SUCCESS && plist) {
        plist_free(plist);
    }
}

static void fuzz_plist_from_bin(const uint8_t *Data, size_t Size) {
    plist_t plist = nullptr;
    plist_err_t err = plist_from_bin(reinterpret_cast<const char*>(Data), static_cast<uint32_t>(Size), &plist);
    if (err == PLIST_ERR_SUCCESS && plist) {
        plist_free(plist);
    }
}

static void fuzz_plist_from_json(const uint8_t *Data, size_t Size) {
    plist_t plist = nullptr;
    plist_err_t err = plist_from_json(reinterpret_cast<const char*>(Data), static_cast<uint32_t>(Size), &plist);
    if (err == PLIST_ERR_SUCCESS && plist) {
        plist_free(plist);
    }
}

static void fuzz_plist_from_xml(const uint8_t *Data, size_t Size) {
    plist_t plist = nullptr;
    plist_err_t err = plist_from_xml(reinterpret_cast<const char*>(Data), static_cast<uint32_t>(Size), &plist);
    if (err == PLIST_ERR_SUCCESS && plist) {
        plist_free(plist);
    }
}

static void fuzz_plist_read_from_file(const uint8_t *Data, size_t Size) {
    std::ofstream file("./dummy_file", std::ios::binary);
    if (file.is_open()) {
        file.write(reinterpret_cast<const char*>(Data), Size);
        file.close();

        plist_t plist = nullptr;
        plist_format_t format;
        plist_err_t err = plist_read_from_file("./dummy_file", &plist, &format);
        if (err == PLIST_ERR_SUCCESS && plist) {
            plist_free(plist);
        }
    }
}

static void fuzz_plist_write_to_file(const uint8_t *Data, size_t Size) {
    plist_t plist = nullptr;
    plist_err_t err = plist_from_memory(reinterpret_cast<const char*>(Data), static_cast<uint32_t>(Size), &plist, nullptr);
    if (err == PLIST_ERR_SUCCESS && plist) {
        err = plist_write_to_file(plist, "./dummy_file", PLIST_FORMAT_XML, PLIST_OPT_NONE);
        plist_free(plist);
    }
}

extern "C" int LLVMFuzzerTestOneInput_14(const uint8_t *Data, size_t Size) {
    fuzz_plist_from_memory(Data, Size);
    fuzz_plist_from_bin(Data, Size);
    fuzz_plist_from_json(Data, Size);
    fuzz_plist_from_xml(Data, Size);
    fuzz_plist_read_from_file(Data, Size);
    fuzz_plist_write_to_file(Data, Size);
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

    LLVMFuzzerTestOneInput_14(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
