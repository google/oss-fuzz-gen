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
#include "magic.h"
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>

static magic_t createMagicSet() {
    return magic_open(MAGIC_NONE);
}

static void closeMagicSet(magic_t magic) {
    magic_close(magic);
}

extern "C" int LLVMFuzzerTestOneInput_2(const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return 0;
    }

    // Create a separate magic_set for each function
    magic_t magicSetList = createMagicSet();
    magic_t magicSetLoadBuffers = createMagicSet();
    magic_t magicSetBuffer = createMagicSet();
    magic_t magicSetGetParam = createMagicSet();
    magic_t magicSetCompile = createMagicSet();

    if (!magicSetList || !magicSetLoadBuffers || !magicSetBuffer || !magicSetGetParam || !magicSetCompile) {
        closeMagicSet(magicSetList);
        closeMagicSet(magicSetLoadBuffers);
        closeMagicSet(magicSetBuffer);
        closeMagicSet(magicSetGetParam);
        closeMagicSet(magicSetCompile);
        return 0;
    }

    // Dummy database file
    const char *dummyFile = "./dummy_file";
    FILE *file = fopen(dummyFile, "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }

    // Test magic_list
    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function magic_list with magic_check
    magic_check(magicSetList, dummyFile);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR

    // Test magic_load_buffers
    void *buffers[] = { (void *)Data };
    size_t sizes[] = { Size };
    magic_load_buffers(magicSetLoadBuffers, buffers, sizes, 1);

    // Test magic_buffer
    magic_buffer(magicSetBuffer, Data, Size);

    // Test magic_getparam
    int param = MAGIC_PARAM_INDIR_MAX;
    size_t val;
    magic_getparam(magicSetGetParam, param, &val);

    // Test magic_compile
    magic_compile(magicSetCompile, dummyFile);

    // Clean up
    closeMagicSet(magicSetList);
    closeMagicSet(magicSetLoadBuffers);
    closeMagicSet(magicSetBuffer);
    closeMagicSet(magicSetGetParam);
    closeMagicSet(magicSetCompile);

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

    LLVMFuzzerTestOneInput_2(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
