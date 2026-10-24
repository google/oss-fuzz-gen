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
#include <fcntl.h>
#include <unistd.h>
#include <iostream>

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    int fd = open("./dummy_file", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd != -1) {
        write(fd, Data, Size);
        close(fd);
    }
}

extern "C" int LLVMFuzzerTestOneInput_16(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Prepare a dummy file for testing
    write_dummy_file(Data, Size);

    // Create a new magic_set
    magic_t ms = magic_open(MAGIC_NONE);
    if (ms == nullptr) {
        return 0;
    }

    // Test magic_load with dummy file
    magic_load(ms, "./dummy_file");

    // Test magic_check with dummy file

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from magic_load to magic_buffer
    // Ensure dataflow is valid (i.e., non-null)
    if (!ms) {
    	return 0;
    }
    int ret_magic_getflags_ycxjx = magic_getflags(ms);
    if (ret_magic_getflags_ycxjx < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ms) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ms) {
    	return 0;
    }
    const char* ret_magic_buffer_exruy = magic_buffer(ms, (const void *)ms, MAGIC_PARAM_REGEX_MAX);
    if (ret_magic_buffer_exruy == NULL){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    magic_check(ms, "./dummy_file");

    // Test magic_setflags with a random flag from input
    int flags = Data[0];  // Use the first byte as a flag
    magic_setflags(ms, flags);

    // Test magic_getflags
    magic_getflags(ms);

    // Test magic_setparam with a random parameter and value from input
    int param = Data[0] % 5;  // Just a simple way to get a parameter type
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 1 of magic_setparam
    magic_setparam(ms, 0, &Size);
    // End mutation: Producer.REPLACE_ARG_MUTATOR

    // Test magic_descriptor with dummy file descriptor
    int fd = open("./dummy_file", O_RDONLY);
    if (fd != -1) {
        magic_descriptor(ms, fd);
        close(fd);
    }

    // Clean up
    magic_close(ms);

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

    LLVMFuzzerTestOneInput_16(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
