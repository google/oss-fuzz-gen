#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern "C" {
    #include "magic.h"
}

extern "C" int LLVMFuzzerTestOneInput_3(const uint8_t *data, size_t size) {
    struct magic_set *magic;
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd;
    FILE *fp;

    // Initialize magic_set
    magic = magic_open(MAGIC_NONE);
    if (magic == NULL) {
        return 0;
    }

    // Create a temporary file and write the input data to it
    fd = mkstemp(tmpl);
    if (fd == -1) {
        magic_close(magic);
        return 0;
    }
    fp = fdopen(fd, "wb");
    if (fp == NULL) {
        close(fd);
        magic_close(magic);
        return 0;
    }
    fwrite(data, 1, size, fp);
    fclose(fp);

    // Call the function-under-test
    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function magic_list with magic_check
    magic_check(magic, tmpl);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR

    // Clean up

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from magic_check to magic_buffer
    // Ensure dataflow is valid (i.e., non-null)
    if (!magic) {
    	return 0;
    }
    int ret_magic_getflags_pbcdm = magic_getflags(magic);
    if (ret_magic_getflags_pbcdm < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!magic) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!magic) {
    	return 0;
    }
    const char* ret_magic_buffer_qxjwn = magic_buffer(magic, (const void *)magic, MAGIC_PARAM_ENCODING_MAX);
    if (ret_magic_buffer_qxjwn == NULL){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    unlink(tmpl);
    magic_close(magic);

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

    LLVMFuzzerTestOneInput_3(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
