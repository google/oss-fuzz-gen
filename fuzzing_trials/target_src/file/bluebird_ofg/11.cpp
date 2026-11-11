#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern "C" {
    #include "magic.h" // Include the header where magic_list is declared
}

extern "C" int LLVMFuzzerTestOneInput_11(const uint8_t *data, size_t size) {
    // Ensure the data is null-terminated for use as a string
    char *input_str = (char *)malloc(size + 1);
    if (input_str == NULL) {
        return 0;
    }
    memcpy(input_str, data, size);
    input_str[size] = '\0';

    // Create a temporary file to pass as a filename
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        free(input_str);
        return 0;
    }
    write(fd, data, size);
    close(fd);

    // Initialize a magic_set structure
    struct magic_set *magic = magic_open(MAGIC_NONE);
    if (magic == NULL) {
        unlink(tmpl);
        free(input_str);
        return 0;
    }

    // Call the function-under-test
    magic_list(magic, tmpl);

    // Clean up

    // Begin mutation: Producer.SPLICE_MUTATOR - Spliced data flow from magic_list to magic_buffer using the plateau pool
    char *null_terminated_data = new char[size + 1];
    // Ensure dataflow is valid (i.e., non-null)
    if (!magic) {
    	return 0;
    }
    const char* ret_magic_buffer_mazmg = magic_buffer(magic, null_terminated_data, size);
    if (ret_magic_buffer_mazmg == NULL){
    	return 0;
    }
    // End mutation: Producer.SPLICE_MUTATOR
    
    magic_close(magic);
    unlink(tmpl);
    free(input_str);

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

    LLVMFuzzerTestOneInput_11(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
