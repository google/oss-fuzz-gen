#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Assuming bstr is a struct defined in the library
typedef struct {
    char *data;
    size_t length;
} bstr;

// Function prototype for the function-under-test
bstr *bstr_add_mem_noex(bstr *str, const void *mem, size_t len);

// Helper function to create a new bstr
bstr *create_bstr_48(const char *initial_data) {
    bstr *new_bstr = (bstr *)malloc(sizeof(bstr));
    if (new_bstr == NULL) {
        return NULL;
    }
    size_t data_len = strlen(initial_data);
    new_bstr->data = (char *)malloc(data_len + 1);
    if (new_bstr->data == NULL) {
        free(new_bstr);
        return NULL;
    }
    memcpy(new_bstr->data, initial_data, data_len);
    new_bstr->data[data_len] = '\0';
    new_bstr->length = data_len;
    return new_bstr;
}

// LLVMFuzzerTestOneInput function
int LLVMFuzzerTestOneInput_48(const uint8_t *data, size_t size) {
    // Create an initial bstr object
    bstr *initial_bstr = create_bstr_48("initial");
    if (initial_bstr == NULL) {
        return 0; // Exit if memory allocation fails
    }

    // Call the function-under-test
    bstr *result_bstr = bstr_add_mem_noex(initial_bstr, data, size);

    // Clean up
    if (result_bstr != NULL) {
        free(result_bstr->data);
        free(result_bstr);
    } else {
        free(initial_bstr->data);
        free(initial_bstr);
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

    LLVMFuzzerTestOneInput_48(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
