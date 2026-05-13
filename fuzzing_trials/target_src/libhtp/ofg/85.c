#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Assuming bstr is a structure defined somewhere in the codebase
typedef struct {
    char *data;
    size_t length;
} bstr;

// To avoid multiple definition errors, we declare bstr_add as static
static bstr * bstr_add(bstr *str1, const bstr *str2) {
    if (str1 == NULL || str2 == NULL) return NULL;

    size_t new_length = str1->length + str2->length;
    char *new_data = (char *)malloc(new_length + 1);
    if (new_data == NULL) return NULL;

    memcpy(new_data, str1->data, str1->length);
    memcpy(new_data + str1->length, str2->data, str2->length);
    new_data[new_length] = '\0';

    bstr *new_bstr = (bstr *)malloc(sizeof(bstr));
    if (new_bstr == NULL) {
        free(new_data);
        return NULL;
    }

    new_bstr->data = new_data;
    new_bstr->length = new_length;
    return new_bstr;
}

int LLVMFuzzerTestOneInput_85(const uint8_t *data, size_t size) {
    if (size < 2) return 0; // Ensure there is enough data to split

    // Split the input data into two parts
    size_t mid = size / 2;

    bstr str1;
    str1.data = (char *)malloc(mid + 1);
    if (str1.data == NULL) return 0;
    memcpy(str1.data, data, mid);
    str1.data[mid] = '\0';
    str1.length = mid;

    bstr str2;
    str2.data = (char *)malloc(size - mid + 1);
    if (str2.data == NULL) {
        free(str1.data);
        return 0;
    }
    memcpy(str2.data, data + mid, size - mid);
    str2.data[size - mid] = '\0';
    str2.length = size - mid;

    // Call the function-under-test
    bstr *result = bstr_add(&str1, &str2);

    // Clean up
    free(str1.data);
    free(str2.data);
    if (result != NULL) {
        free(result->data);
        free(result);
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

    LLVMFuzzerTestOneInput_85(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
