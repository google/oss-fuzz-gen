#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_31(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient to create a non-NULL input
    if (size < sizeof(char*) * 2) {
        return 0;
    }

    // Allocate memory for the table
    char **table = (char **)malloc(sizeof(char*) * 2);
    if (table == NULL) {
        return 0;
    }

    // Allocate memory for the strings within the table
    table[0] = (char *)malloc(size / 2);
    table[1] = (char *)malloc(size / 2);
    if (table[0] == NULL || table[1] == NULL) {
        free(table[0]);
        free(table[1]);
        free(table);
        return 0;
    }

    // Copy data into the table strings
    memcpy(table[0], data, size / 2);
    memcpy(table[1], data + size / 2, size / 2);

    // Call the function-under-test
    sqlite3_free_table(table);

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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_31(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
