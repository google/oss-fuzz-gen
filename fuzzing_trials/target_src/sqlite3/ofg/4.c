#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>
#include <string.h>
#include <stdlib.h> // Include stdlib.h for malloc and free

int LLVMFuzzerTestOneInput_4(const uint8_t *data, size_t size) {
    // Ensure the data is null-terminated for use as a string
    char *vfs_name = (char *)malloc(size + 1);
    if (vfs_name == NULL) {
        return 0; // If memory allocation fails, exit early
    }

    memcpy(vfs_name, data, size);
    vfs_name[size] = '\0'; // Null-terminate the string

    // Call the function-under-test
    sqlite3_vfs *vfs = sqlite3_vfs_find(vfs_name);

    // Cleanup
    free(vfs_name);

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

    LLVMFuzzerTestOneInput_4(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
