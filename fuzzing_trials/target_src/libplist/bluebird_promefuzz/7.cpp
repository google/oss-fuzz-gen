#include <sys/stat.h>
#include <string.h>
#include <iostream>
#include <cstring>
#include "plist/plist.h"

extern "C" int LLVMFuzzerTestOneInput_7(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Ensure null-termination for string operations
    char* dataCopy = new char[Size + 1];
    memcpy(dataCopy, Data, Size);
    dataCopy[Size] = '\0';

    // Prepare a dummy PLIST_UID node
    plist_t uidnode = plist_new_uid(0);
    uint64_t cmpval = 0;
    if (Size >= sizeof(uint64_t))
        memcpy(&cmpval, Data, sizeof(uint64_t));
    plist_uid_val_compare(uidnode, cmpval);
    plist_free(uidnode);

    // Prepare a dummy PLIST_STRING node
    plist_t strnode = plist_new_string(dataCopy);
    plist_string_val_compare(strnode, dataCopy);
    plist_free(strnode);

    // Prepare a dummy PLIST_KEY node using plist_new_string
    plist_t keynode = plist_new_string(dataCopy);
    plist_key_val_compare(keynode, dataCopy);
    plist_key_val_compare_with_size(keynode, dataCopy, Size);
    plist_free(keynode);

    // Prepare a dummy PLIST_INT node
    plist_t intnode = plist_new_int(0);
    int64_t cmpint = 0;
    uint64_t cmpuint = 0;
    if (Size >= sizeof(int64_t))
        memcpy(&cmpint, Data, sizeof(int64_t));
    if (Size >= sizeof(uint64_t))
        memcpy(&cmpuint, Data, sizeof(uint64_t));
    plist_int_val_compare(intnode, cmpint);
    plist_uint_val_compare(intnode, cmpuint);
    plist_free(intnode);

    delete[] dataCopy;
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

    LLVMFuzzerTestOneInput_7(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
