// This is the entry of 19 fuzz drivers:
// 14, 18, 26, 29, 36, 50, 52, 53, 55, 56, 57, 62, 66, 67, 68, 69, 73, 78, 79
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <memory.h>

// Declarations of all fuzz drivers `LLVMFuzzerTestOneInput` functions
int LLVMFuzzerTestOneInput_14(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_18(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_26(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_29(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_36(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_50(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_52(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_53(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_55(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_56(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_57(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_62(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_66(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_67(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_68(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_69(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_73(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_78(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_79(const uint8_t *Data, size_t Size);

// Entry function
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Driver selector
    if (Size < 1) {
        return 0;
    }
    const uint8_t *selector = Data;
    unsigned int driverIndex = 0;
    memcpy(&driverIndex, selector, 1);

    // Remain data and size
    const uint8_t *remainData = Data + 1;
    size_t remainSize = Size - 1;
    if (remainSize == 0) {
        return 0;
    }

    // Select driver
    switch (driverIndex % 19) {
        case 0:
            return LLVMFuzzerTestOneInput_14(remainData, remainSize);
        case 1:
            return LLVMFuzzerTestOneInput_18(remainData, remainSize);
        case 2:
            return LLVMFuzzerTestOneInput_26(remainData, remainSize);
        case 3:
            return LLVMFuzzerTestOneInput_29(remainData, remainSize);
        case 4:
            return LLVMFuzzerTestOneInput_36(remainData, remainSize);
        case 5:
            return LLVMFuzzerTestOneInput_50(remainData, remainSize);
        case 6:
            return LLVMFuzzerTestOneInput_52(remainData, remainSize);
        case 7:
            return LLVMFuzzerTestOneInput_53(remainData, remainSize);
        case 8:
            return LLVMFuzzerTestOneInput_55(remainData, remainSize);
        case 9:
            return LLVMFuzzerTestOneInput_56(remainData, remainSize);
        case 10:
            return LLVMFuzzerTestOneInput_57(remainData, remainSize);
        case 11:
            return LLVMFuzzerTestOneInput_62(remainData, remainSize);
        case 12:
            return LLVMFuzzerTestOneInput_66(remainData, remainSize);
        case 13:
            return LLVMFuzzerTestOneInput_67(remainData, remainSize);
        case 14:
            return LLVMFuzzerTestOneInput_68(remainData, remainSize);
        case 15:
            return LLVMFuzzerTestOneInput_69(remainData, remainSize);
        case 16:
            return LLVMFuzzerTestOneInput_73(remainData, remainSize);
        case 17:
            return LLVMFuzzerTestOneInput_78(remainData, remainSize);
        case 18:
            return LLVMFuzzerTestOneInput_79(remainData, remainSize);
        default:
            return 0;
    }
    return 0;
}

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

    if(size < 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size+1);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);
    data[size] = '\0';

    LLVMFuzzerTestOneInput(data, size);

    free(data);
    fclose(f);
    return 0;
}

