// This is the entry of 14 fuzz drivers:
// 1, 5, 7, 8, 11, 13, 24, 26, 30, 34, 42, 45, 49, 51
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <memory.h>

// Declarations of all fuzz drivers `LLVMFuzzerTestOneInput` functions
int LLVMFuzzerTestOneInput_1(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_5(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_7(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_8(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_11(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_13(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_24(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_26(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_30(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_34(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_42(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_45(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_49(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_51(const uint8_t *Data, size_t Size);

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
    switch (driverIndex % 14) {
        case 0:
            return LLVMFuzzerTestOneInput_1(remainData, remainSize);
        case 1:
            return LLVMFuzzerTestOneInput_5(remainData, remainSize);
        case 2:
            return LLVMFuzzerTestOneInput_7(remainData, remainSize);
        case 3:
            return LLVMFuzzerTestOneInput_8(remainData, remainSize);
        case 4:
            return LLVMFuzzerTestOneInput_11(remainData, remainSize);
        case 5:
            return LLVMFuzzerTestOneInput_13(remainData, remainSize);
        case 6:
            return LLVMFuzzerTestOneInput_24(remainData, remainSize);
        case 7:
            return LLVMFuzzerTestOneInput_26(remainData, remainSize);
        case 8:
            return LLVMFuzzerTestOneInput_30(remainData, remainSize);
        case 9:
            return LLVMFuzzerTestOneInput_34(remainData, remainSize);
        case 10:
            return LLVMFuzzerTestOneInput_42(remainData, remainSize);
        case 11:
            return LLVMFuzzerTestOneInput_45(remainData, remainSize);
        case 12:
            return LLVMFuzzerTestOneInput_49(remainData, remainSize);
        case 13:
            return LLVMFuzzerTestOneInput_51(remainData, remainSize);
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

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput(data, size);

    free(data);
    fclose(f);
    return 0;
}
