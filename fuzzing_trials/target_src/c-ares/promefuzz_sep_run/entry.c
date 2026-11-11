// This is the entry of 25 fuzz drivers:
// 1, 3, 5, 7, 8, 9, 11, 13, 14, 15, 16, 18, 20, 22, 24, 28, 32, 33, 34, 35, 38, 42
// , 44, 49, 85
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <memory.h>

// Declarations of all fuzz drivers `LLVMFuzzerTestOneInput` functions
int LLVMFuzzerTestOneInput_1(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_3(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_5(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_7(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_8(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_9(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_11(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_13(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_14(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_15(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_16(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_18(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_20(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_22(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_24(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_28(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_32(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_33(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_34(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_35(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_38(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_42(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_44(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_49(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_85(const uint8_t *Data, size_t Size);

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
    switch (driverIndex % 25) {
        case 0:
            return LLVMFuzzerTestOneInput_1(remainData, remainSize);
        case 1:
            return LLVMFuzzerTestOneInput_3(remainData, remainSize);
        case 2:
            return LLVMFuzzerTestOneInput_5(remainData, remainSize);
        case 3:
            return LLVMFuzzerTestOneInput_7(remainData, remainSize);
        case 4:
            return LLVMFuzzerTestOneInput_8(remainData, remainSize);
        case 5:
            return LLVMFuzzerTestOneInput_9(remainData, remainSize);
        case 6:
            return LLVMFuzzerTestOneInput_11(remainData, remainSize);
        case 7:
            return LLVMFuzzerTestOneInput_13(remainData, remainSize);
        case 8:
            return LLVMFuzzerTestOneInput_14(remainData, remainSize);
        case 9:
            return LLVMFuzzerTestOneInput_15(remainData, remainSize);
        case 10:
            return LLVMFuzzerTestOneInput_16(remainData, remainSize);
        case 11:
            return LLVMFuzzerTestOneInput_18(remainData, remainSize);
        case 12:
            return LLVMFuzzerTestOneInput_20(remainData, remainSize);
        case 13:
            return LLVMFuzzerTestOneInput_22(remainData, remainSize);
        case 14:
            return LLVMFuzzerTestOneInput_24(remainData, remainSize);
        case 15:
            return LLVMFuzzerTestOneInput_28(remainData, remainSize);
        case 16:
            return LLVMFuzzerTestOneInput_32(remainData, remainSize);
        case 17:
            return LLVMFuzzerTestOneInput_33(remainData, remainSize);
        case 18:
            return LLVMFuzzerTestOneInput_34(remainData, remainSize);
        case 19:
            return LLVMFuzzerTestOneInput_35(remainData, remainSize);
        case 20:
            return LLVMFuzzerTestOneInput_38(remainData, remainSize);
        case 21:
            return LLVMFuzzerTestOneInput_42(remainData, remainSize);
        case 22:
            return LLVMFuzzerTestOneInput_44(remainData, remainSize);
        case 23:
            return LLVMFuzzerTestOneInput_49(remainData, remainSize);
        case 24:
            return LLVMFuzzerTestOneInput_85(remainData, remainSize);
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

