// This is the entry of 25 fuzz drivers:
// 1, 2, 4, 5, 7, 8, 9, 10, 11, 14, 16, 17, 21, 22, 25, 26, 30, 31, 32, 38, 39, 40,
//  45, 55, 58
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <memory.h>

// Declarations of all fuzz drivers `LLVMFuzzerTestOneInput` functions
int LLVMFuzzerTestOneInput_1(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_2(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_4(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_5(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_7(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_8(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_9(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_10(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_11(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_14(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_16(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_17(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_21(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_22(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_25(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_26(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_30(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_31(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_32(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_38(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_39(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_40(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_45(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_55(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_58(const uint8_t *Data, size_t Size);

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
            return LLVMFuzzerTestOneInput_2(remainData, remainSize);
        case 2:
            return LLVMFuzzerTestOneInput_4(remainData, remainSize);
        case 3:
            return LLVMFuzzerTestOneInput_5(remainData, remainSize);
        case 4:
            return LLVMFuzzerTestOneInput_7(remainData, remainSize);
        case 5:
            return LLVMFuzzerTestOneInput_8(remainData, remainSize);
        case 6:
            return LLVMFuzzerTestOneInput_9(remainData, remainSize);
        case 7:
            return LLVMFuzzerTestOneInput_10(remainData, remainSize);
        case 8:
            return LLVMFuzzerTestOneInput_11(remainData, remainSize);
        case 9:
            return LLVMFuzzerTestOneInput_14(remainData, remainSize);
        case 10:
            return LLVMFuzzerTestOneInput_16(remainData, remainSize);
        case 11:
            return LLVMFuzzerTestOneInput_17(remainData, remainSize);
        case 12:
            return LLVMFuzzerTestOneInput_21(remainData, remainSize);
        case 13:
            return LLVMFuzzerTestOneInput_22(remainData, remainSize);
        case 14:
            return LLVMFuzzerTestOneInput_25(remainData, remainSize);
        case 15:
            return LLVMFuzzerTestOneInput_26(remainData, remainSize);
        case 16:
            return LLVMFuzzerTestOneInput_30(remainData, remainSize);
        case 17:
            return LLVMFuzzerTestOneInput_31(remainData, remainSize);
        case 18:
            return LLVMFuzzerTestOneInput_32(remainData, remainSize);
        case 19:
            return LLVMFuzzerTestOneInput_38(remainData, remainSize);
        case 20:
            return LLVMFuzzerTestOneInput_39(remainData, remainSize);
        case 21:
            return LLVMFuzzerTestOneInput_40(remainData, remainSize);
        case 22:
            return LLVMFuzzerTestOneInput_45(remainData, remainSize);
        case 23:
            return LLVMFuzzerTestOneInput_55(remainData, remainSize);
        case 24:
            return LLVMFuzzerTestOneInput_58(remainData, remainSize);
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

