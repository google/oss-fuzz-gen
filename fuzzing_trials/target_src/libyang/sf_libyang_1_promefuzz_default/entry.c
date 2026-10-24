// This is the entry of 32 fuzz drivers:
// 2, 4, 8, 9, 10, 12, 13, 15, 16, 22, 23, 25, 31, 34, 36, 37, 39, 41, 45, 47, 49, 
// 50, 51, 52, 53, 54, 56, 57, 61, 71, 78, 84
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <memory.h>

// Declarations of all fuzz drivers `LLVMFuzzerTestOneInput` functions
int LLVMFuzzerTestOneInput_2(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_4(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_8(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_9(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_10(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_12(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_13(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_15(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_16(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_22(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_23(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_25(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_31(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_34(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_36(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_37(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_39(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_41(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_45(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_47(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_49(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_50(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_51(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_52(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_53(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_54(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_56(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_57(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_61(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_71(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_78(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_84(const uint8_t *Data, size_t Size);

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
    switch (driverIndex % 32) {
        case 0:
            return LLVMFuzzerTestOneInput_2(remainData, remainSize);
        case 1:
            return LLVMFuzzerTestOneInput_4(remainData, remainSize);
        case 2:
            return LLVMFuzzerTestOneInput_8(remainData, remainSize);
        case 3:
            return LLVMFuzzerTestOneInput_9(remainData, remainSize);
        case 4:
            return LLVMFuzzerTestOneInput_10(remainData, remainSize);
        case 5:
            return LLVMFuzzerTestOneInput_12(remainData, remainSize);
        case 6:
            return LLVMFuzzerTestOneInput_13(remainData, remainSize);
        case 7:
            return LLVMFuzzerTestOneInput_15(remainData, remainSize);
        case 8:
            return LLVMFuzzerTestOneInput_16(remainData, remainSize);
        case 9:
            return LLVMFuzzerTestOneInput_22(remainData, remainSize);
        case 10:
            return LLVMFuzzerTestOneInput_23(remainData, remainSize);
        case 11:
            return LLVMFuzzerTestOneInput_25(remainData, remainSize);
        case 12:
            return LLVMFuzzerTestOneInput_31(remainData, remainSize);
        case 13:
            return LLVMFuzzerTestOneInput_34(remainData, remainSize);
        case 14:
            return LLVMFuzzerTestOneInput_36(remainData, remainSize);
        case 15:
            return LLVMFuzzerTestOneInput_37(remainData, remainSize);
        case 16:
            return LLVMFuzzerTestOneInput_39(remainData, remainSize);
        case 17:
            return LLVMFuzzerTestOneInput_41(remainData, remainSize);
        case 18:
            return LLVMFuzzerTestOneInput_45(remainData, remainSize);
        case 19:
            return LLVMFuzzerTestOneInput_47(remainData, remainSize);
        case 20:
            return LLVMFuzzerTestOneInput_49(remainData, remainSize);
        case 21:
            return LLVMFuzzerTestOneInput_50(remainData, remainSize);
        case 22:
            return LLVMFuzzerTestOneInput_51(remainData, remainSize);
        case 23:
            return LLVMFuzzerTestOneInput_52(remainData, remainSize);
        case 24:
            return LLVMFuzzerTestOneInput_53(remainData, remainSize);
        case 25:
            return LLVMFuzzerTestOneInput_54(remainData, remainSize);
        case 26:
            return LLVMFuzzerTestOneInput_56(remainData, remainSize);
        case 27:
            return LLVMFuzzerTestOneInput_57(remainData, remainSize);
        case 28:
            return LLVMFuzzerTestOneInput_61(remainData, remainSize);
        case 29:
            return LLVMFuzzerTestOneInput_71(remainData, remainSize);
        case 30:
            return LLVMFuzzerTestOneInput_78(remainData, remainSize);
        case 31:
            return LLVMFuzzerTestOneInput_84(remainData, remainSize);
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

