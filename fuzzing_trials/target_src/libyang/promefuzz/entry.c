// This is the entry of 36 fuzz drivers:
// 4, 5, 6, 7, 10, 11, 15, 16, 24, 30, 32, 34, 35, 38, 39, 41, 43, 45, 46, 47, 49, 
// 54, 56, 57, 58, 59, 62, 69, 72, 77, 79, 80, 82, 83, 85, 91
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <memory.h>

// Declarations of all fuzz drivers `LLVMFuzzerTestOneInput` functions
int LLVMFuzzerTestOneInput_4(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_5(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_6(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_7(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_10(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_11(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_15(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_16(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_24(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_30(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_32(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_34(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_35(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_38(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_39(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_41(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_43(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_45(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_46(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_47(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_49(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_54(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_56(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_57(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_58(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_59(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_62(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_69(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_72(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_77(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_79(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_80(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_82(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_83(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_85(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_91(const uint8_t *Data, size_t Size);

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
    switch (driverIndex % 36) {
        case 0:
            return LLVMFuzzerTestOneInput_4(remainData, remainSize);
        case 1:
            return LLVMFuzzerTestOneInput_5(remainData, remainSize);
        case 2:
            return LLVMFuzzerTestOneInput_6(remainData, remainSize);
        case 3:
            return LLVMFuzzerTestOneInput_7(remainData, remainSize);
        case 4:
            return LLVMFuzzerTestOneInput_10(remainData, remainSize);
        case 5:
            return LLVMFuzzerTestOneInput_11(remainData, remainSize);
        case 6:
            return LLVMFuzzerTestOneInput_15(remainData, remainSize);
        case 7:
            return LLVMFuzzerTestOneInput_16(remainData, remainSize);
        case 8:
            return LLVMFuzzerTestOneInput_24(remainData, remainSize);
        case 9:
            return LLVMFuzzerTestOneInput_30(remainData, remainSize);
        case 10:
            return LLVMFuzzerTestOneInput_32(remainData, remainSize);
        case 11:
            return LLVMFuzzerTestOneInput_34(remainData, remainSize);
        case 12:
            return LLVMFuzzerTestOneInput_35(remainData, remainSize);
        case 13:
            return LLVMFuzzerTestOneInput_38(remainData, remainSize);
        case 14:
            return LLVMFuzzerTestOneInput_39(remainData, remainSize);
        case 15:
            return LLVMFuzzerTestOneInput_41(remainData, remainSize);
        case 16:
            return LLVMFuzzerTestOneInput_43(remainData, remainSize);
        case 17:
            return LLVMFuzzerTestOneInput_45(remainData, remainSize);
        case 18:
            return LLVMFuzzerTestOneInput_46(remainData, remainSize);
        case 19:
            return LLVMFuzzerTestOneInput_47(remainData, remainSize);
        case 20:
            return LLVMFuzzerTestOneInput_49(remainData, remainSize);
        case 21:
            return LLVMFuzzerTestOneInput_54(remainData, remainSize);
        case 22:
            return LLVMFuzzerTestOneInput_56(remainData, remainSize);
        case 23:
            return LLVMFuzzerTestOneInput_57(remainData, remainSize);
        case 24:
            return LLVMFuzzerTestOneInput_58(remainData, remainSize);
        case 25:
            return LLVMFuzzerTestOneInput_59(remainData, remainSize);
        case 26:
            return LLVMFuzzerTestOneInput_62(remainData, remainSize);
        case 27:
            return LLVMFuzzerTestOneInput_69(remainData, remainSize);
        case 28:
            return LLVMFuzzerTestOneInput_72(remainData, remainSize);
        case 29:
            return LLVMFuzzerTestOneInput_77(remainData, remainSize);
        case 30:
            return LLVMFuzzerTestOneInput_79(remainData, remainSize);
        case 31:
            return LLVMFuzzerTestOneInput_80(remainData, remainSize);
        case 32:
            return LLVMFuzzerTestOneInput_82(remainData, remainSize);
        case 33:
            return LLVMFuzzerTestOneInput_83(remainData, remainSize);
        case 34:
            return LLVMFuzzerTestOneInput_85(remainData, remainSize);
        case 35:
            return LLVMFuzzerTestOneInput_91(remainData, remainSize);
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

