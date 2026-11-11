// This is the entry of 28 fuzz drivers:
// 2, 5, 8, 12, 13, 17, 19, 21, 22, 26, 27, 28, 29, 31, 33, 34, 36, 37, 44, 45, 48,
//  55, 56, 64, 67, 75, 76, 81
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <memory.h>

// Declarations of all fuzz drivers `LLVMFuzzerTestOneInput` functions
int LLVMFuzzerTestOneInput_2(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_5(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_8(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_12(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_13(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_17(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_19(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_21(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_22(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_26(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_27(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_28(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_29(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_31(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_33(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_34(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_36(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_37(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_44(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_45(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_48(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_55(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_56(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_64(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_67(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_75(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_76(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_81(const uint8_t *Data, size_t Size);

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
    switch (driverIndex % 28) {
        case 0:
            return LLVMFuzzerTestOneInput_2(remainData, remainSize);
        case 1:
            return LLVMFuzzerTestOneInput_5(remainData, remainSize);
        case 2:
            return LLVMFuzzerTestOneInput_8(remainData, remainSize);
        case 3:
            return LLVMFuzzerTestOneInput_12(remainData, remainSize);
        case 4:
            return LLVMFuzzerTestOneInput_13(remainData, remainSize);
        case 5:
            return LLVMFuzzerTestOneInput_17(remainData, remainSize);
        case 6:
            return LLVMFuzzerTestOneInput_19(remainData, remainSize);
        case 7:
            return LLVMFuzzerTestOneInput_21(remainData, remainSize);
        case 8:
            return LLVMFuzzerTestOneInput_22(remainData, remainSize);
        case 9:
            return LLVMFuzzerTestOneInput_26(remainData, remainSize);
        case 10:
            return LLVMFuzzerTestOneInput_27(remainData, remainSize);
        case 11:
            return LLVMFuzzerTestOneInput_28(remainData, remainSize);
        case 12:
            return LLVMFuzzerTestOneInput_29(remainData, remainSize);
        case 13:
            return LLVMFuzzerTestOneInput_31(remainData, remainSize);
        case 14:
            return LLVMFuzzerTestOneInput_33(remainData, remainSize);
        case 15:
            return LLVMFuzzerTestOneInput_34(remainData, remainSize);
        case 16:
            return LLVMFuzzerTestOneInput_36(remainData, remainSize);
        case 17:
            return LLVMFuzzerTestOneInput_37(remainData, remainSize);
        case 18:
            return LLVMFuzzerTestOneInput_44(remainData, remainSize);
        case 19:
            return LLVMFuzzerTestOneInput_45(remainData, remainSize);
        case 20:
            return LLVMFuzzerTestOneInput_48(remainData, remainSize);
        case 21:
            return LLVMFuzzerTestOneInput_55(remainData, remainSize);
        case 22:
            return LLVMFuzzerTestOneInput_56(remainData, remainSize);
        case 23:
            return LLVMFuzzerTestOneInput_64(remainData, remainSize);
        case 24:
            return LLVMFuzzerTestOneInput_67(remainData, remainSize);
        case 25:
            return LLVMFuzzerTestOneInput_75(remainData, remainSize);
        case 26:
            return LLVMFuzzerTestOneInput_76(remainData, remainSize);
        case 27:
            return LLVMFuzzerTestOneInput_81(remainData, remainSize);
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

