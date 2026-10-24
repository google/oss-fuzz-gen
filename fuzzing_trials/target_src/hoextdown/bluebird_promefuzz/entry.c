// This is the entry of 32 fuzz drivers:
// 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 2
// 3, 24, 25, 26, 27, 28, 29, 30, 31, 32
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
int LLVMFuzzerTestOneInput_2(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_3(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_4(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_5(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_6(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_7(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_8(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_9(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_10(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_11(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_12(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_13(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_14(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_15(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_16(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_17(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_18(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_19(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_20(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_21(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_22(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_23(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_24(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_25(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_26(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_27(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_28(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_29(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_30(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_31(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_32(const uint8_t *Data, size_t Size);

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
            return LLVMFuzzerTestOneInput_1(remainData, remainSize);
        case 1:
            return LLVMFuzzerTestOneInput_2(remainData, remainSize);
        case 2:
            return LLVMFuzzerTestOneInput_3(remainData, remainSize);
        case 3:
            return LLVMFuzzerTestOneInput_4(remainData, remainSize);
        case 4:
            return LLVMFuzzerTestOneInput_5(remainData, remainSize);
        case 5:
            return LLVMFuzzerTestOneInput_6(remainData, remainSize);
        case 6:
            return LLVMFuzzerTestOneInput_7(remainData, remainSize);
        case 7:
            return LLVMFuzzerTestOneInput_8(remainData, remainSize);
        case 8:
            return LLVMFuzzerTestOneInput_9(remainData, remainSize);
        case 9:
            return LLVMFuzzerTestOneInput_10(remainData, remainSize);
        case 10:
            return LLVMFuzzerTestOneInput_11(remainData, remainSize);
        case 11:
            return LLVMFuzzerTestOneInput_12(remainData, remainSize);
        case 12:
            return LLVMFuzzerTestOneInput_13(remainData, remainSize);
        case 13:
            return LLVMFuzzerTestOneInput_14(remainData, remainSize);
        case 14:
            return LLVMFuzzerTestOneInput_15(remainData, remainSize);
        case 15:
            return LLVMFuzzerTestOneInput_16(remainData, remainSize);
        case 16:
            return LLVMFuzzerTestOneInput_17(remainData, remainSize);
        case 17:
            return LLVMFuzzerTestOneInput_18(remainData, remainSize);
        case 18:
            return LLVMFuzzerTestOneInput_19(remainData, remainSize);
        case 19:
            return LLVMFuzzerTestOneInput_20(remainData, remainSize);
        case 20:
            return LLVMFuzzerTestOneInput_21(remainData, remainSize);
        case 21:
            return LLVMFuzzerTestOneInput_22(remainData, remainSize);
        case 22:
            return LLVMFuzzerTestOneInput_23(remainData, remainSize);
        case 23:
            return LLVMFuzzerTestOneInput_24(remainData, remainSize);
        case 24:
            return LLVMFuzzerTestOneInput_25(remainData, remainSize);
        case 25:
            return LLVMFuzzerTestOneInput_26(remainData, remainSize);
        case 26:
            return LLVMFuzzerTestOneInput_27(remainData, remainSize);
        case 27:
            return LLVMFuzzerTestOneInput_28(remainData, remainSize);
        case 28:
            return LLVMFuzzerTestOneInput_29(remainData, remainSize);
        case 29:
            return LLVMFuzzerTestOneInput_30(remainData, remainSize);
        case 30:
            return LLVMFuzzerTestOneInput_31(remainData, remainSize);
        case 31:
            return LLVMFuzzerTestOneInput_32(remainData, remainSize);
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
