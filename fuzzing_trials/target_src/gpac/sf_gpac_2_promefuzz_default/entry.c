// This is the entry of 42 fuzz drivers:
// 1, 4, 6, 7, 9, 10, 13, 15, 19, 21, 22, 23, 24, 25, 26, 28, 29, 33, 34, 35, 36, 3
// 7, 38, 39, 42, 44, 45, 46, 47, 48, 49, 50, 52, 55, 58, 59, 62, 63, 64, 66, 67, 6
// 9
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <memory.h>

// Declarations of all fuzz drivers `LLVMFuzzerTestOneInput` functions
int LLVMFuzzerTestOneInput_1(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_4(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_6(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_7(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_9(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_10(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_13(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_15(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_19(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_21(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_22(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_23(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_24(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_25(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_26(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_28(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_29(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_33(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_34(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_35(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_36(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_37(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_38(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_39(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_42(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_44(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_45(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_46(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_47(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_48(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_49(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_50(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_52(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_55(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_58(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_59(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_62(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_63(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_64(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_66(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_67(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_69(const uint8_t *Data, size_t Size);

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
    switch (driverIndex % 42) {
        case 0:
            return LLVMFuzzerTestOneInput_1(remainData, remainSize);
        case 1:
            return LLVMFuzzerTestOneInput_4(remainData, remainSize);
        case 2:
            return LLVMFuzzerTestOneInput_6(remainData, remainSize);
        case 3:
            return LLVMFuzzerTestOneInput_7(remainData, remainSize);
        case 4:
            return LLVMFuzzerTestOneInput_9(remainData, remainSize);
        case 5:
            return LLVMFuzzerTestOneInput_10(remainData, remainSize);
        case 6:
            return LLVMFuzzerTestOneInput_13(remainData, remainSize);
        case 7:
            return LLVMFuzzerTestOneInput_15(remainData, remainSize);
        case 8:
            return LLVMFuzzerTestOneInput_19(remainData, remainSize);
        case 9:
            return LLVMFuzzerTestOneInput_21(remainData, remainSize);
        case 10:
            return LLVMFuzzerTestOneInput_22(remainData, remainSize);
        case 11:
            return LLVMFuzzerTestOneInput_23(remainData, remainSize);
        case 12:
            return LLVMFuzzerTestOneInput_24(remainData, remainSize);
        case 13:
            return LLVMFuzzerTestOneInput_25(remainData, remainSize);
        case 14:
            return LLVMFuzzerTestOneInput_26(remainData, remainSize);
        case 15:
            return LLVMFuzzerTestOneInput_28(remainData, remainSize);
        case 16:
            return LLVMFuzzerTestOneInput_29(remainData, remainSize);
        case 17:
            return LLVMFuzzerTestOneInput_33(remainData, remainSize);
        case 18:
            return LLVMFuzzerTestOneInput_34(remainData, remainSize);
        case 19:
            return LLVMFuzzerTestOneInput_35(remainData, remainSize);
        case 20:
            return LLVMFuzzerTestOneInput_36(remainData, remainSize);
        case 21:
            return LLVMFuzzerTestOneInput_37(remainData, remainSize);
        case 22:
            return LLVMFuzzerTestOneInput_38(remainData, remainSize);
        case 23:
            return LLVMFuzzerTestOneInput_39(remainData, remainSize);
        case 24:
            return LLVMFuzzerTestOneInput_42(remainData, remainSize);
        case 25:
            return LLVMFuzzerTestOneInput_44(remainData, remainSize);
        case 26:
            return LLVMFuzzerTestOneInput_45(remainData, remainSize);
        case 27:
            return LLVMFuzzerTestOneInput_46(remainData, remainSize);
        case 28:
            return LLVMFuzzerTestOneInput_47(remainData, remainSize);
        case 29:
            return LLVMFuzzerTestOneInput_48(remainData, remainSize);
        case 30:
            return LLVMFuzzerTestOneInput_49(remainData, remainSize);
        case 31:
            return LLVMFuzzerTestOneInput_50(remainData, remainSize);
        case 32:
            return LLVMFuzzerTestOneInput_52(remainData, remainSize);
        case 33:
            return LLVMFuzzerTestOneInput_55(remainData, remainSize);
        case 34:
            return LLVMFuzzerTestOneInput_58(remainData, remainSize);
        case 35:
            return LLVMFuzzerTestOneInput_59(remainData, remainSize);
        case 36:
            return LLVMFuzzerTestOneInput_62(remainData, remainSize);
        case 37:
            return LLVMFuzzerTestOneInput_63(remainData, remainSize);
        case 38:
            return LLVMFuzzerTestOneInput_64(remainData, remainSize);
        case 39:
            return LLVMFuzzerTestOneInput_66(remainData, remainSize);
        case 40:
            return LLVMFuzzerTestOneInput_67(remainData, remainSize);
        case 41:
            return LLVMFuzzerTestOneInput_69(remainData, remainSize);
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

