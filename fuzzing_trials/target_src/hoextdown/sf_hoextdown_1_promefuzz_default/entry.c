// This is the entry of 32 fuzz drivers:
// 4, 8, 11, 13, 15, 16, 17, 18, 19, 22, 23, 32, 33, 42, 43, 46, 50, 52, 54, 58, 63
// , 66, 67, 68, 70, 71, 72, 73, 74, 75, 76, 77
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <memory.h>

// Declarations of all fuzz drivers `LLVMFuzzerTestOneInput` functions
int LLVMFuzzerTestOneInput_4(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_8(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_11(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_13(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_15(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_16(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_17(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_18(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_19(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_22(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_23(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_32(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_33(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_42(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_43(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_46(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_50(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_52(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_54(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_58(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_63(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_66(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_67(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_68(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_70(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_71(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_72(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_73(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_74(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_75(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_76(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_77(const uint8_t *Data, size_t Size);

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
            return LLVMFuzzerTestOneInput_4(remainData, remainSize);
        case 1:
            return LLVMFuzzerTestOneInput_8(remainData, remainSize);
        case 2:
            return LLVMFuzzerTestOneInput_11(remainData, remainSize);
        case 3:
            return LLVMFuzzerTestOneInput_13(remainData, remainSize);
        case 4:
            return LLVMFuzzerTestOneInput_15(remainData, remainSize);
        case 5:
            return LLVMFuzzerTestOneInput_16(remainData, remainSize);
        case 6:
            return LLVMFuzzerTestOneInput_17(remainData, remainSize);
        case 7:
            return LLVMFuzzerTestOneInput_18(remainData, remainSize);
        case 8:
            return LLVMFuzzerTestOneInput_19(remainData, remainSize);
        case 9:
            return LLVMFuzzerTestOneInput_22(remainData, remainSize);
        case 10:
            return LLVMFuzzerTestOneInput_23(remainData, remainSize);
        case 11:
            return LLVMFuzzerTestOneInput_32(remainData, remainSize);
        case 12:
            return LLVMFuzzerTestOneInput_33(remainData, remainSize);
        case 13:
            return LLVMFuzzerTestOneInput_42(remainData, remainSize);
        case 14:
            return LLVMFuzzerTestOneInput_43(remainData, remainSize);
        case 15:
            return LLVMFuzzerTestOneInput_46(remainData, remainSize);
        case 16:
            return LLVMFuzzerTestOneInput_50(remainData, remainSize);
        case 17:
            return LLVMFuzzerTestOneInput_52(remainData, remainSize);
        case 18:
            return LLVMFuzzerTestOneInput_54(remainData, remainSize);
        case 19:
            return LLVMFuzzerTestOneInput_58(remainData, remainSize);
        case 20:
            return LLVMFuzzerTestOneInput_63(remainData, remainSize);
        case 21:
            return LLVMFuzzerTestOneInput_66(remainData, remainSize);
        case 22:
            return LLVMFuzzerTestOneInput_67(remainData, remainSize);
        case 23:
            return LLVMFuzzerTestOneInput_68(remainData, remainSize);
        case 24:
            return LLVMFuzzerTestOneInput_70(remainData, remainSize);
        case 25:
            return LLVMFuzzerTestOneInput_71(remainData, remainSize);
        case 26:
            return LLVMFuzzerTestOneInput_72(remainData, remainSize);
        case 27:
            return LLVMFuzzerTestOneInput_73(remainData, remainSize);
        case 28:
            return LLVMFuzzerTestOneInput_74(remainData, remainSize);
        case 29:
            return LLVMFuzzerTestOneInput_75(remainData, remainSize);
        case 30:
            return LLVMFuzzerTestOneInput_76(remainData, remainSize);
        case 31:
            return LLVMFuzzerTestOneInput_77(remainData, remainSize);
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

