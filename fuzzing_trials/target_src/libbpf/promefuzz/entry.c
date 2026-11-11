// This is the entry of 49 fuzz drivers:
// 3, 4, 5, 6, 7, 8, 10, 11, 15, 18, 23, 24, 26, 27, 30, 32, 33, 35, 36, 46, 51, 53
// , 54, 55, 63, 65, 66, 68, 71, 72, 75, 77, 78, 79, 82, 87, 88, 94, 95, 96, 99, 10
// 0, 103, 105, 107, 109, 115, 116, 120
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <memory.h>

// Declarations of all fuzz drivers `LLVMFuzzerTestOneInput` functions
int LLVMFuzzerTestOneInput_3(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_4(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_5(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_6(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_7(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_8(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_10(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_11(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_15(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_18(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_23(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_24(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_26(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_27(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_30(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_32(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_33(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_35(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_36(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_46(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_51(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_53(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_54(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_55(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_63(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_65(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_66(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_68(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_71(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_72(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_75(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_77(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_78(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_79(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_82(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_87(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_88(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_94(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_95(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_96(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_99(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_100(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_103(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_105(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_107(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_109(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_115(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_116(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_120(const uint8_t *Data, size_t Size);

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
    switch (driverIndex % 49) {
        case 0:
            return LLVMFuzzerTestOneInput_3(remainData, remainSize);
        case 1:
            return LLVMFuzzerTestOneInput_4(remainData, remainSize);
        case 2:
            return LLVMFuzzerTestOneInput_5(remainData, remainSize);
        case 3:
            return LLVMFuzzerTestOneInput_6(remainData, remainSize);
        case 4:
            return LLVMFuzzerTestOneInput_7(remainData, remainSize);
        case 5:
            return LLVMFuzzerTestOneInput_8(remainData, remainSize);
        case 6:
            return LLVMFuzzerTestOneInput_10(remainData, remainSize);
        case 7:
            return LLVMFuzzerTestOneInput_11(remainData, remainSize);
        case 8:
            return LLVMFuzzerTestOneInput_15(remainData, remainSize);
        case 9:
            return LLVMFuzzerTestOneInput_18(remainData, remainSize);
        case 10:
            return LLVMFuzzerTestOneInput_23(remainData, remainSize);
        case 11:
            return LLVMFuzzerTestOneInput_24(remainData, remainSize);
        case 12:
            return LLVMFuzzerTestOneInput_26(remainData, remainSize);
        case 13:
            return LLVMFuzzerTestOneInput_27(remainData, remainSize);
        case 14:
            return LLVMFuzzerTestOneInput_30(remainData, remainSize);
        case 15:
            return LLVMFuzzerTestOneInput_32(remainData, remainSize);
        case 16:
            return LLVMFuzzerTestOneInput_33(remainData, remainSize);
        case 17:
            return LLVMFuzzerTestOneInput_35(remainData, remainSize);
        case 18:
            return LLVMFuzzerTestOneInput_36(remainData, remainSize);
        case 19:
            return LLVMFuzzerTestOneInput_46(remainData, remainSize);
        case 20:
            return LLVMFuzzerTestOneInput_51(remainData, remainSize);
        case 21:
            return LLVMFuzzerTestOneInput_53(remainData, remainSize);
        case 22:
            return LLVMFuzzerTestOneInput_54(remainData, remainSize);
        case 23:
            return LLVMFuzzerTestOneInput_55(remainData, remainSize);
        case 24:
            return LLVMFuzzerTestOneInput_63(remainData, remainSize);
        case 25:
            return LLVMFuzzerTestOneInput_65(remainData, remainSize);
        case 26:
            return LLVMFuzzerTestOneInput_66(remainData, remainSize);
        case 27:
            return LLVMFuzzerTestOneInput_68(remainData, remainSize);
        case 28:
            return LLVMFuzzerTestOneInput_71(remainData, remainSize);
        case 29:
            return LLVMFuzzerTestOneInput_72(remainData, remainSize);
        case 30:
            return LLVMFuzzerTestOneInput_75(remainData, remainSize);
        case 31:
            return LLVMFuzzerTestOneInput_77(remainData, remainSize);
        case 32:
            return LLVMFuzzerTestOneInput_78(remainData, remainSize);
        case 33:
            return LLVMFuzzerTestOneInput_79(remainData, remainSize);
        case 34:
            return LLVMFuzzerTestOneInput_82(remainData, remainSize);
        case 35:
            return LLVMFuzzerTestOneInput_87(remainData, remainSize);
        case 36:
            return LLVMFuzzerTestOneInput_88(remainData, remainSize);
        case 37:
            return LLVMFuzzerTestOneInput_94(remainData, remainSize);
        case 38:
            return LLVMFuzzerTestOneInput_95(remainData, remainSize);
        case 39:
            return LLVMFuzzerTestOneInput_96(remainData, remainSize);
        case 40:
            return LLVMFuzzerTestOneInput_99(remainData, remainSize);
        case 41:
            return LLVMFuzzerTestOneInput_100(remainData, remainSize);
        case 42:
            return LLVMFuzzerTestOneInput_103(remainData, remainSize);
        case 43:
            return LLVMFuzzerTestOneInput_105(remainData, remainSize);
        case 44:
            return LLVMFuzzerTestOneInput_107(remainData, remainSize);
        case 45:
            return LLVMFuzzerTestOneInput_109(remainData, remainSize);
        case 46:
            return LLVMFuzzerTestOneInput_115(remainData, remainSize);
        case 47:
            return LLVMFuzzerTestOneInput_116(remainData, remainSize);
        case 48:
            return LLVMFuzzerTestOneInput_120(remainData, remainSize);
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

