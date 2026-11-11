// This is the entry of 69 fuzz drivers:
// 1, 2, 3, 5, 6, 7, 8, 9, 10, 12, 13, 14, 15, 16, 17, 19, 21, 22, 23, 24, 25, 26, 
// 29, 30, 31, 35, 37, 41, 42, 46, 47, 49, 50, 55, 56, 58, 59, 60, 63, 64, 65, 66, 
// 67, 72, 74, 75, 76, 77, 78, 79, 80, 83, 84, 85, 87, 88, 90, 91, 95, 96, 97, 100,
//  105, 106, 108, 112, 114, 115, 119
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <memory.h>

// Declarations of all fuzz drivers `LLVMFuzzerTestOneInput` functions
int LLVMFuzzerTestOneInput_1(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_2(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_3(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_5(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_6(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_7(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_8(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_9(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_10(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_12(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_13(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_14(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_15(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_16(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_17(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_19(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_21(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_22(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_23(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_24(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_25(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_26(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_29(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_30(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_31(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_35(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_37(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_41(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_42(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_46(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_47(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_49(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_50(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_55(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_56(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_58(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_59(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_60(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_63(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_64(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_65(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_66(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_67(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_72(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_74(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_75(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_76(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_77(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_78(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_79(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_80(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_83(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_84(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_85(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_87(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_88(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_90(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_91(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_95(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_96(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_97(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_100(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_105(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_106(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_108(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_112(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_114(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_115(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_119(const uint8_t *Data, size_t Size);

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
    switch (driverIndex % 69) {
        case 0:
            return LLVMFuzzerTestOneInput_1(remainData, remainSize);
        case 1:
            return LLVMFuzzerTestOneInput_2(remainData, remainSize);
        case 2:
            return LLVMFuzzerTestOneInput_3(remainData, remainSize);
        case 3:
            return LLVMFuzzerTestOneInput_5(remainData, remainSize);
        case 4:
            return LLVMFuzzerTestOneInput_6(remainData, remainSize);
        case 5:
            return LLVMFuzzerTestOneInput_7(remainData, remainSize);
        case 6:
            return LLVMFuzzerTestOneInput_8(remainData, remainSize);
        case 7:
            return LLVMFuzzerTestOneInput_9(remainData, remainSize);
        case 8:
            return LLVMFuzzerTestOneInput_10(remainData, remainSize);
        case 9:
            return LLVMFuzzerTestOneInput_12(remainData, remainSize);
        case 10:
            return LLVMFuzzerTestOneInput_13(remainData, remainSize);
        case 11:
            return LLVMFuzzerTestOneInput_14(remainData, remainSize);
        case 12:
            return LLVMFuzzerTestOneInput_15(remainData, remainSize);
        case 13:
            return LLVMFuzzerTestOneInput_16(remainData, remainSize);
        case 14:
            return LLVMFuzzerTestOneInput_17(remainData, remainSize);
        case 15:
            return LLVMFuzzerTestOneInput_19(remainData, remainSize);
        case 16:
            return LLVMFuzzerTestOneInput_21(remainData, remainSize);
        case 17:
            return LLVMFuzzerTestOneInput_22(remainData, remainSize);
        case 18:
            return LLVMFuzzerTestOneInput_23(remainData, remainSize);
        case 19:
            return LLVMFuzzerTestOneInput_24(remainData, remainSize);
        case 20:
            return LLVMFuzzerTestOneInput_25(remainData, remainSize);
        case 21:
            return LLVMFuzzerTestOneInput_26(remainData, remainSize);
        case 22:
            return LLVMFuzzerTestOneInput_29(remainData, remainSize);
        case 23:
            return LLVMFuzzerTestOneInput_30(remainData, remainSize);
        case 24:
            return LLVMFuzzerTestOneInput_31(remainData, remainSize);
        case 25:
            return LLVMFuzzerTestOneInput_35(remainData, remainSize);
        case 26:
            return LLVMFuzzerTestOneInput_37(remainData, remainSize);
        case 27:
            return LLVMFuzzerTestOneInput_41(remainData, remainSize);
        case 28:
            return LLVMFuzzerTestOneInput_42(remainData, remainSize);
        case 29:
            return LLVMFuzzerTestOneInput_46(remainData, remainSize);
        case 30:
            return LLVMFuzzerTestOneInput_47(remainData, remainSize);
        case 31:
            return LLVMFuzzerTestOneInput_49(remainData, remainSize);
        case 32:
            return LLVMFuzzerTestOneInput_50(remainData, remainSize);
        case 33:
            return LLVMFuzzerTestOneInput_55(remainData, remainSize);
        case 34:
            return LLVMFuzzerTestOneInput_56(remainData, remainSize);
        case 35:
            return LLVMFuzzerTestOneInput_58(remainData, remainSize);
        case 36:
            return LLVMFuzzerTestOneInput_59(remainData, remainSize);
        case 37:
            return LLVMFuzzerTestOneInput_60(remainData, remainSize);
        case 38:
            return LLVMFuzzerTestOneInput_63(remainData, remainSize);
        case 39:
            return LLVMFuzzerTestOneInput_64(remainData, remainSize);
        case 40:
            return LLVMFuzzerTestOneInput_65(remainData, remainSize);
        case 41:
            return LLVMFuzzerTestOneInput_66(remainData, remainSize);
        case 42:
            return LLVMFuzzerTestOneInput_67(remainData, remainSize);
        case 43:
            return LLVMFuzzerTestOneInput_72(remainData, remainSize);
        case 44:
            return LLVMFuzzerTestOneInput_74(remainData, remainSize);
        case 45:
            return LLVMFuzzerTestOneInput_75(remainData, remainSize);
        case 46:
            return LLVMFuzzerTestOneInput_76(remainData, remainSize);
        case 47:
            return LLVMFuzzerTestOneInput_77(remainData, remainSize);
        case 48:
            return LLVMFuzzerTestOneInput_78(remainData, remainSize);
        case 49:
            return LLVMFuzzerTestOneInput_79(remainData, remainSize);
        case 50:
            return LLVMFuzzerTestOneInput_80(remainData, remainSize);
        case 51:
            return LLVMFuzzerTestOneInput_83(remainData, remainSize);
        case 52:
            return LLVMFuzzerTestOneInput_84(remainData, remainSize);
        case 53:
            return LLVMFuzzerTestOneInput_85(remainData, remainSize);
        case 54:
            return LLVMFuzzerTestOneInput_87(remainData, remainSize);
        case 55:
            return LLVMFuzzerTestOneInput_88(remainData, remainSize);
        case 56:
            return LLVMFuzzerTestOneInput_90(remainData, remainSize);
        case 57:
            return LLVMFuzzerTestOneInput_91(remainData, remainSize);
        case 58:
            return LLVMFuzzerTestOneInput_95(remainData, remainSize);
        case 59:
            return LLVMFuzzerTestOneInput_96(remainData, remainSize);
        case 60:
            return LLVMFuzzerTestOneInput_97(remainData, remainSize);
        case 61:
            return LLVMFuzzerTestOneInput_100(remainData, remainSize);
        case 62:
            return LLVMFuzzerTestOneInput_105(remainData, remainSize);
        case 63:
            return LLVMFuzzerTestOneInput_106(remainData, remainSize);
        case 64:
            return LLVMFuzzerTestOneInput_108(remainData, remainSize);
        case 65:
            return LLVMFuzzerTestOneInput_112(remainData, remainSize);
        case 66:
            return LLVMFuzzerTestOneInput_114(remainData, remainSize);
        case 67:
            return LLVMFuzzerTestOneInput_115(remainData, remainSize);
        case 68:
            return LLVMFuzzerTestOneInput_119(remainData, remainSize);
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

