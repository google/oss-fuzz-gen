// This is the entry of 27 fuzz drivers:
// 1, 2, 4, 13, 16, 22, 26, 33, 39, 40, 42, 43, 48, 49, 59, 60, 65, 72, 75, 77, 82,
//  96, 97, 108, 109, 115, 119
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
int LLVMFuzzerTestOneInput_13(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_16(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_22(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_26(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_33(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_39(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_40(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_42(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_43(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_48(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_49(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_59(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_60(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_65(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_72(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_75(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_77(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_82(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_96(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_97(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_108(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_109(const uint8_t *Data, size_t Size);
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
    switch (driverIndex % 27) {
        case 0:
            return LLVMFuzzerTestOneInput_1(remainData, remainSize);
        case 1:
            return LLVMFuzzerTestOneInput_2(remainData, remainSize);
        case 2:
            return LLVMFuzzerTestOneInput_4(remainData, remainSize);
        case 3:
            return LLVMFuzzerTestOneInput_13(remainData, remainSize);
        case 4:
            return LLVMFuzzerTestOneInput_16(remainData, remainSize);
        case 5:
            return LLVMFuzzerTestOneInput_22(remainData, remainSize);
        case 6:
            return LLVMFuzzerTestOneInput_26(remainData, remainSize);
        case 7:
            return LLVMFuzzerTestOneInput_33(remainData, remainSize);
        case 8:
            return LLVMFuzzerTestOneInput_39(remainData, remainSize);
        case 9:
            return LLVMFuzzerTestOneInput_40(remainData, remainSize);
        case 10:
            return LLVMFuzzerTestOneInput_42(remainData, remainSize);
        case 11:
            return LLVMFuzzerTestOneInput_43(remainData, remainSize);
        case 12:
            return LLVMFuzzerTestOneInput_48(remainData, remainSize);
        case 13:
            return LLVMFuzzerTestOneInput_49(remainData, remainSize);
        case 14:
            return LLVMFuzzerTestOneInput_59(remainData, remainSize);
        case 15:
            return LLVMFuzzerTestOneInput_60(remainData, remainSize);
        case 16:
            return LLVMFuzzerTestOneInput_65(remainData, remainSize);
        case 17:
            return LLVMFuzzerTestOneInput_72(remainData, remainSize);
        case 18:
            return LLVMFuzzerTestOneInput_75(remainData, remainSize);
        case 19:
            return LLVMFuzzerTestOneInput_77(remainData, remainSize);
        case 20:
            return LLVMFuzzerTestOneInput_82(remainData, remainSize);
        case 21:
            return LLVMFuzzerTestOneInput_96(remainData, remainSize);
        case 22:
            return LLVMFuzzerTestOneInput_97(remainData, remainSize);
        case 23:
            return LLVMFuzzerTestOneInput_108(remainData, remainSize);
        case 24:
            return LLVMFuzzerTestOneInput_109(remainData, remainSize);
        case 25:
            return LLVMFuzzerTestOneInput_115(remainData, remainSize);
        case 26:
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

