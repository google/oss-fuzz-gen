// This is the entry of 23 fuzz drivers:
// 2, 3, 24, 25, 28, 29, 32, 34, 35, 36, 37, 39, 41, 46, 54, 69, 73, 81, 82, 85, 86
// , 89, 93
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <memory.h>

// Declarations of all fuzz drivers `LLVMFuzzerTestOneInput` functions
int LLVMFuzzerTestOneInput_2(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_3(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_24(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_25(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_28(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_29(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_32(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_34(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_35(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_36(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_37(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_39(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_41(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_46(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_54(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_69(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_73(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_81(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_82(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_85(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_86(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_89(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_93(const uint8_t *Data, size_t Size);

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
    switch (driverIndex % 23) {
        case 0:
            return LLVMFuzzerTestOneInput_2(remainData, remainSize);
        case 1:
            return LLVMFuzzerTestOneInput_3(remainData, remainSize);
        case 2:
            return LLVMFuzzerTestOneInput_24(remainData, remainSize);
        case 3:
            return LLVMFuzzerTestOneInput_25(remainData, remainSize);
        case 4:
            return LLVMFuzzerTestOneInput_28(remainData, remainSize);
        case 5:
            return LLVMFuzzerTestOneInput_29(remainData, remainSize);
        case 6:
            return LLVMFuzzerTestOneInput_32(remainData, remainSize);
        case 7:
            return LLVMFuzzerTestOneInput_34(remainData, remainSize);
        case 8:
            return LLVMFuzzerTestOneInput_35(remainData, remainSize);
        case 9:
            return LLVMFuzzerTestOneInput_36(remainData, remainSize);
        case 10:
            return LLVMFuzzerTestOneInput_37(remainData, remainSize);
        case 11:
            return LLVMFuzzerTestOneInput_39(remainData, remainSize);
        case 12:
            return LLVMFuzzerTestOneInput_41(remainData, remainSize);
        case 13:
            return LLVMFuzzerTestOneInput_46(remainData, remainSize);
        case 14:
            return LLVMFuzzerTestOneInput_54(remainData, remainSize);
        case 15:
            return LLVMFuzzerTestOneInput_69(remainData, remainSize);
        case 16:
            return LLVMFuzzerTestOneInput_73(remainData, remainSize);
        case 17:
            return LLVMFuzzerTestOneInput_81(remainData, remainSize);
        case 18:
            return LLVMFuzzerTestOneInput_82(remainData, remainSize);
        case 19:
            return LLVMFuzzerTestOneInput_85(remainData, remainSize);
        case 20:
            return LLVMFuzzerTestOneInput_86(remainData, remainSize);
        case 21:
            return LLVMFuzzerTestOneInput_89(remainData, remainSize);
        case 22:
            return LLVMFuzzerTestOneInput_93(remainData, remainSize);
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
