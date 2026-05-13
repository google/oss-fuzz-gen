// This is the entry of 20 fuzz drivers:
// 2, 3, 13, 18, 20, 29, 30, 31, 41, 64, 67, 79, 89, 92, 94, 95, 123, 125, 126, 131
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <memory.h>

// Declarations of all fuzz drivers `LLVMFuzzerTestOneInput` functions
extern "C" int LLVMFuzzerTestOneInput_2(const uint8_t *Data, size_t Size);
extern "C" int LLVMFuzzerTestOneInput_3(const uint8_t *Data, size_t Size);
extern "C" int LLVMFuzzerTestOneInput_13(const uint8_t *Data, size_t Size);
extern "C" int LLVMFuzzerTestOneInput_18(const uint8_t *Data, size_t Size);
extern "C" int LLVMFuzzerTestOneInput_20(const uint8_t *Data, size_t Size);
extern "C" int LLVMFuzzerTestOneInput_29(const uint8_t *Data, size_t Size);
extern "C" int LLVMFuzzerTestOneInput_30(const uint8_t *Data, size_t Size);
extern "C" int LLVMFuzzerTestOneInput_31(const uint8_t *Data, size_t Size);
extern "C" int LLVMFuzzerTestOneInput_41(const uint8_t *Data, size_t Size);
extern "C" int LLVMFuzzerTestOneInput_64(const uint8_t *Data, size_t Size);
extern "C" int LLVMFuzzerTestOneInput_67(const uint8_t *Data, size_t Size);
extern "C" int LLVMFuzzerTestOneInput_79(const uint8_t *Data, size_t Size);
extern "C" int LLVMFuzzerTestOneInput_89(const uint8_t *Data, size_t Size);
extern "C" int LLVMFuzzerTestOneInput_92(const uint8_t *Data, size_t Size);
extern "C" int LLVMFuzzerTestOneInput_94(const uint8_t *Data, size_t Size);
extern "C" int LLVMFuzzerTestOneInput_95(const uint8_t *Data, size_t Size);
extern "C" int LLVMFuzzerTestOneInput_123(const uint8_t *Data, size_t Size);
extern "C" int LLVMFuzzerTestOneInput_125(const uint8_t *Data, size_t Size);
extern "C" int LLVMFuzzerTestOneInput_126(const uint8_t *Data, size_t Size);
extern "C" int LLVMFuzzerTestOneInput_131(const uint8_t *Data, size_t Size);

// Entry function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
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
    switch (driverIndex % 20) {
        case 0:
            return LLVMFuzzerTestOneInput_2(remainData, remainSize);
        case 1:
            return LLVMFuzzerTestOneInput_3(remainData, remainSize);
        case 2:
            return LLVMFuzzerTestOneInput_13(remainData, remainSize);
        case 3:
            return LLVMFuzzerTestOneInput_18(remainData, remainSize);
        case 4:
            return LLVMFuzzerTestOneInput_20(remainData, remainSize);
        case 5:
            return LLVMFuzzerTestOneInput_29(remainData, remainSize);
        case 6:
            return LLVMFuzzerTestOneInput_30(remainData, remainSize);
        case 7:
            return LLVMFuzzerTestOneInput_31(remainData, remainSize);
        case 8:
            return LLVMFuzzerTestOneInput_41(remainData, remainSize);
        case 9:
            return LLVMFuzzerTestOneInput_64(remainData, remainSize);
        case 10:
            return LLVMFuzzerTestOneInput_67(remainData, remainSize);
        case 11:
            return LLVMFuzzerTestOneInput_79(remainData, remainSize);
        case 12:
            return LLVMFuzzerTestOneInput_89(remainData, remainSize);
        case 13:
            return LLVMFuzzerTestOneInput_92(remainData, remainSize);
        case 14:
            return LLVMFuzzerTestOneInput_94(remainData, remainSize);
        case 15:
            return LLVMFuzzerTestOneInput_95(remainData, remainSize);
        case 16:
            return LLVMFuzzerTestOneInput_123(remainData, remainSize);
        case 17:
            return LLVMFuzzerTestOneInput_125(remainData, remainSize);
        case 18:
            return LLVMFuzzerTestOneInput_126(remainData, remainSize);
        case 19:
            return LLVMFuzzerTestOneInput_131(remainData, remainSize);
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

