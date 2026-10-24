// This fuzz driver is generated for library liblouis, aiming to fuzz the following functions:
// lou_version at compileTranslationTable.c:5435:1 in liblouis.h
// lou_indexTables at metadata.c:947:1 in liblouis.h
// lou_findTable at metadata.c:1068:1 in liblouis.h
// lou_getTableInfo at metadata.c:1147:1 in liblouis.h
// lou_listTables at metadata.c:1177:1 in liblouis.h
// lou_freeTableFiles at compileTranslationTable.c:4949:1 in liblouis.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <liblouis.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <fstream>

static void writeDummyFile(const uint8_t *Data, size_t Size) {
    std::ofstream dummyFile("./dummy_file", std::ios::binary);
    dummyFile.write(reinterpret_cast<const char*>(Data), Size);
    dummyFile.close();
}

extern "C" int LLVMFuzzerTestOneInput_23(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Test lou_version
    const char *version = lou_version();
    if (version) {
        std::cout << "Liblouis version: " << version << std::endl;
    }

    // Prepare data for lou_indexTables
    std::vector<const char*> tables;
    size_t offset = 0;
    while (offset < Size) {
        size_t remaining = Size - offset;
        const char *str = reinterpret_cast<const char*>(Data) + offset;
        size_t strLength = strnlen(str, remaining);
        
        if (strLength < remaining) {
            tables.push_back(str);
            offset += strLength + 1;
        } else {
            break;
        }
    }
    tables.push_back(nullptr); // Null-terminate the array
    lou_indexTables(tables.data());

    // Test lou_findTable
    if (Size > 0 && Data[Size - 1] == '\0') {
        char *foundTable = lou_findTable(reinterpret_cast<const char*>(Data));
        if (foundTable) {
            std::cout << "Found table: " << foundTable << std::endl;
            free(foundTable);
        }
    }

    // Test lou_getTableInfo
    if (Size > 0 && Data[Size - 1] == '\0') {
        char *tableInfo = lou_getTableInfo(reinterpret_cast<const char*>(Data), "key");
        if (tableInfo) {
            std::cout << "Table info: " << tableInfo << std::endl;
            free(tableInfo);
        }
    }

    // Test lou_listTables
    char **listedTables = lou_listTables();
    if (listedTables) {
        for (int i = 0; listedTables[i] != nullptr; ++i) {
            std::cout << "Table: " << listedTables[i] << std::endl;
        }
        lou_freeTableFiles(listedTables);
    }

    // Write data to a dummy file
    writeDummyFile(Data, Size);

    return 0;
}
    #ifdef INC_MAIN
    #include <stdio.h>
    #include <stdlib.h>
    #include <stdint.h>
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

        if(size < 1 + 1)
            exit(0);

        data = (uint8_t *)malloc((size_t)size);
        if(data == NULL)
            exit(0);

        if(fread(data, (size_t)size, 1, f) != 1)
            exit(0);

        LLVMFuzzerTestOneInput_23(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    