#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <dwarf.h>
#include <libdwarf.h>

int LLVMFuzzerTestOneInput_129(char *fuzzData, size_t size)
{
   
    char filename[256];
    sprintf(filename, "/tmp/libfuzzer.%d", getpid());

    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        return 0;
    }
    fwrite(fuzzData, size, 1, fp);
    fclose(fp);
    fuzzData = filename;


   Dwarf_Debug dwarf_init_path_dlvar6;
	memset(&dwarf_init_path_dlvar6, 0, sizeof(dwarf_init_path_dlvar6));

   unsigned char* dwarf_init_path_dlvar9[256];
	sprintf(dwarf_init_path_dlvar9, "/tmp/41bmr");
   char* dwarf_package_versionval1 = dwarf_package_version();
	if(!dwarf_package_versionval1){
		fprintf(stderr, "err");
		exit(0);	}
   int dwarf_init_path_dlval1 = dwarf_init_path_dl(fuzzData, fuzzData, sizeof(fuzzData), DW_AT_LLVM_include_path, NULL, NULL, &dwarf_init_path_dlvar6, NULL, DW_VIRTUALITY_none, dwarf_init_path_dlvar9, NULL);
	if((int)dwarf_init_path_dlval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
