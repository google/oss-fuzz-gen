#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <dwarf.h>
#include <libdwarf.h>

static void function_pointer3458764516298326016fp(Dwarf_Error, Dwarf_Ptr){
	exit(0);
}
int LLVMFuzzerTestOneInput_10(char *fuzzData, size_t size)
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


   Dwarf_Ptr dwarf_init_path_dl_avar6;
	memset(&dwarf_init_path_dl_avar6, 0, sizeof(dwarf_init_path_dl_avar6));

   Dwarf_Debug dwarf_init_path_dl_avar7;
	memset(&dwarf_init_path_dl_avar7, 0, sizeof(dwarf_init_path_dl_avar7));

   Dwarf_Error dwarf_init_path_dl_avar11;
	memset(&dwarf_init_path_dl_avar11, 0, sizeof(dwarf_init_path_dl_avar11));

   char* dwarf_package_versionval1 = dwarf_package_version();
	if(!dwarf_package_versionval1){
		fprintf(stderr, "err");
		exit(0);	}
	if(!dwarf_package_versionval1){
		fprintf(stderr, "err");
		exit(0);	}
   int dwarf_init_path_dl_aval1 = dwarf_init_path_dl_a(fuzzData, &fuzzData, sizeof(fuzzData), DW_AT_call_all_tail_calls, DW_TAG_file_type, function_pointer3458764516298326016fp, dwarf_init_path_dl_avar6, &dwarf_init_path_dl_avar7, &dwarf_package_versionval1, DW_DLV_ERROR, fuzzData, &dwarf_init_path_dl_avar11);
	if((int)dwarf_init_path_dl_aval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
