#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <dwarf.h>
#include <libdwarf.h>

int LLVMFuzzerTestOneInput_15(char *fuzzData, size_t size)
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


   char* dwarf_object_detector_path_bvar1[256];
	sprintf(dwarf_object_detector_path_bvar1, "/tmp/pfq9j");
   unsigned long dwarf_object_detector_path_bvar2 = 1;
   char** dwarf_object_detector_path_bvar3[256];
	sprintf(dwarf_object_detector_path_bvar3, "/tmp/h30i4");
   unsigned int dwarf_object_detector_path_bvar5 = 1;
   unsigned int dwarf_object_detector_path_bvar6 = 1;
   unsigned int dwarf_object_detector_path_bvar7 = 1;
   Dwarf_Unsigned dwarf_object_detector_path_bvar8;
	memset(&dwarf_object_detector_path_bvar8, 0, sizeof(dwarf_object_detector_path_bvar8));

   int dwarf_object_detector_path_bvar10 = 1;
   char* dwarf_package_versionval1 = dwarf_package_version();
	if(!dwarf_package_versionval1){
		fprintf(stderr, "err");
		exit(0);	}
   int dwarf_object_detector_path_bval1 = dwarf_object_detector_path_b(fuzzData, dwarf_object_detector_path_bvar1, dwarf_object_detector_path_bvar2, dwarf_object_detector_path_bvar3, sizeof(dwarf_object_detector_path_bvar3), &dwarf_object_detector_path_bvar5, &dwarf_object_detector_path_bvar6, &dwarf_object_detector_path_bvar7, &dwarf_object_detector_path_bvar8, fuzzData, &dwarf_object_detector_path_bvar10);
	if((int)dwarf_object_detector_path_bval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
