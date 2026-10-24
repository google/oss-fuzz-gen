#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_4(char *fuzzData, size_t size)
{
	

   plist_format_t plist_from_memoryoverload3var3;
	memset(&plist_from_memoryoverload3var3, 0, sizeof(plist_from_memoryoverload3var3));

   uint32_t plist_write_to_stringoverload3varuint32_tsize = size;
   plist_t plist_new_dictval1 = plist_new_dict();
   plist_err_t plist_from_memoryoverload3val1 = plist_from_memory(fuzzData, size, &plist_new_dictval1, &plist_from_memoryoverload3var3);
	if(plist_from_memoryoverload3val1 != PLIST_ERR_SUCCESS){
		fprintf(stderr, "err");
		exit(0);	}
	if(!fuzzData){
		fprintf(stderr, "err");
		exit(0);	}
   plist_err_t plist_write_to_stringoverload3val1 = plist_write_to_string(plist_new_dictval1, &fuzzData, &plist_write_to_stringoverload3varuint32_tsize, PLIST_FORMAT_PLUTIL, PLIST_OPT_NO_NEWLINE);
	if(plist_write_to_stringoverload3val1 != PLIST_ERR_SUCCESS){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
