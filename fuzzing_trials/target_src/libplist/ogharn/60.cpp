#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_60(char *fuzzData, size_t size)
{
	

   plist_format_t plist_from_memoryoverload3var3;
	memset(&plist_from_memoryoverload3var3, 0, sizeof(plist_from_memoryoverload3var3));

   uint32_t plist_to_binoverload3varuint32_tsize = size;
   plist_t plist_from_binvar2;
	memset(&plist_from_binvar2, 0, sizeof(plist_from_binvar2));

   plist_t plist_new_dictval1 = plist_new_dict();
   plist_err_t plist_from_memoryoverload3val1 = plist_from_memory(fuzzData, size, &plist_new_dictval1, &plist_from_memoryoverload3var3);
	if(plist_from_memoryoverload3val1 != PLIST_ERR_SUCCESS){
		fprintf(stderr, "err");
		exit(0);	}
	if(!fuzzData){
		fprintf(stderr, "err");
		exit(0);	}
   plist_err_t plist_to_binoverload3val1 = plist_to_bin(plist_new_dictval1, &fuzzData, &plist_to_binoverload3varuint32_tsize);
	if(plist_to_binoverload3val1 != PLIST_ERR_SUCCESS){
		fprintf(stderr, "err");
		exit(0);	}
   plist_err_t plist_from_binval1 = plist_from_bin(fuzzData, plist_to_binoverload3varuint32_tsize, &plist_from_binvar2);
	if(plist_from_binval1 != PLIST_ERR_SUCCESS){
		fprintf(stderr, "err");
		exit(0);	}
   char plist_compare_node_valueval1 = plist_compare_node_value(plist_from_binvar2, plist_new_dictval1);
   return 0;
}
