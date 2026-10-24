#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_13(char *fuzzData, size_t size)
{
	

   plist_format_t plist_from_memoryoverload3var3;
	memset(&plist_from_memoryoverload3var3, 0, sizeof(plist_from_memoryoverload3var3));

   char* plist_set_key_valvar1[size+1];
	sprintf((char *)plist_set_key_valvar1, "/tmp/3hmer");
   uint32_t plist_write_to_stringoverload3varuint32_tsize = size;
   plist_t plist_from_memoryoverload2var2;
	memset(&plist_from_memoryoverload2var2, 0, sizeof(plist_from_memoryoverload2var2));

   plist_format_t plist_from_memoryoverload2var3;
	memset(&plist_from_memoryoverload2var3, 0, sizeof(plist_from_memoryoverload2var3));

   plist_t plist_new_dictval1 = plist_new_dict();
   plist_err_t plist_from_memoryoverload3val1 = plist_from_memory(fuzzData, size, &plist_new_dictval1, &plist_from_memoryoverload3var3);
	if(plist_from_memoryoverload3val1 != PLIST_ERR_SUCCESS){
		fprintf(stderr, "err");
		exit(0);	}
   plist_set_key_val(plist_new_dictval1, (char* )plist_set_key_valvar1);
	if(!fuzzData){
		fprintf(stderr, "err");
		exit(0);	}
   plist_err_t plist_write_to_stringoverload3val1 = plist_write_to_string(plist_new_dictval1, &fuzzData, &plist_write_to_stringoverload3varuint32_tsize, plist_from_memoryoverload3var3, PLIST_OPT_COMPACT);
	if(plist_write_to_stringoverload3val1 != PLIST_ERR_SUCCESS){
		fprintf(stderr, "err");
		exit(0);	}
   plist_err_t plist_from_memoryoverload2val1 = plist_from_memory(fuzzData, size, &plist_from_memoryoverload2var2, &plist_from_memoryoverload2var3);
	if(plist_from_memoryoverload2val1 != PLIST_ERR_SUCCESS){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
