#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <libical/ical.h>

extern "C" int LLVMFuzzerTestOneInput_24(char *fuzzData, size_t size)
{
	
        

   icalproperty_kind icalcomponent_count_propertiesvar0;
	memset(&icalcomponent_count_propertiesvar0, 0, (sizeof icalcomponent_count_propertiesvar0));

   icalcomponent* icalcomponent_new_from_stringval1 = icalcomponent_new_from_string(fuzzData);

	if(!icalcomponent_new_from_stringval1){
		fprintf(stderr, "err");
		exit(0);	}
   int icalcomponent_check_restrictionsval1 = icalcomponent_check_restrictions(icalcomponent_new_from_stringval1);
	if(icalcomponent_check_restrictionsval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int icalcomponent_count_propertiesval1 = icalcomponent_count_properties(icalcomponent_new_from_stringval1, icalcomponent_count_propertiesvar0);
	if(icalcomponent_count_propertiesval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
