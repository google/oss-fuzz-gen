#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <libical/ical.h>

extern "C" int LLVMFuzzerTestOneInput_58(char *fuzzData, size_t size)
{
	
        

   icalcomponent* icalcomponent_new_from_stringval1 = icalcomponent_new_from_string(fuzzData);

	if(!icalcomponent_new_from_stringval1){
		fprintf(stderr, "err");
		exit(0);	}
   icalcomponent_normalize(icalcomponent_new_from_stringval1);
   struct icaltimetype icalcomponent_get_dtendval1 = icalcomponent_get_dtend(icalcomponent_new_from_stringval1);
   int icalproperty_recurrence_is_excludedval1 = icalproperty_recurrence_is_excluded(icalcomponent_new_from_stringval1, &icalcomponent_get_dtendval1, &icalcomponent_get_dtendval1);
	if(icalproperty_recurrence_is_excludedval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
