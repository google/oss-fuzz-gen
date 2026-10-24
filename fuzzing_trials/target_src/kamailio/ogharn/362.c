#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <hf.h>
#include <keys.h>
#include <msg_parser.h>
#include <parse_addr_spec.h>
#include <parse_allow.h>
#include <parse_body.h>
#include <parse_content.h>
#include <parse_cseq.h>
#include <parse_date.h>
#include <parse_def.h>
#include <parse_disposition.h>
#include <parse_diversion.h>
#include <parse_event.h>
#include <parse_expires.h>
#include <parse_fline.h>
#include <parse_from.h>
#include <parse_hname2.h>
#include <parse_identity.h>
#include <parse_identityinfo.h>
#include <parse_methods.h>
#include <parse_nameaddr.h>
#include <parse_option_tags.h>
#include <parse_param.h>
#include <parse_ppi_pai.h>
#include <parse_privacy.h>
#include <parse_refer_to.h>
#include <parse_require.h>
#include <parse_retry_after.h>
#include <parse_rpid.h>
#include <parse_rr.h>
#include <parse_sipifmatch.h>
#include <parse_subscription_state.h>
#include <parse_supported.h>
#include <parse_to.h>
#include <parse_uri.h>
#include <parse_via.h>
#include <parser_f.h>

int LLVMFuzzerTestOneInput_362(char *fuzzData, size_t size)
{
	

   struct sip_uri parse_urivar2;
	memset(&parse_urivar2, 0, sizeof(parse_urivar2));

   char* parse_identityvar1[size+1];
	sprintf(parse_identityvar1, "/tmp/boova");
   struct identity_body parse_identityvar2;
	memset(&parse_identityvar2, 0, sizeof(parse_identityvar2));

   char* parse_retry_aftervar0[size+1];
	sprintf(parse_retry_aftervar0, "/tmp/k5htt");
   int parse_retry_aftervar3 = 1;
   unsigned int parse_retry_aftervarU_INTsize = sizeof(parse_identityvar1);
   int parse_urival1 = parse_uri(fuzzData, size, &parse_urivar2);
	if((int)parse_urival1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   parse_identity(fuzzData, parse_identityvar1, &parse_identityvar2);
   parse_identityinfo(fuzzData, parse_identityvar1, NULL);
   char* parse_retry_afterval1 = parse_retry_after(parse_retry_aftervar0, parse_identityvar1, &parse_retry_aftervarU_INTsize, &parse_retry_aftervar3);
	if(!parse_retry_afterval1){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
