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

int LLVMFuzzerTestOneInput_711(char *fuzzData, size_t size)
{
	

   struct sip_uri parse_urivar2;
	memset(&parse_urivar2, 0, sizeof(parse_urivar2));

   sip_msg_t get_src_urivar0;
	memset(&get_src_urivar0, 0, sizeof(get_src_urivar0));

   str get_src_urivar2;
	memset(&get_src_urivar2, 0, sizeof(get_src_urivar2));

   int parse_urival1 = parse_uri(fuzzData, size, &parse_urivar2);
	if((int)parse_urival1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int get_src_urival1 = get_src_uri(&get_src_urivar0, parse_urival1, &get_src_urivar2);
	if((int)get_src_urival1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
	if(!*fuzzData){
		fprintf(stderr, "err");
		exit(0);	}
   char* find_not_quotedval1 = find_not_quoted(&get_src_urivar2, *fuzzData);
	if(!find_not_quotedval1){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
