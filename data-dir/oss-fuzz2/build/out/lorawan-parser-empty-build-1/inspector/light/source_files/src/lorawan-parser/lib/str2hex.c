#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "base64.h"

/** extend this value to handle long words */
#define STR2HEX_BUF_LEN                     (18)

#define STR2HEX_ERR_CHAR_INVALID            (-1)
#define STR2HEX_ERR_ODD                     (-2)
#define STR2HEX_ERR_TOO_LONG                (-3)

const char hex_tab[][16] = {
	"0123456789ABCDEF",
	"0123456789abcdef",
};

uint8_t str2hex_buf[STR2HEX_BUF_LEN];

int char2hex(char c)
{
	int i;
	for(i = 0; i<16; i++){
		if( c == hex_tab[0][i] || c == hex_tab[1][i]){
			return i;
		}
	}
	return STR2HEX_ERR_CHAR_INVALID;
}

int word2hex(char *str, uint8_t *hex, int max_len)
{
	int i, j, len;
	int h;
	len = strlen(str);
	j = 0;
	if(len%2){
		h = char2hex(str[0]);
		if(h<0){
			return h;
		}
		hex[j] = h;
		j++;
		i=1;
	}else{
		i=0;
	}
	for(; i<len; i+=2){
        if(j >= max_len){
            return STR2HEX_ERR_TOO_LONG;
        }
		h = char2hex(str[i]);
		if(h<0){
			return h;
		}
		hex[j] = h;
		hex[j] <<= 4;
		h = char2hex(str[i+1]);
		if(h<0){
			return h;
		}
		hex[j] |= h;
		j++;
	}
	return j;
}

/** -1: char invalid, -2: string is too long,  */
int str2hex(char *str, uint8_t *hex, int max_len)
{
	int i, len, j, num, len_tmp;
	int start_index, para_len;
	char c;
	char *word = (char *)str2hex_buf;

	len = strlen(str);
    for(i=0; i<len; i++){
        c = str[i];
        if(c=='0'){
            if( ((len-1-i)>2) && (str[i+1]== 'x' || str[i+1] == 'X') ){
                str[i++] = ' ';
                str[i] = ' ';
            }
        }else if( (c==',') || (c==':') || (c=='-') ){
            str[i] = ' ';
        }else if( !( (c>='a' && c<='f') || (c>='A' && c<='F') || (c>='0' && c<='9') || c == ' ') ){
            /** character invalid */
            j = b64_to_bin(str, len, hex, max_len);
            if( j > 0 ){
                return j;
            }
            return STR2HEX_ERR_CHAR_INVALID;
        }
    }

    j=0;
	for(i=0; i<len; i++){
		c = str[i];
		if(c != ' '){
			start_index = i;
			para_len = 0;
			while( c != ' ' && c != '\0' ){
				c = str[++i];
				para_len++;
			}
			if(para_len == 0){
				break;
			}

            while( para_len > 0){
                if((para_len+1)>STR2HEX_BUF_LEN){
                    len_tmp = para_len%(STR2HEX_BUF_LEN-2);
                    if(len_tmp == 0){
                        len_tmp = STR2HEX_BUF_LEN-2;
                    }
                }else{
                    len_tmp = para_len;
                }
                if(j>=max_len){
                    return STR2HEX_ERR_TOO_LONG;
                }
                memcpy(word, str+start_index, len_tmp);
                start_index += len_tmp;
                word[len_tmp] = '\0';
                num = word2hex(word, hex+j, max_len-j);
                if(num < 0){
                    return num;
                }
                j+=num;
                para_len -= len_tmp;
            }
		}
	}

	return j;
}

