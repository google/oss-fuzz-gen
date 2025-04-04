
/*

<https://github.com/rafagafe/tiny-json>
     
  Licensed under the MIT License <http://opensource.org/licenses/MIT>.
  SPDX-License-Identifier: MIT
  Copyright (c) 2016-2018 Rafa Garcia <rafagarcia77@gmail.com>.

  Permission is hereby  granted, free of charge, to any  person obtaining a copy
  of this software and associated  documentation files (the "Software"), to deal
  in the Software  without restriction, including without  limitation the rights
  to  use, copy,  modify, merge,  publish, distribute,  sublicense, and/or  sell
  copies  of  the Software,  and  to  permit persons  to  whom  the Software  is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE  IS PROVIDED "AS  IS", WITHOUT WARRANTY  OF ANY KIND,  EXPRESS OR
  IMPLIED,  INCLUDING BUT  NOT  LIMITED TO  THE  WARRANTIES OF  MERCHANTABILITY,
  FITNESS FOR  A PARTICULAR PURPOSE AND  NONINFRINGEMENT. IN NO EVENT  SHALL THE
  AUTHORS  OR COPYRIGHT  HOLDERS  BE  LIABLE FOR  ANY  CLAIM,  DAMAGES OR  OTHER
  LIABILITY, WHETHER IN AN ACTION OF  CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE  OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
    
*/

/*
 * In this example the JSON library is used to scan an object that nothing is
 * known about its properties.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../tiny-json.h"

/** Print the value os a json object or array.
  * @param json The handler of the json object or array. */
static void dump( json_t const* json ) {

    jsonType_t const type = json_getType( json );
    if ( type != JSON_OBJ && type != JSON_ARRAY ) {
        puts("error");
        return;
    }

    printf( "%s", type == JSON_OBJ? " {": " [" );

    json_t const* child;
    for( child = json_getChild( json ); child != 0; child = json_getSibling( child ) ) {

        jsonType_t propertyType = json_getType( child );
        char const* name = json_getName( child );
        if ( name ) printf(" \"%s\": ", name );

        if ( propertyType == JSON_OBJ || propertyType == JSON_ARRAY )
            dump( child );

        else {
            char const* value = json_getValue( child );
            if ( value ) {
                bool const text = JSON_TEXT == json_getType( child );
                char const* fmt = text? " \"%s\"": " %s";
                printf( fmt, value );
                bool const last = !json_getSibling( child );
                if ( !last ) putchar(',');
            }
        }
    }

    printf( "%s", type == JSON_OBJ? " }": " ]" );

}

/* Parser a json string. */
int main( void ) {
    char str[] = "{\n"
        "\t\"firstName\": \"Bidhan\",\n"
        "\t\"lastName\": \"Chatterjee\",\n"
        "\t\"age\": 40,\n"
        "\t\"address\": {\n"
        "\t\t\"streetAddress\": \"144 J B Hazra Road\",\n"
        "\t\t\"city\": \"Burdwan\",\n"
        "\t\t\"state\": \"Paschimbanga\",\n"
        "\t\t\"postalCode\": \"713102\"\n"
        "\t},\n"
        "\t\"phoneList\": [\n"
        "\t\t{ \"type\": \"personal\", \"number\": \"09832209761\" },\n"
        "\t\t{ \"type\": \"fax\", \"number\": \"91-342-2567692\" }\n"
        "\t]\n"
        "}\n";
    puts( str );
    json_t mem[32];
    json_t const* json = json_create( str, mem, sizeof mem / sizeof *mem );
    if ( !json ) {
        puts("Error json create.");
        return EXIT_FAILURE;
    }
    puts("Print JSON:");
    dump( json );
    return EXIT_SUCCESS;
}
