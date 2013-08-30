
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include "http_parser.h" 

static http_parser default_parser;


enum state
  { s_dead = 1 /* important that this is > 0 */

  , s_http_open
 
  , s_headers_almost_done
  , s_headers_done

  /* Important: 's_headers_done' must be the last 'header' state. All
* states beyond this must be 'body' states. It is used for overflow
* checking. See the PARSING_HEADER() macro.
*/

  , s_chunk_data
  , s_chunk_data_almost_done
  , s_chunk_data_done

  , s_body_identity
  , s_body_identity_eof

  , s_message_done
  };



http_parser * http_parser_get(void)
{
    default_parser.nread = 0;
    
    return &default_parser;
}

/* Request content 
Request       = Request-Line              ; Section 5.1
                *(( general-header        ; Section 4.5
                 | request-header         ; Section 5.3
                 | entity-header ) CRLF)  ; Section 7.1
                CRLF
                [ message-body ]          ; Section 4.3*/

/* For optimisation purpose, we consider that line are completed*/                
size_t http_parser_recvdata(http_parser * parser,const char * buffer,size_t length)
{
    return 0;
}


int http_should_keep_alive(const http_parser *parser)
{
    return 0;
}


/* Checks if this is the final chunk of the body. */
int http_body_is_final(const http_parser *parser)
{
    return 0;
}

