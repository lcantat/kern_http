
#ifndef http_parser_h
#define http_parser_h

typedef struct http_parser http_parser;

typedef int (*http_data_cb) (http_parser*, const char *at, size_t length);


struct http_parser 
{
  /** PRIVATE **/
  unsigned char state;          /* enum state from http_parser.c */
  uint32_t nread;               /* # bytes read in various scenarios */

  unsigned char method;         /* requests only */
};

http_parser * http_parser_get(void );


size_t http_parser_recvdata(http_parser * parser,const char * buffer,size_t length);
int http_should_keep_alive(const http_parser *parser);


/* Checks if this is the final chunk of the body. */
int http_body_is_final(const http_parser *parser);

#endif
