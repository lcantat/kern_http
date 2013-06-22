
#ifndef http_parser_h
#define http_parser_h

typedef struct http_parser http_parser;

typedef int (*http_data_cb) (http_parser*, const char *at, size_t length);


/* Flag values for http_parser.flags field */
enum flags
  { F_CHUNKED = 1 << 0
  , F_CONNECTION_KEEP_ALIVE = 1 << 1
  , F_CONNECTION_CLOSE = 1 << 2
  , F_TRAILING = 1 << 3
  , F_UPGRADE = 1 << 4
  , F_SKIPBODY = 1 << 5
  };


struct http_parser 
{
  /** PRIVATE **/
  unsigned char state;          /* enum state from http_parser.c */
  unsigned char header_state;   /* enum header_state from http_parser.c */
  unsigned char index;          /* index into current matcher */

  uint32_t nread;               /* # bytes read in various scenarios */
  uint64_t content_length;      /* # bytes in body (0 if no Content-Length header) */

  /** READ-ONLY **/
  unsigned short http_major;
  unsigned short http_minor;
  unsigned short status_code;   /* responses only */
  unsigned char method;         /* requests only */
};

http_parser * http_parser_get();


size_t http_parser_recvdata(http_parser * parser,const char * buffer,size_t length);
int http_should_keep_alive(const http_parser *parser);


/* Checks if this is the final chunk of the body. */
int http_body_is_final(const http_parser *parser);

#endif
