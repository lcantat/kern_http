
#ifndef http_engine_h
#define http_engine_h

int http_engine_start(void);
int http_engine_stop(void);

int tcp_engine_start(void);
int tcp_engine_stop(void);

int tcp_receive_data(struct socket * sk,char * buffer,int    length);
int tcp_send_data(struct socket * sk,char * buffer,int length);
int http_build_reply(char * out_buffer,char * in_buffer,int max_length);

#endif /*http_engine_h*/
