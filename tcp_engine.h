
#ifndef tcp_engine_h
#define tcp_engine_h

#define CON_SOCK_TYPE_LISTENING		1	
#define CON_SOCK_TYPE_ACCEPTED		2	



// TODO : A  nettoyer 
#define CON_SOCK_STATE_NEW		    0	/* -> CLOSED */
#define CON_SOCK_STATE_CLOSED		1	/* -> CONNECTING */
#define CON_SOCK_STATE_CONNECTING	2	/* -> CONNECTED or -> CLOSING */
#define CON_SOCK_STATE_CONNECTED	3	/* -> CLOSING or -> CLOSED */
#define CON_SOCK_STATE_CLOSING		4	/* -> CLOSED */


/*
 * connection states
 */
#define CON_STATE_CLOSED        1  /* -> PREOPEN */
#define CON_STATE_PREOPEN       2  /* -> CONNECTING, CLOSED */
#define CON_STATE_CONNECTING    3  /* -> NEGOTIATING, CLOSED */
#define CON_STATE_NEGOTIATING   4  /* -> OPEN, CLOSED */
#define CON_STATE_OPEN          5  /* -> STANDBY, CLOSED */
#define CON_STATE_STANDBY       6  /* -> PREOPEN, CLOSED */

/*
 * tcp_connection flag bits // TODO supprimer inutile
 */
#define CON_FLAG_LOSSYTX           0  /* we can close channel or drop
				       * messages on errors */
#define CON_FLAG_KEEPALIVE_PENDING 1  /* we need to send a keepalive */
#define CON_FLAG_WRITE_PENDING	   2  /* we have data ready to send */
#define CON_FLAG_SOCK_CLOSED	   3  /* socket state changed to closed */
#define CON_FLAG_BACKOFF           4  /* need to retry queuing delayed work */

#endif /*tcp_engine_h*/
