/*  
 *  tcp_mod.c 
 */
#include <linux/kernel.h>	/* Needed for KERN_INFO */

/* kthread management*/
#include <linux/kthread.h>  

/* socket management*/
#include <net/sock.h>
#include <net/tcp.h>

#include "http_engine.h"
#define tcp_debug printk // TODO

#define CON_SOCK_STATE_NEW		0	/* -> CLOSED */
#define CON_SOCK_STATE_CLOSED		1	/* -> CONNECTING */
#define CON_SOCK_STATE_CONNECTING	2	/* -> CONNECTED or -> CLOSING */
#define CON_SOCK_STATE_CONNECTED	3	/* -> CLOSING or -> CLOSED */
#define CON_SOCK_STATE_CLOSING		4	/* -> CLOSED */

#define CON_SOCK_TYPE_LISTENING		1	
#define CON_SOCK_TYPE_ACCEPTED		2	

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

struct tcp_connection;
struct http_msg;

static void queue_con(struct tcp_connection *con);
static void con_work(struct work_struct *);
static void con_fault(struct tcp_connection *con);

/*
 * Ceph defines these callbacks for handling connection events.
 */
struct tcp_connection_operations 
{
    
	// TODO struct tcp_connection *(*get)(struct tcp_connection *);
	// TODO void (*put)(struct tcp_connection *);

	/* handle an incoming message. */
	// TODO void (*dispatch) (struct tcp_connection *con, struct http_msg *m);

	/* authorize an outgoing connection */
	/* TODO struct tcp_auth_handshake *(*get_authorizer) (
				struct tcp_connection *con,
			       int *proto, int force_new);*/
	// TODO int (*verify_authorizer_reply) (struct tcp_connection *con, int len);
	// TODO int (*invalidate_authorizer)(struct tcp_connection *con);

	/* there was some error on the socket (disconnect, whatever) */
	// TODO void (*fault) (struct tcp_connection *con);

	/* a remote host as terminated a message exchange session, and messages
	 * we sent (or they tried to send us) may be lost. */
	// TODO void (*peer_reset) (struct tcp_connection *con);

	// TODO struct http_msg * (*alloc_msg) (struct tcp_connection *con,
	// TODO 				int *skip);
};


/*
 * A single connection with another host.
 *
 * We maintain a queue of outgoing messages, and some session state to
 * ensure that we can preserve the lossless, ordered delivery of
 * messages in the case of a TCP disconnect.
 */
struct tcp_connection {
	void *private;

	const struct tcp_connection_operations *ops;

	atomic_t sock_state;
	struct socket *sock;

	/* TODO */unsigned long flags;
	unsigned long state;
    unsigned long type;
    
	struct mutex mutex; // TODO : usage ?
	struct delayed_work work;	    /* send|recv work */
	unsigned long       delay;      /* current delay interval */
};

/*
 * a single message.  
 */
struct http_msg {
    
	/* TODO */
};


/*
 * work queue for all reading and writing to/from the socket.
 */
static struct workqueue_struct * tcp_msgr_wq = NULL;


/*
 * Atomically queue work on a connection after the specified delay.
 * Bump @con reference to avoid races with connection teardown.
 * Returns 0 if work was queued, or an error code otherwise.
 */
static void queue_con(struct tcp_connection *con)
{
     unsigned long delay = 0; 
     /* TODO 
	if (!con->ops->get(con)) {
		tcp_debug("%s %p ref count 0\n", __func__, con);

		return -ENOENT;
	}*/

	if (!queue_work(tcp_msgr_wq, &con->work)) 
	{
		tcp_debug("%s %p - already queued\n", __func__, con);
		// TODO con->ops->put(con);

		return -EBUSY;
	}

	tcp_debug("%s %p %lu\n", __func__, con, delay);

	return 0;
}



/* Connection socket state transition functions */

static void con_sock_state_init(struct tcp_connection *con)
{
	int old_state;

	old_state = atomic_xchg(&con->sock_state, CON_SOCK_STATE_CLOSED);
	if (WARN_ON(old_state != CON_SOCK_STATE_NEW))
		printk("%s: unexpected old state %d\n", __func__, old_state);
	tcp_debug("%s con %p sock %d -> %d\n", __func__, con, old_state,
	     CON_SOCK_STATE_CLOSED);
}

static void con_sock_state_connecting(struct tcp_connection *con)
{
	int old_state;

	old_state = atomic_xchg(&con->sock_state, CON_SOCK_STATE_CONNECTING);
	tcp_debug("%s con %p sock %d -> %d\n", __func__, con, old_state,CON_SOCK_STATE_CONNECTING);
}

static void con_sock_state_connected(struct tcp_connection *con)
{
	int old_state;

	old_state = atomic_xchg(&con->sock_state, CON_SOCK_STATE_CONNECTED);
	tcp_debug("%s con %p sock %d -> %d\n", __func__, con, old_state,CON_SOCK_STATE_CONNECTED);
}

static void con_sock_state_closing(struct tcp_connection *con)
{
	int old_state;

	old_state = atomic_xchg(&con->sock_state, CON_SOCK_STATE_CLOSING);
	tcp_debug("%s con %p sock %d -> %d\n", __func__, con, old_state,CON_SOCK_STATE_CLOSING);
}

static void con_sock_state_closed(struct tcp_connection *con)
{
	int old_state;

	old_state = atomic_xchg(&con->sock_state, CON_SOCK_STATE_CLOSED);
	tcp_debug("%s con %p sock %d -> %d\n", __func__, con, old_state,CON_SOCK_STATE_CLOSED);
}

/*
 * socket callback functions
 */

/* data available on socket, or listen socket received a connect */
static void tcp_sock_data_ready(struct sock *sk, int count_unused)
{
	struct tcp_connection *con = sk->sk_user_data;
	/*
	if (atomic_read(&con->msgr->stopping)) {
		return;
	}
    */
    
    if (con->type == CON_SOCK_TYPE_LISTENING)
    {
        tcp_debug("%s on %p state = %lu, no operations for listing sock\n", __func__,con, con->state);
    }
    else if (con->type == CON_SOCK_TYPE_ACCEPTED)
    {
	    if (sk->sk_state != TCP_CLOSE_WAIT) 
	    {
		    tcp_debug("%s on %p state = %lu, queueing work\n", __func__,con, con->state);
		    queue_con(con);
	    }
	}
}

/* socket has buffer space for writing */
static void tcp_sock_write_space(struct sock *sk)
{
	struct tcp_connection *con = sk->sk_user_data;

	/* only queue to workqueue if there is data we want to write,
	 * and there is sufficient space in the socket buffer to accept
	 * more data.  clear SOCK_NOSPACE so that tcp_sock_write_space()
	 * doesn't get called again until try_write() fills the socket
	 * buffer. See net/ipv4/tcp_input.c:tcp_check_space()
	 * and net/core/stream.c:sk_stream_write_space().
	 */
	/* TODO 
	if (con_flag_test(con, CON_FLAG_WRITE_PENDING)) {
		if (sk_stream_wspace(sk) >= sk_stream_min_wspace(sk)) {
			tcp_debug("%s %p queueing write work\n", __func__, con);
			clear_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
			queue_con(con);
		}
	} else {
		
	}*/
	tcp_debug("%s %p nothing to write\n", __func__, con);
}

/* socket's state has changed */
static void tcp_sock_state_change(struct sock *sk)
{
	struct tcp_connection *con = sk->sk_user_data;

	tcp_debug("%s %p state = %lu sk_state = %u\n", __func__,
	     con, con->state, sk->sk_state);

	switch (sk->sk_state) {
	case TCP_CLOSE:
		tcp_debug("%s TCP_CLOSE\n", __func__);
	case TCP_CLOSE_WAIT:
		tcp_debug("%s TCP_CLOSE_WAIT\n", __func__);
		con_sock_state_closing(con);
		// TODO con_flag_set(con, CON_FLAG_SOCK_CLOSED);
		queue_con(con);
		break;
	case TCP_ESTABLISHED:
		tcp_debug("%s TCP_ESTABLISHED\n", __func__);
		con_sock_state_connected(con);
		queue_con(con);
		break;
	default:	/* Everything else is uninteresting */
		break;
	}
}

/*
 * set up socket callbacks
 */
static void set_sock_callbacks(struct socket *sock,struct tcp_connection *con)
{
	struct sock *sk = sock->sk;
	sk->sk_user_data = con;
	sk->sk_data_ready = tcp_sock_data_ready;
	sk->sk_write_space = tcp_sock_write_space;
	sk->sk_state_change = tcp_sock_state_change;
}


static struct tcp_connection_operations s_ops;
static struct tcp_connection s_con;
static struct tcp_connection s_con_cli;
/*
 * Do some work on a connection.  Drop a connection ref when we're done.
 */
static void con_work(struct work_struct *work)
{
	struct tcp_connection *con = container_of(work, struct tcp_connection,work.work);
	int ret;	
	char   recv_buffer[512];
	char   send_buffer[512];	
	int    length = 512;
		
    tcp_debug("do work \n");
	mutex_lock(&con->mutex);
	while (true) 
	{

		if (con->type == CON_SOCK_TYPE_LISTENING)
		{
		    tcp_debug("wait socket to accept \n");
	        ret = kernel_accept(con->sock, &(s_con_cli.sock),0);
		    if (ret < 0) 
		    {
			    if (ret == -EAGAIN)
				    continue;
			    break;
		    }
		    else
		    {
			    s_con_cli.private = NULL;
	            s_con_cli.ops = &s_ops;
                s_con_cli.type = CON_SOCK_TYPE_ACCEPTED;	

	            con_sock_state_init(&s_con_cli);

	            mutex_init(&s_con_cli.mutex);
	            INIT_DELAYED_WORK(&s_con_cli.work, con_work);

	            s_con_cli.state = CON_STATE_OPEN;
	            set_sock_callbacks(s_con_cli.sock,&s_con_cli);
		    }
		}
		if (con->type == CON_SOCK_TYPE_ACCEPTED)
		{		
	        ret = tcp_receive_data(con->sock,recv_buffer,length);
            tcp_debug("tcp_receive_data  = %d\n", ret);	
            ret = http_build_reply(send_buffer,recv_buffer,length);
            
            ret = tcp_send_data(con->sock,send_buffer,ret);
            tcp_debug("tcp_send_data  = %d\n", ret);	
            msleep(15000);        
            kernel_sock_shutdown(con->sock,SHUT_RDWR);
            ret = con->sock->ops->release(con->sock);
	        sock_release(con->sock);
	        con->sock = NULL;
            tcp_debug("release  = %d\n", ret);	
        }
		break;	/* If we make it to here, we're done */
	}
	
	/* TODO if (fault)
		con_fault(con); */ 
	mutex_unlock(&con->mutex);
	
	/* TODO if (fault)
	if (fault)
		con_fault_finish(con);*/ 

	// TODO con->ops->put(con);
}




/*
 * initialize a new connection.
 */
static void tcp_con_init(  void *private)
{
	int ret = 0;
	struct tcp_connection * con = &s_con;    
    struct sockaddr_in svr_addr;
    
	memset(&svr_addr, 0, sizeof(svr_addr));
	svr_addr.sin_family = AF_INET;
	svr_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	svr_addr.sin_port = htons(9090);		
	
    
	tcp_debug("con_init %p\n", con);
	memset(con, 0, sizeof(*con));
	con->private = private;
	con->ops = &s_ops;
    con->type = CON_SOCK_TYPE_LISTENING;	
	// TODO con->msgr = msgr;

	con_sock_state_init(con);

	mutex_init(&con->mutex);
	// TODO INIT_LIST_HEAD(&con->out_queue);
	// TODO INIT_LIST_HEAD(&con->out_sent);
	INIT_DELAYED_WORK(&con->work, con_work);

	con->state = CON_STATE_CLOSED;
	
	ret = sock_create(AF_INET, SOCK_STREAM,IPPROTO_TCP, &(con->sock));
	if (ret < 0)
	{
		tcp_debug("sock_create failed %d\n",ret);
		return ret;
	}

	set_sock_callbacks(con->sock,con);
	
	ret = con->sock->ops->bind(con->sock, (struct sockaddr *)&svr_addr,sizeof(svr_addr));
	tcp_debug("bind ret = %d\n", ret);
		
	ret = con->sock->ops->listen(con->sock, SOMAXCONN);
	tcp_debug("bind listen = %d\n", ret);	
}




static void _tcp_msgr_exit(void)
{
	if (tcp_msgr_wq) 
	{
	    flush_workqueue(tcp_msgr_wq);
		destroy_workqueue(tcp_msgr_wq);
		tcp_msgr_wq = NULL;
	}
}

/* TODO : add parameter (if / port / ...)*/
int  tcp_engine_start(void)
{

	tcp_debug(KERN_INFO "TCP module start \n");
	tcp_con_init(NULL);
	
	tcp_msgr_wq = alloc_workqueue("ceph-msgr", WQ_NON_REENTRANT, 0); // TODO : check the WQ_NON_REENTRANT
	if (tcp_msgr_wq)
		return 0;
		

    
	pr_err("msgr_init failed to create workqueue\n");
	_tcp_msgr_exit();

	return -ENOMEM;
}

int tcp_engine_stop(void)
{
	int ret = 0;
	tcp_debug(KERN_INFO "TCP module stop \n");
	// TODO : order stop
    if (s_con.sock)
	    ret = s_con.sock->ops->release(s_con.sock);
		sock_release(s_con.sock);
        tcp_debug("release binded socket = %d\n", ret);
        	
	_tcp_msgr_exit();	
	return 0;
}
