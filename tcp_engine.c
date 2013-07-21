/*  
 *  tcp_mod.c 
 */
#include <linux/kernel.h>	/* Needed for KERN_INFO */

/* kthread management*/
//#include <linux/kthread.h>  

/* socket management*/
#include <net/sock.h>
#include <net/tcp.h>

#include <linux/slab.h>
#include <linux/percpu.h>
#include <linux/kthread.h>  

#include "http_engine.h"
#include "tcp_engine.h"

#define tcp_debug(args...) printk (args) //


#define    TCP_LISTEN_CON       0x00
#define    TCP_DATA_CON         0x01

/*
 * A single connection with another host.
 *
 * We maintain a queue of outgoing messages, and some session state to
 * ensure that we can preserve the lossless, ordered delivery of
 * messages in the case of a TCP disconnect.
 */
struct tcp_data_connection 
{
    u32                 type;
	atomic_t            opcount;
 	struct socket *     sock;   
 	
	atomic_t sock_state;

	u32 state; // TODO : suppress
    struct list_head	con_list;
    
	struct mutex mutex;             // TODO : usage ?
	struct delayed_work work;	    /* send|recv work */
};

/*
 * A single connection with another host.
 *
 * We maintain a queue of outgoing messages, and some session state to
 * ensure that we can preserve the lossless, ordered delivery of
 * messages in the case of a TCP disconnect.
 */
struct tcp_listen_connection 
{
    u32                 type;
	atomic_t            opcount;    
	struct socket *     sock;

    struct list_head	con_list;
};

union tcp_connection {
   struct tcp_data_connection   d;
   struct tcp_listen_connection l;
};

/*
TODO 
 */
struct tcp_cpu_context
{
	atomic_t                opcount;     // TODO : use
	struct task_struct *    task;
	union  tcp_connection * conn;  // TODO ?
};

/*
 * work queue for all reading and writing to/from the socket.
 */
static struct tcp_listen_connection s_con;
static struct kmem_cache * s_con_cache;

DEFINE_PER_CPU(struct tcp_cpu_context ,server_context);

/* TODO : check static variable management*/


/*
 * socket callback functions
 */

/* data available on socket, or listen socket received a connect */
static void tcp_sock_data_ready(struct sock *sk, int count_unused)
{
	struct tcp_data_connection *con = sk->sk_user_data;
	/*
	if (atomic_read(&con->msgr->stopping)) {
		return;
	}
    */
    tcp_debug("%s - data ready\n", __func__);
	if (sk->sk_state != TCP_CLOSE_WAIT) 
	{
	    tcp_debug("%s on %d state = %u, queueing work\n", __func__,con->type, con->state);
	}
}

/* socket has buffer space for writing */
static void tcp_sock_write_space(struct sock *sk)
{
	struct tcp_data_connection *con = sk->sk_user_data;

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
	tcp_debug("%s %d nothing to write\n", __func__, con->type);
}

/* socket's state has changed */
static void tcp_sock_state_change(struct sock *sk)
{
	struct tcp_data_connection *con = sk->sk_user_data;

	tcp_debug("%s %d state = %u sk_state = %u\n", __func__,
	     con->type, con->state, sk->sk_state);

	switch (sk->sk_state) {
	case TCP_LAST_ACK:	
		tcp_debug("%s TCP_LAST_ACK\n", __func__);	
		break;	
	case TCP_CLOSE:
		tcp_debug("%s TCP_CLOSE\n", __func__);
	case TCP_CLOSE_WAIT:
		tcp_debug("%s TCP_CLOSE_WAIT\n", __func__);
		// queue_con(con);
		break;
	case TCP_ESTABLISHED:
	    tcp_debug("%s TCP_ESTABLISHED\n", __func__);
		// queue_con(con);
		break;
	default:	/* Everything else is uninteresting */
	    tcp_debug("%s UNNKOWN STATE %d\n", __func__,sk->sk_state);
		break;
	}
}

/*
 * set up socket callbacks
 */
static void set_sock_callbacks(struct socket *sock,struct tcp_data_connection *con)
{
	struct sock *sk = sock->sk;
	sk->sk_user_data = con;
	sk->sk_data_ready = tcp_sock_data_ready;
	sk->sk_write_space = tcp_sock_write_space;
	sk->sk_state_change = tcp_sock_state_change;
}

static void process_read(struct tcp_data_connection * con)
{
    int     ret;	
    char    recv_buffer[512];
    char    send_buffer[512];	
    int     length = 512;   

    ret = tcp_receive_data(con->sock,recv_buffer,length);
    if (ret > 0)
    {
        tcp_debug("tcp_receive_data  = %d\n", ret);	
        ret = http_build_reply(send_buffer,recv_buffer,length);
        tcp_debug("data to send  = %d\n", ret);	
        ret = tcp_send_data(con->sock,send_buffer,ret);
        tcp_debug("tcp_send_data  = %d\n", ret);	
    }
    else
    {
        tcp_debug("No data to process yet %d\n", ret);
    }	    
}

#define CON_SOCK_STATE_NEW		    0	/* -> CLOSED */
#define CON_SOCK_STATE_CLOSED		1	/* -> CONNECTING */
#define CON_SOCK_STATE_CONNECTING	2	/* -> CONNECTED or -> CLOSING */
#define CON_SOCK_STATE_CONNECTED	3	/* -> CLOSING or -> CLOSED */
#define CON_SOCK_STATE_CLOSING		4	/* -> CLOSED */




/* data available on socket, or listen socket received a connect */
static void tcp_listen_data_ready(struct sock *sk, int count_unused)
{   
	struct tcp_listen_connection * con = sk->sk_user_data;
    struct tcp_cpu_context * cpu_context;
    int    ret = 0;
    
    cpu_context = &get_cpu_var(server_context);
    
    ret = atomic_inc_return(&con->opcount);
    if ((ret == 1) || (con->thread == NULL))
    {
        // by default associated connection to current thread
        disable_interupt();
        con->thread = current;
        add_con(current_thread->con_list);
        enable_interupt();
    }
    else
    {
        // already affected to a thread
        if (con->thread == current_thread)
        {
            // nothing to do
        }
    }
       
    ret = atomic_inc_return(&cpu_context->opcount);
    if (ret == 1)
    {
        ret = wake_up_process(cpu_context->task);    
        tcp_debug(KERN_INFO "[%d]wake up counter  %p - %p : %d\n",smp_processor_id(),&cpu_context->opcount,cpu_context->task,ret);
    }
    else
    {
        tcp_debug("[%d]%s - already wake up %d \n",smp_processor_id(), __func__,ret);
    }
    put_cpu_var(server_context);
}

   new_val = atomic_INC_AND_TEST(con_activity)
   if ((new_val == 1) || (con->thread == NULL))
   {
      // by default associated connection to current thread
      disable_interupt();
      con->thread = current;
      add_con(current_thread->con_list);
      enable_interupt();
   }
   else
   {
      // already affected to a thread
      if (con->thread == current_thread)
      {
         // nothing to do
      }
   }
   new_thread_activity = atomic_INC_AND_TEST(con->thread.thread_activity)
   if (new_thread_activity == 1)
   {
      wakeup(thread);
   }  

/*
 * initialize a new connection.
 */
static int tcp_con_init(struct tcp_listen_connection * con)
{
	int ret = 0;
    struct sockaddr_in svr_addr;
	    
	memset(&svr_addr, 0, sizeof(svr_addr));
	svr_addr.sin_family = AF_INET;
	svr_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	svr_addr.sin_port = htons(9090);		

	memset(con, 0, sizeof(*con));
 
	INIT_LIST_HEAD(&con->con_list);

	ret = sock_create(AF_INET, SOCK_STREAM,IPPROTO_TCP, &(con->sock));
	if (ret < 0)
	{
		tcp_debug("sock_create failed %d\n",ret);
		return ret;
	}
	
	/* We attach the data_ready callback to catch new connections*/
	con->sock->sk->sk_user_data    = con;
    con->sock->sk->sk_data_ready   = tcp_listen_data_ready;
    	
	ret = kernel_bind(con->sock, (struct sockaddr *)&svr_addr,sizeof(svr_addr));
	if (ret < 0)
	    goto initerror;
		
	ret = kernel_listen(con->sock, SOMAXCONN);
	if (ret < 0)
	    goto initerror;
	    
    return 0;
    
initerror:
	tcp_debug("tcp_con: svc_create_socket error = %d\n", -ret);
	sock_release(con->sock);	
	return 0;
}


static void tcp_client_constructor(void *buf)
{
    // struct tcp_data_connection * con = (struct tcp_data_connection *) buf;
    // TODO 
}

/*
static void ThreadListenInterupt()
{
   // New connection arriving.
   new_val = atomic_INC_AND_TEST(con_activity)
   if ((new_val == 1) || (con->thread == NULL))
   {
      // by default associated connection to current thread
      disable_interupt();
      con->thread = current;
      add_con(current_thread->con_list);
      enable_interupt();
   }
   else
   {
      // already affected to a thread
      if (con->thread == current_thread)
      {
         // nothing to do
      }
   }
   new_thread_activity = atomic_INC_AND_TEST(con->thread.thread_activity)
   if (new_thread_activity == 1)
   {
      wakeup(thread);
   }  
}
action * get_first_action_pending()
{
   disable_interupt();
   for con in con_list:
      atomic_TEST_AND_DEC(con_activity)
     
   con->thread = current;
   add_con(current_thread->con_list);
   enable_interupt();  
}

void Thread()
{
  
   Initialisation()
   schedule()
  
   while (1)
   {
      val = atomic_TESTandDEC(thread_activity);
      if (val == 0)
      {
         // No more action pending
         schedule();
      }
      else
      {
         action = get_first_action_pending();
         process_action();
      }
   }
} 
*/

static int tcp_server_thread(void * data) 
{
    int ret = 0;
    int opcount = 0;
    char thread_name[TASK_COMM_LEN]; 
    
	struct tcp_listen_connection *      con = &s_con; // TODO ;
	struct tcp_data_connection        * new_con = NULL;
	struct tcp_cpu_context       *      cpu_context = &get_cpu_var(server_context);
	atomic_t                     *      counter = &cpu_context->opcount;
    /* We initialize thread context*/
    get_task_comm(thread_name,current);    
    
    allow_signal(SIGTERM); // TODO : use wakeup instead
    opcount = atomic_read(counter);
	tcp_debug("[%d]Thread %s initialized\n",smp_processor_id(),thread_name);

    while (1)
    {
        /* Ask thread */
        if (!kthread_should_stop())
        {
            opcount = atomic_read(counter);
            BUG_ON(opcount < 0);
            
            tcp_debug(KERN_INFO "[%d]There is %d Operation pending \n",smp_processor_id(),opcount);
            
            if (opcount == 0)
            {
                set_current_state(TASK_INTERRUPTIBLE);
                schedule();   
            }
            else
            {
                /* An active connection is linked to this kthread*/
                new_con = kmem_cache_alloc(s_con_cache, GFP_KERNEL);
                ret = kernel_accept(con->sock, &(new_con->sock),0);
                tcp_debug("accepting new socket %d\n",ret);	        
                if (ret < 0) 
                {
                    if (ret == -EAGAIN) //
                        tcp_debug("ERROR : timing no new socket %d\n",ret);	
	                    continue;
                    break;
                }
                else
                {
                    atomic_set(&new_con->sock_state,CON_SOCK_STATE_CONNECTED);
                    set_sock_callbacks(new_con->sock,new_con);
                    process_read(new_con);
                }
                
                // Opération completed, we decrement opcount
                tcp_debug(KERN_INFO "[%d]Operation completed  %s \n",smp_processor_id(),thread_name);
                atomic_dec(counter);
	        }
        }
        else
        {
            set_current_state(TASK_RUNNING);
            tcp_debug(KERN_INFO "Stopping kernel thread  %s \n",thread_name);
            break;
        }
    }   
    return 0;
}

/* TODO : add parameter (if / port / ...)*/
int  tcp_engine_start(void)
{
    struct task_struct * task;
    atomic_t * counter = NULL;
    int i;
    
	tcp_debug(KERN_INFO "TCP module start \n");

	s_con_cache = kmem_cache_create("tcp_cache",sizeof (struct tcp_data_connection), 0,0,tcp_client_constructor);
	
    tcp_con_init(&s_con);
	
    for_each_online_cpu(i)
    {
        counter = &per_cpu(server_context, i).opcount;
        atomic_set(counter,0);    
        task = kthread_create(tcp_server_thread,NULL,"tcpwork/%d", i);
        kthread_bind(task,i);
        per_cpu(server_context, i).task = task;
    }
    
    for_each_online_cpu(i)
    {
        counter = &per_cpu(server_context, i).opcount;
        task =  per_cpu(server_context, i).task;
        if (!IS_ERR(task))                                               
        {
            tcp_debug(KERN_INFO "thread handle %d to  %p - %p\n",i,task,counter);
            wake_up_process(task);
        } 
    }
      
	return -ENOMEM;
}
 
int tcp_engine_stop(void)
{
    struct task_struct * task;
    int i;
    
	int ret = 0;
	tcp_debug(KERN_INFO "TCP module stop \n");
	      
    for_each_online_cpu(i)
    {    
        task = per_cpu(server_context, i).task;
        
        tcp_debug(KERN_INFO "thread handle %d to realease %p \n",i,task);
	    send_sig(SIGTERM, task, 1);	
	    kthread_stop(task);        
    }
    
    if (s_con.sock)
	    ret = s_con.sock->ops->release(s_con.sock);
		sock_release(s_con.sock);
        tcp_debug("release binded socket = %d\n", ret);
        	 
	return 0;
}


