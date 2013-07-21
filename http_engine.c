/*  
 *  http_mod.c - RFC 2616 module documentation.
 */
#include <linux/kernel.h>	/* Needed for KERN_INFO */

/* kthread management*/
#include <linux/kthread.h>  

/* socket management*/
#include <net/sock.h>

#include "http_parser.h"


#define http_debug printk // TODO

static struct task_struct * server_task; // TODO multiple server

int tcp_receive_data(struct socket * sk,char * buffer,int    length)
{
	struct msghdr msg;
	struct iovec iov;
	int ret;
	
	iov.iov_base = (void *)buffer;
	iov.iov_len = (__kernel_size_t)length;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
    msg.msg_flags = MSG_DONTWAIT;
 
	ret = sock_recvmsg(sk, &msg, length, 0);

    buffer[ret] = 0;
	printk(buffer);
	return ret;
}

int tcp_send_data(struct socket * sk,char * buffer,int length)
{
	struct msghdr msg;
	struct iovec iov;
	int len;

	iov.iov_base = (void *)buffer;
	iov.iov_len = (__kernel_size_t)length;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;
	
	len = sock_sendmsg(sk, &msg, length);
	
	return len;
}

const char * html_header = "HTTP/1.1 200 OK\n\
Content-Type: text/html; charset=utf-8\n\
Connection: close\n\
Content-Length: "; 

const char * html_content = "<html><body><h1>It works!</h1>\
<p>This is the default web page for this server.</p>\
<p>The web server software is running but no content has been added, yet.</p>\
</body></html>\n";


int http_build_reply(char * out_buffer,char * in_buffer,int max_length)
{
    int len;
    int msg_len = strlen(html_content);
    
    len = sprintf(out_buffer,"%s%d\n\n%s",html_header,msg_len,html_content);
    printk("Compute html content %d octets total size = %d \n",(int)strlen(html_content),len);
    
    return len;
}

static void  (*sk_old_data_ready)(struct sock *sk, int bytes) = NULL;

/* data available on socket, or listen socket received a connect */
static void ceph_sock_data_ready(struct sock *sk, int count_unused)
{
    char    recv_buffer[512];
	int     length = 512;  
	int     ret = 0;	  
    struct socket * sk_socket = sk->sk_socket;
    
    /*TODO : Use this method to handle multiple connections*/
    printk("sock_data_ready %d \n",count_unused);
    sk_old_data_ready(sk,count_unused);
    
    // ret = tcp_receive_data(sk_socket,recv_buffer,length);
    // http_debug("tcp_receive_data  = %d\n", ret);    
/*        struct ceph_connection *con = sk->sk_user_data;
        if (atomic_read(&con->msgr->stopping)) {
                return;
        }

        if (sk->sk_state != TCP_CLOSE_WAIT) {
                dout("%s on %p state = %lu, queueing work\n", __func__,
                     con, con->state);
                queue_con(con);
        }
*/
}

static void set_sock_callbacks(struct socket *sock)
{
        struct sock *sk = sock->sk;
        // sk->sk_user_data = con;
        sk_old_data_ready = sk->sk_data_ready;
        sk->sk_data_ready = ceph_sock_data_ready;
        //sk->sk_write_space = ceph_sock_write_space;
        //sk->sk_state_change = ceph_sock_state_change;
}

static int tcp_server_thread(void *data) 
{
	char   recv_buffer[512];
	char   send_buffer[512];	
	int    length = 512;
    struct socket *sk = NULL;
    struct socket *new_sk = NULL;
    http_parser * cur_parser = NULL;
    struct sockaddr_in svr_addr;
    struct sockaddr_in client_addr;
	int ret = 0;
	
	memset(&svr_addr, 0, sizeof(svr_addr));
	svr_addr.sin_family = AF_INET;
	svr_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	svr_addr.sin_port = htons(9090);		

    allow_signal(SIGTERM);

    http_debug(KERN_INFO "HTTP listen thread start\n");
    
	ret = sock_create(AF_INET, SOCK_STREAM,IPPROTO_TCP, &sk);
	if (ret < 0)
	{
		http_debug("sock_create failed %d\n",ret);
		return ret;
	}
	ret = sk->ops->bind(sk, (struct sockaddr *)&svr_addr,sizeof(svr_addr));
	http_debug("bind ret = %d\n", ret);
		
	ret = sk->ops->listen(sk, SOMAXCONN);
	http_debug("bind listen = %d\n", ret);
    while (1)
    {
        set_current_state(TASK_INTERRUPTIBLE);
        if (!kthread_should_stop())
        {
            http_debug("wait socket to accept \n");
	        ret = kernel_accept(sk, &new_sk,0);
	        
	        if (ret >= 0)
	        {
	            http_debug("connection received %d\n", ret);
                // TODO : IPV6         	    
	            ret = kernel_getpeername(new_sk,(struct sockaddr *)&client_addr,&length);
		        printk("client sock %d : %X:%d\n",length,client_addr.sin_addr.s_addr,htons(client_addr.sin_port));
		        
                set_current_state(TASK_RUNNING);
                set_sock_callbacks(new_sk); // TODO : handle read / right
                
                cur_parser = http_parser_get();
                http_parser_recvdata(cur_parser,recv_buffer,length);
                
                ret = tcp_receive_data(new_sk,recv_buffer,length);
                http_debug("tcp_receive_data  = %d\n", ret);	
                ret = http_build_reply(send_buffer,recv_buffer,length);
                
                ret = tcp_send_data(new_sk,send_buffer,ret);
                http_debug("tcp_send_data  = %d\n", ret);	
                msleep(15000);        
                kernel_sock_shutdown(new_sk,SHUT_RDWR);
	            ret = new_sk->ops->release(new_sk);
		        sock_release(new_sk);
                http_debug("release  = %d\n", ret);	
		    }
		    else
		    {
	            http_debug("no connection received %d\n", ret);
		        break;		        
		    }
            
            
	
        }
        else
        {
            break;
        }                   
    }
    
    if (sk)
	    ret = sk->ops->release(sk);
		sock_release(sk);
        http_debug("release binded socket = %d\n", ret);

	return ret;
}


/* TODO : add parameter (if / port / ...)*/
int  http_engine_start(void)
{
	http_debug(KERN_INFO "HTTP module start \n");
	/* creating a thread for connection management */
	server_task = kthread_run(tcp_server_thread, NULL, "server task");
	if (IS_ERR(server_task)) 
	{
        printk(KERN_ERR "can't start http daemon\n");
        return PTR_ERR(server_task);
    }
	
	return 0;
}

int http_engine_stop(void)
{
	http_debug(KERN_INFO "HTTP module stop \n");
	send_sig(SIGTERM, server_task, 1);	
	kthread_stop(server_task);
	return 0;
}


