/*  
 *  http_mod.c - RFC 2616 module documentation.
 */
#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/init.h>		/* Needed for the macros */


#include "http_engine.h" 

#define DRIVER_AUTHOR "Loïc CANTAT <xxx@yyyy.org>"
#define DRIVER_DESC   "A RFC 2616 implementation"

#define http_debug printk


static int __init init_http(void)
{
	http_debug(KERN_INFO "HTTP module init \n");
	return http_engine_start();
}

static void __exit cleanup_http(void)
{
	http_debug(KERN_INFO "HTTP module cleanup \n");
	http_engine_stop();
}


module_init(init_http);
module_exit(cleanup_http);

/*  
 *  You can use strings, like this:
 */

/* 
 * Get rid of taint message by declaring code as GPL. 
 */
MODULE_LICENSE("GPL");

/*
 * Or with defines, like this:
 */
MODULE_AUTHOR(DRIVER_AUTHOR);	/* Who wrote this module? */
MODULE_DESCRIPTION(DRIVER_DESC);	/* What does this module do */


