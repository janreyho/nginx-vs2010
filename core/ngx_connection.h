
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_CONNECTION_H_INCLUDED_
#define _NGX_CONNECTION_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_listening_s  ngx_listening_t;

struct ngx_listening_s {
    ngx_socket_t        fd;	//套接字句柄

    struct sockaddr    *sockaddr;	//监听sockaddr地址
    socklen_t           socklen;    /* size of sockaddr */
    size_t              addr_text_max_len;	//存储ip地址的字符串addr_text最大长度
    ngx_str_t           addr_text;	//以字符串形式存储ip地址

    int                 type;

	/**
	 * TCP实现监听时的backlog队列
	 * 它表示允许正在通过三次握手建立tcp连接
	 * 但还没有任何进程开始处理的连接最大个数
	**/
    int                 backlog;
    int                 rcvbuf;	//套接字接收缓冲区大小
    int                 sndbuf;	//套接字发送缓冲区大小

	/**
	 * 当新的tcp连接成功建立后的处理方法
	**/
    /* handler of accepted connection */
    ngx_connection_handler_pt   handler;

	/**
	 * 目前主要用于HTTP或者mail等模块
	 * 用于保存当前监听端口对应着的所有主机名
	**/
    void               *servers;  /* array of ngx_http_in_addr_t, for example */

    ngx_log_t           log;	//日志
    ngx_log_t          *logp;	//日志指针

	/**
	 * 如果为新的tcp连接创建内存池，则内存池的初始大小应该为pool size
	**/
    size_t              pool_size;
    /* should be here because of the AcceptEx() preread */
    size_t              post_accept_buffer_size;
    /* should be here because of the deferred accept */
    ngx_msec_t          post_accept_timeout;	//x秒后仍然没有收到用户的数据，则丢弃该连接

	/**
	 * 前一个ngx_listening_t结构，用于组成单链表
	**/
    ngx_listening_t    *previous;
    ngx_connection_t   *connection; //当前监听句柄对应的ngx_connection_t结构

    unsigned            open:1;	//1表示监听句柄有效，0表示正常关闭
    unsigned            remain:1; //为1表示不关闭原先打开的监听端口，0表示关闭曾经打开的监听端口
    unsigned            ignore:1; //1表示跳过设置当前ngx_listening_t结构中的套接字，0表示正常设置

    unsigned            bound:1;       /* already bound */
    unsigned            inherited:1;   /* inherited from previous process */
    unsigned            nonblocking_accept:1;
    unsigned            listen:1;	//1表示当前结构体对应的套接字已经监听
    unsigned            nonblocking:1;
    unsigned            shared:1;    /* shared between threads or processes */
    unsigned            addr_ntop:1;	//为1表示将网络地址转变为字符串形式的地址

#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned            ipv6only:2;
#endif

#if (NGX_HAVE_DEFERRED_ACCEPT)
    unsigned            deferred_accept:1;
    unsigned            delete_deferred:1;
    unsigned            add_deferred:1;
#ifdef SO_ACCEPTFILTER
    char               *accept_filter;
#endif
#endif
#if (NGX_HAVE_SETFIB)
    int                 setfib;
#endif

};


typedef enum {
     NGX_ERROR_ALERT = 0,
     NGX_ERROR_ERR,
     NGX_ERROR_INFO,
     NGX_ERROR_IGNORE_ECONNRESET,
     NGX_ERROR_IGNORE_EINVAL
} ngx_connection_log_error_e;


typedef enum {
     NGX_TCP_NODELAY_UNSET = 0,
     NGX_TCP_NODELAY_SET,
     NGX_TCP_NODELAY_DISABLED
} ngx_connection_tcp_nodelay_e;


typedef enum {
     NGX_TCP_NOPUSH_UNSET = 0,
     NGX_TCP_NOPUSH_SET,
     NGX_TCP_NOPUSH_DISABLED
} ngx_connection_tcp_nopush_e;


#define NGX_LOWLEVEL_BUFFERED  0x0f
#define NGX_SSL_BUFFERED       0x01


struct ngx_connection_s {
	/**
	 * 连接未使用时，data充当连接池中空闲链表中的next
	 * 连接使用时，由模块决定，对于http模块，data指向ngx_http_request_t
	**/
    void               *data;
    ngx_event_t        *read;	//连接对应的读事件
    ngx_event_t        *write;	//连接对应的写事件

    ngx_socket_t        fd;	//套接字对应的句柄

    ngx_recv_pt         recv;	//直接接收网络字符流的方法
    ngx_send_pt         send;	//直接发送网络字符流的方法
    ngx_recv_chain_pt   recv_chain;	//以链表来接收网络字符串流的方法
    ngx_send_chain_pt   send_chain;	//以链表来发送网络字符串流的方法

	/**
	 * 这个连接对应的ngx_listen_t监听对象
	 * 此连接由listening监听端口的事件建立
	**/
    ngx_listening_t    *listening;

    off_t               sent;	//这个连接上已发送的字节数

    ngx_log_t          *log;	//日志对象

	/**
	 * 内存池
	 * 一般在accept一个新的连接时
	 * 会创建一个内存池
	 * 而在这个连接结束时会销毁内存池
	 * 内存池大小是由上面listening成员的pool size决定的
	**/
    ngx_pool_t         *pool;

    struct sockaddr    *sockaddr;	//连接客户端的sockaddr
    socklen_t           socklen;	//sockaddr结构体的长度
    ngx_str_t           addr_text;	//连接客户端字符串形式的IP地址


#if (NGX_SSL)
    ngx_ssl_connection_t  *ssl;
#endif

    struct sockaddr    *local_sockaddr;	//本机监听端口对应的sockaddr结构体，实际上就是listening监听对象的sockaddr成员

    ngx_buf_t          *buffer;	//用户接受、缓存客户端发来的字符流，buffer是由连接内存池分配的，大小自由决定

	/**
	 * 用来将当前连接以双向链表元素的形式添加到ngx_cycle_t核心结构体
	 * 的reuseable_connection_queue双向链表中，表示可以重用的连接
	**/
    ngx_queue_t         queue;

	/**
	 * 连接使用次数
	 * ngx_connection_t结构体每次建立一条来自客户端的连接
	 * 或者主动向后端服务器发起连接
	 * number 都会+1
	**/
    ngx_atomic_uint_t   number;

    ngx_uint_t          requests;	//处理的请求次数

    unsigned            buffered:8;	//缓存中的业务类型

    unsigned            log_error:3;     /* ngx_connection_log_error_e */

    unsigned            single_connection:1;	//为1表示独立的连接，为0表示依靠其他连接行为而建立起来的非独立连接
    unsigned            unexpected_eof:1;	//为1表示不期待字符流结束
    unsigned            timedout:1;	//为1 表示连接已经销毁
    unsigned            error:1;
    unsigned            destroyed:1;

    unsigned            idle:1;	//为1 表示连接处于空闲状态，如keepalive两次请求中间的状态
    unsigned            reusable:1;	//为1表示连接可重用，与上面的queue字段结合使用
    unsigned            close:1;	//1表示连接关闭

    unsigned            sendfile:1;	//为1表示正在将文件中的数据发往连接的另一端
	/**
	 * 为1 表示只有连接套接字对应的发送缓冲区必须满足最低设置的大小阈值
	 * 事件驱动模块才会分发该事件
	 * 这与ngx_handle_write_event方法中的lowat参数是对应的
	**/
    unsigned            sndlowat:1;
    unsigned            tcp_nodelay:2;   /* ngx_connection_tcp_nodelay_e */
    unsigned            tcp_nopush:2;    /* ngx_connection_tcp_nopush_e */

#if (NGX_HAVE_IOCP)
    unsigned            accept_context_updated:1;
#endif

#if (NGX_HAVE_AIO_SENDFILE)
    unsigned            aio_sendfile:1;
    ngx_buf_t          *busy_sendfile;
#endif

#if (NGX_THREADS)
    ngx_atomic_t        lock;
#endif
};


ngx_listening_t *ngx_create_listening(ngx_conf_t *cf, void *sockaddr,
    socklen_t socklen);
ngx_int_t ngx_set_inherited_sockets(ngx_cycle_t *cycle);
ngx_int_t ngx_open_listening_sockets(ngx_cycle_t *cycle);
void ngx_configure_listening_sockets(ngx_cycle_t *cycle);
void ngx_close_listening_sockets(ngx_cycle_t *cycle);
void ngx_close_connection(ngx_connection_t *c);
ngx_int_t ngx_connection_local_sockaddr(ngx_connection_t *c, ngx_str_t *s,
    ngx_uint_t port);
ngx_int_t ngx_connection_error(ngx_connection_t *c, ngx_err_t err, char *text);

ngx_connection_t *ngx_get_connection(ngx_socket_t s, ngx_log_t *log);
void ngx_free_connection(ngx_connection_t *c);

void ngx_reusable_connection(ngx_connection_t *c, ngx_uint_t reusable);

#endif /* _NGX_CONNECTION_H_INCLUDED_ */
