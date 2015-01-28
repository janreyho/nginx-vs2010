
/*
 * Copyright (C) Igor Sysoev
 */


#ifndef _NGX_CONNECTION_H_INCLUDED_
#define _NGX_CONNECTION_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_listening_s  ngx_listening_t;

struct ngx_listening_s {
    ngx_socket_t        fd;	//�׽��־��

    struct sockaddr    *sockaddr;	//����sockaddr��ַ
    socklen_t           socklen;    /* size of sockaddr */
    size_t              addr_text_max_len;	//�洢ip��ַ���ַ���addr_text��󳤶�
    ngx_str_t           addr_text;	//���ַ�����ʽ�洢ip��ַ

    int                 type;

	/**
	 * TCPʵ�ּ���ʱ��backlog����
	 * ����ʾ��������ͨ���������ֽ���tcp����
	 * ����û���κν��̿�ʼ���������������
	**/
    int                 backlog;
    int                 rcvbuf;	//�׽��ֽ��ջ�������С
    int                 sndbuf;	//�׽��ַ��ͻ�������С

	/**
	 * ���µ�tcp���ӳɹ�������Ĵ�����
	**/
    /* handler of accepted connection */
    ngx_connection_handler_pt   handler;

	/**
	 * Ŀǰ��Ҫ����HTTP����mail��ģ��
	 * ���ڱ��浱ǰ�����˿ڶ�Ӧ�ŵ�����������
	**/
    void               *servers;  /* array of ngx_http_in_addr_t, for example */

    ngx_log_t           log;	//��־
    ngx_log_t          *logp;	//��־ָ��

	/**
	 * ���Ϊ�µ�tcp���Ӵ����ڴ�أ����ڴ�صĳ�ʼ��СӦ��Ϊpool size
	**/
    size_t              pool_size;
    /* should be here because of the AcceptEx() preread */
    size_t              post_accept_buffer_size;
    /* should be here because of the deferred accept */
    ngx_msec_t          post_accept_timeout;	//x�����Ȼû���յ��û������ݣ�����������

	/**
	 * ǰһ��ngx_listening_t�ṹ��������ɵ�����
	**/
    ngx_listening_t    *previous;
    ngx_connection_t   *connection; //��ǰ���������Ӧ��ngx_connection_t�ṹ

    unsigned            open:1;	//1��ʾ���������Ч��0��ʾ�����ر�
    unsigned            remain:1; //Ϊ1��ʾ���ر�ԭ�ȴ򿪵ļ����˿ڣ�0��ʾ�ر������򿪵ļ����˿�
    unsigned            ignore:1; //1��ʾ�������õ�ǰngx_listening_t�ṹ�е��׽��֣�0��ʾ��������

    unsigned            bound:1;       /* already bound */
    unsigned            inherited:1;   /* inherited from previous process */
    unsigned            nonblocking_accept:1;
    unsigned            listen:1;	//1��ʾ��ǰ�ṹ���Ӧ���׽����Ѿ�����
    unsigned            nonblocking:1;
    unsigned            shared:1;    /* shared between threads or processes */
    unsigned            addr_ntop:1;	//Ϊ1��ʾ�������ַת��Ϊ�ַ�����ʽ�ĵ�ַ

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
	 * ����δʹ��ʱ��data�䵱���ӳ��п��������е�next
	 * ����ʹ��ʱ����ģ�����������httpģ�飬dataָ��ngx_http_request_t
	**/
    void               *data;
    ngx_event_t        *read;	//���Ӷ�Ӧ�Ķ��¼�
    ngx_event_t        *write;	//���Ӷ�Ӧ��д�¼�

    ngx_socket_t        fd;	//�׽��ֶ�Ӧ�ľ��

    ngx_recv_pt         recv;	//ֱ�ӽ��������ַ����ķ���
    ngx_send_pt         send;	//ֱ�ӷ��������ַ����ķ���
    ngx_recv_chain_pt   recv_chain;	//�����������������ַ������ķ���
    ngx_send_chain_pt   send_chain;	//�����������������ַ������ķ���

	/**
	 * ������Ӷ�Ӧ��ngx_listen_t��������
	 * ��������listening�����˿ڵ��¼�����
	**/
    ngx_listening_t    *listening;

    off_t               sent;	//����������ѷ��͵��ֽ���

    ngx_log_t          *log;	//��־����

	/**
	 * �ڴ��
	 * һ����acceptһ���µ�����ʱ
	 * �ᴴ��һ���ڴ��
	 * ����������ӽ���ʱ�������ڴ��
	 * �ڴ�ش�С��������listening��Ա��pool size������
	**/
    ngx_pool_t         *pool;

    struct sockaddr    *sockaddr;	//���ӿͻ��˵�sockaddr
    socklen_t           socklen;	//sockaddr�ṹ��ĳ���
    ngx_str_t           addr_text;	//���ӿͻ����ַ�����ʽ��IP��ַ


#if (NGX_SSL)
    ngx_ssl_connection_t  *ssl;
#endif

    struct sockaddr    *local_sockaddr;	//���������˿ڶ�Ӧ��sockaddr�ṹ�壬ʵ���Ͼ���listening���������sockaddr��Ա

    ngx_buf_t          *buffer;	//�û����ܡ�����ͻ��˷������ַ�����buffer���������ڴ�ط���ģ���С���ɾ���

	/**
	 * ��������ǰ������˫������Ԫ�ص���ʽ��ӵ�ngx_cycle_t���Ľṹ��
	 * ��reuseable_connection_queue˫�������У���ʾ�������õ�����
	**/
    ngx_queue_t         queue;

	/**
	 * ����ʹ�ô���
	 * ngx_connection_t�ṹ��ÿ�ν���һ�����Կͻ��˵�����
	 * �����������˷�������������
	 * number ����+1
	**/
    ngx_atomic_uint_t   number;

    ngx_uint_t          requests;	//������������

    unsigned            buffered:8;	//�����е�ҵ������

    unsigned            log_error:3;     /* ngx_connection_log_error_e */

    unsigned            single_connection:1;	//Ϊ1��ʾ���������ӣ�Ϊ0��ʾ��������������Ϊ�����������ķǶ�������
    unsigned            unexpected_eof:1;	//Ϊ1��ʾ���ڴ��ַ�������
    unsigned            timedout:1;	//Ϊ1 ��ʾ�����Ѿ�����
    unsigned            error:1;
    unsigned            destroyed:1;

    unsigned            idle:1;	//Ϊ1 ��ʾ���Ӵ��ڿ���״̬����keepalive���������м��״̬
    unsigned            reusable:1;	//Ϊ1��ʾ���ӿ����ã��������queue�ֶν��ʹ��
    unsigned            close:1;	//1��ʾ���ӹر�

    unsigned            sendfile:1;	//Ϊ1��ʾ���ڽ��ļ��е����ݷ������ӵ���һ��
	/**
	 * Ϊ1 ��ʾֻ�������׽��ֶ�Ӧ�ķ��ͻ�������������������õĴ�С��ֵ
	 * �¼�����ģ��Ż�ַ����¼�
	 * ����ngx_handle_write_event�����е�lowat�����Ƕ�Ӧ��
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
