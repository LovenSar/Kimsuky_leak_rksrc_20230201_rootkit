#ifndef _PROXY_H
#define _PROXY_H 1

#include <stdio.h>
#include <stdint.h>

#include "dynbuf.h"


#ifdef _WIN32
 #include <io.h>
 #include <winsock2.h>
 #include <Ws2tcpip.h>

 #pragma comment(lib, "ws2_32.lib")
 #define SOCKET_CLOSE closesocket
 #define IOCTL_SOCKET ioctlsocket
 #define SLEEP(x) Sleep(x)
 #define snprintf _snprintf
#else
 #include <unistd.h>
 #include <sys/socket.h>
 #include <netinet/in.h>
 #include <netinet/tcp.h>
 #include <arpa/inet.h>
 #include <netdb.h>

 #include <sys/ioctl.h>

 #define SOCKET int
 #define SOCKET_CLOSE close
 #define IOCTL_SOCKET ioctl
 #define INVALID_SOCKET (SOCKET)(~0)
 #define SOCKET_ERROR (-1)
 #define WSAEINTR EINTR
 #define SLEEP(x) usleep(x * 1000)
#endif


#define MAX_STREAM_DATA         4000


// socket type
#define CLIENT_STATE_DEFAULT                0
#define STREAM_STATE_FORWARD_START          2
#define SENDER_STATE_FORWARD_START_OK       3
#define RECEIVER_STATE_FORWARD_START_OK     5

#define SOCK_STATE_LISTENER                  31
#define SOCK_STATE_CONNECTING                32
#define SOCK_STATE_OPENING                   33
#define SOCK_STATE_OPEN                      34

#define SOCK_STATE_NEW_CLIENT                34
#define SOCK_STATE_DYNAMIC                   35
#define SOCK_STATE_RDYNAMIC_OPEN                36
#define SOCK_STATE_SSH_CHANNEL_RDYNAMIC_FINISH  37


#define SENDER_STATE_FORWARD_START          2
#define RECEIVER_STATE_FORWARD_START        4
#define CLIENT_STATE_FORWARD_DATA           6
#define CLIENT_STATE_FORWARD_END            7
#define COMMAND_SOCKET_OPEN_ERR             20
#define COMMAND_SOCKET_RECV_ERR             21
#define COMMAND_SOCKET_WRITE_ERR            24
#define COMMAND_SOCKET_CONNECT_ERR          25

#define HDR_COMMAND_CONNECT                 22
#define HDR_COMMAND_DISCONNECT

struct st_client{
    uint32_t id;
    SOCKET fd;
    //uint32_t sockType;
    uint32_t state;     //  client state
    uint32_t flags;     // socks5 state
    uint16_t s5flags;
    time_t lastTime;
    //uint32_t command;
    char    *remote_host;
    int     remote_port;
    dynbuf_t *inbuf;
    dynbuf_t *outbuf;
};
typedef struct st_client stCLIENT;

struct _stream_hdr{
    uint32_t command;
    uint32_t id;
    uint32_t len;
    char data[1024];
};
typedef struct _stream_hdr STREAM_HDR;



int init_proxy_env();

int add_proxy_client2(int id, SOCKET newsock, int sockType, char *dst_host, int dst_port);
int add_proxy_client(SOCKET newsock, int sockType, char *dst_host, int dst_port);
int close_proxy_all_client();
int close_proxy_client(uint32_t id);
int sock_is_listen(SOCKET sock);
int get_sock_sport(SOCKET client, int type);
int add_sock2fds(SOCKET _maxfd, fd_set *readfds, fd_set *writefds);
int select_event(SOCKET _maxfd, fd_set *readfds, fd_set *writefds, long timer_ms);

int set_stream_host(int sid, char *rhost, int rport);
int set_stream_state(int sid, uint32_t state);

SOCKET get_accept(SOCKET sock);
//int get_new_clinet(SOCKET socklisten);

dynbuf_t *get_streams_outbuf();

int write_data2stream(uint32_t sid, void *data, size_t len);
int write_outbuf_data(uint32_t sid, uint32_t command, void *data, size_t len);
int clear_outbuf();
int free_outbuf();


#define SOCKS_VER5    	0x05
//#define SOCKS_PORT    1080

#define SOCKS5_AUTHDONE 0x1000
#define SOCKS5_NOAUTH   0x00
#define SOCKS5_IPV4     0x01
#define SOCKS5_DOMAIN   0x03
#define SOCKS5_IPV6     0x04
#define SOCKS5_CONNECT  0x01
#define SOCKS5_SUCCESS  0x00

#define _FORWARD_OPEN 0x2000


struct _ipv4_addr
{
    struct in_addr addr;
    uint16_t port;
} __attribute__ ((packed));

struct _ipv6_addr
{
    struct in6_addr addr;
    uint16_t port;
} __attribute__ ((packed));


#endif
