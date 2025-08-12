#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "proxy.h"


#ifndef MAX
#define MAX(p, q) (((p) >= (q)) ? (p) : (q))
#endif


dynbuf_t *gOutBuf = NULL;

int client_index = 0;
static stCLIENT proxy_clients[500] = {0};


int non_blocking(SOCKET sock)
{
	int ret;
	unsigned long imode = 1;
	
    #ifdef _WIN32
        ret = ioctlsocket(sock, FIONBIO, &imode);
    #else
        ret = ioctl(sock, FIONBIO, &imode);     // set non-blocking mode
    #endif
	
	return 1;
}

int blocking(SOCKET sock)
{
	int ret;
	unsigned long imode = 0;
	
    #ifdef _WIN32
        ret = ioctlsocket(sock, FIONBIO, &imode);
    #else
        ret = ioctl(sock, FIONBIO, &imode);     // set blocking mode
    #endif

	return 1;
}

static inline void tcp_solinger(int sockfd, unsigned int time_s) {
	
    struct linger stLinger;
    stLinger.l_onoff = 1;
    stLinger.l_linger = time_s; // X s
	
    // 延迟关闭. 时间是 stLinger 中第二个参数的值
    if (setsockopt(sockfd, SOL_SOCKET, SO_LINGER, (const char *)&stLinger, sizeof(struct linger)) < 0) {
        ///printf("[set_tcp_solinger0] setsockopt(%d, SO_LINGER): %s", sockfd, strerror(errno));
    }
}

int close_proxy_client(uint32_t id)
{
    int index;
    for (index = 0; index < 500; index++)
    {
        if (proxy_clients[index].id == id)
        {
			tcp_solinger(proxy_clients[index].fd, 0);
			
            SOCKET_CLOSE(proxy_clients[index].fd);
            proxy_clients[index].fd = 0;

            proxy_clients[index].id = 0;
            //proxy_clients[index].sockType = 0;
            proxy_clients[index].state = 0;
            proxy_clients[index].lastTime = 0;
            //proxy_clients[index].command = 0;
			proxy_clients[index].s5flags = 0;

            if (proxy_clients[index].remote_host != NULL)
            {
                free(proxy_clients[index].remote_host);

                proxy_clients[index].remote_host = NULL;
            }

            proxy_clients[index].remote_port = 0;


            if (proxy_clients[index].inbuf != NULL)
            {
                dynbuf_free(proxy_clients[index].inbuf);

                proxy_clients[index].inbuf = NULL;
            }

            if (proxy_clients[index].outbuf != NULL)
            {
                dynbuf_free(proxy_clients[index].outbuf);

                proxy_clients[index].outbuf = NULL;
            }


            break;
        }
    }

    return 0;
}

int close_proxy_all_client()
{
    int index;
    for (index = 0; index < 500; index++)
    {
        if (proxy_clients[index].fd > 0)
        {
            tcp_solinger(proxy_clients[index].fd, 0);
			
            SOCKET_CLOSE(proxy_clients[index].fd);
            proxy_clients[index].fd = 0;

            proxy_clients[index].id = 0;
            //proxy_clients[index].sockType = 0;
            proxy_clients[index].state = 0;
            proxy_clients[index].lastTime = 0;
            //proxy_clients[index].command = 0;
			proxy_clients[index].s5flags = 0;

            if (proxy_clients[index].remote_host != NULL)
            {
                free(proxy_clients[index].remote_host);

                proxy_clients[index].remote_host = NULL;
            }

            proxy_clients[index].remote_port = 0;


            if (proxy_clients[index].inbuf != NULL)
            {
                dynbuf_free(proxy_clients[index].inbuf);

                proxy_clients[index].inbuf = NULL;
            }

            if (proxy_clients[index].outbuf != NULL)
            {
                dynbuf_free(proxy_clients[index].outbuf);

                proxy_clients[index].outbuf = NULL;
            }

        }
    }

    return 0;
}

int reset_client(int index)
{
    if (index != -1)
    {
        memset(proxy_clients, 0, 500 * sizeof(stCLIENT));
    }
    else
    {
        memset(&proxy_clients[index], 0, sizeof(stCLIENT));
    }

    return 0;
}

int set_stream_state(int sid, uint32_t state)
{
    int index;
    for (index = 0; index < 500; index++)
    {
        if (proxy_clients[index].id == sid)
        {
            proxy_clients[index].state = state;

            break;
        }
    }

    return 0;
}


int sock_is_read(SOCKET sock_id, int time_out)
{
    fd_set readfds;
    struct timeval timeout;
    int ret;

    FD_ZERO(&readfds);
    FD_SET(sock_id, &readfds);

    if (time_out == -1)
    {

        while (1)
        {
            timeout.tv_sec = 60 * 60;
            timeout.tv_usec = 0;

            ret = select(sock_id + 1, &readfds, NULL, NULL, &timeout);
            if (ret < 0)
            {
#ifdef __GNUC__
                if (errno == EINTR)
                    continue;
#endif

#ifdef _WIN32
                DWORD err = WSAGetLastError();
                if (err == WSAEINPROGRESS)
                {
                    continue;
                }
                else
                {
                    return -1;
                }
#endif
                return -2;
            }

            if (ret == 0)
            {
                //debug(" recv time out ...\n");
                return -1;
            }

            if (FD_ISSET(sock_id, &readfds))
            {
                return 1;
            }
        }
    }
    else
    {
        timeout.tv_sec = time_out / 1000;
        timeout.tv_usec = (time_out % 1000) * 1000;

        ret = select(sock_id + 1, &readfds, NULL, NULL, &timeout);
        if (ret < 0)
        {
#ifdef __GNUC__
            if (errno == EINTR)
                return 0; //continue;
#endif

#ifdef _WIN32
            DWORD err = WSAGetLastError();
            if (err == WSAEINPROGRESS)
            {
                return 0;
            }
            else
            {
                return -1;
            }
#endif
            return -2;
        }

        if (ret == 0)
        {
            //debug(" recv time out ...\n");
            return -1;
        }

        if (FD_ISSET(sock_id, &readfds))
        {
            return 1;
        }
    }

    return 0;
}

int sock_is_write(SOCKET sock_id, int time_out)
{
    fd_set writefds;
    struct timeval timeout;
    int ret;

    FD_ZERO(&writefds);
    FD_SET(sock_id, &writefds);

    if (time_out == -1)
    {
        while (1)
        {
            timeout.tv_sec = 60 * 60;
            timeout.tv_usec = 0;

            ret = select(sock_id + 1, NULL, &writefds, NULL, &timeout);
            if (ret < 0)
            {
#ifdef __GNUC__
                if (errno == EINTR)
                    continue;
#endif

#ifdef _WIN32
                DWORD err = WSAGetLastError();
                if (err == WSAEINPROGRESS)
                {
                    continue;
                }
                else
                {
                    return -1;
                }
#endif
                return -2;
            }

            if (ret == 0)
            {
                //debug(" write time out ...\n");
                return -1;
            }

            if (FD_ISSET(sock_id, &writefds))
            {
                return 1;
            }
        }
    }
    else
    {
        timeout.tv_sec = time_out / 1000;
        timeout.tv_usec = (time_out % 1000) * 1000;

        ret = select(sock_id + 1, NULL, &writefds, NULL, &timeout);
        if (ret < 0)
        {
#ifdef __GNUC__
            if (errno == EINTR)
                return 0; //continue;
#endif

#ifdef _WIN32
            DWORD err = WSAGetLastError();
            if (err == WSAEINPROGRESS)
            {
                return 0;
            }
            else
            {
                return -1;
            }
#endif
            return -2;
        }

        if (ret == 0)
        {
            //debug(" write time out ...\n");
            return -1;
        }

        // if (ret > 0)
        // {
        //     return 1;
        // }

        if (FD_ISSET(sock_id, &writefds))
        {
            return 1;
        }
    }

    return 0;
}

// nonblock
SOCKET get_accept(SOCKET sock)
{
    int ret = 0;

    if (sock <= 0)
    {
        return -1;
    }
    /*
    non_blocking(sock);
    */
    struct sockaddr_in client_addr;
    int client_addr_len = sizeof(client_addr);
    SOCKET new_sock = accept(sock, (struct sockaddr *)&client_addr, &client_addr_len);
    /*
    blocking(sock);
    */
    if (new_sock < 0)
    {
        return -1;
    }

    blocking(new_sock);

    // off nagle
    int enable = 1;
    setsockopt(new_sock, IPPROTO_TCP, TCP_NODELAY, (char *)&enable, sizeof(enable));

    return new_sock;
}

int sock_is_listen(SOCKET sock)
{
    int index;
    for (index = 0; index < 500; index++)
    {
        if (proxy_clients[index].fd == sock)
        {

            if (proxy_clients[index].state == SOCK_STATE_LISTENER)
            {
                //proxy_clients[index].sockType = sockType;
                return 1;

            }
        }

    }

    return 0;
}

int sock_is_connect()
{
    return 0;

}


int set_stream_dst_host(stCLIENT *client, char *host, int port)
{
	if(host != NULL)
	{
    // socks5 host/port is NULL
    client->remote_port = port;

    client->remote_host = strdup(host);
	}

    return 0;
}

int get_sock_sport(SOCKET client, int type)
{
    struct sockaddr_storage addr;
    int sport = 0;

    memset(&addr, 0, sizeof(addr));

    int addrlen = sizeof(struct sockaddr_storage);


    if (type == 1)  // local sock
    {
        if (getsockname(client, (struct sockaddr *)&addr, &addrlen) != 0)
            return -1;
    }
    else if (type == 2) // remote sock
    {
        if (getpeername(client, (struct sockaddr *)&addr, &addrlen) != 0)
        {
            //SOCKET_CLOSE(client);

            return -1;
        }
    }


    if (addr.ss_family == AF_INET)
    {
        sport = ntohs(((struct sockaddr_in *)&addr)->sin_port);
    }
    else if (addr.ss_family == AF_INET6)
    {
        sport = ntohs(((struct sockaddr_in6 *)&addr)->sin6_port);
    }


    return sport;
}

int get_new_clinet(stCLIENT *client)
{
    SOCKET newSock = 0;

    int id = client->id;
    SOCKET socklisten = client->fd;
    char *_rhost = client->remote_host;
    int _rport = client->remote_port;


    newSock = get_accept(socklisten);
    if (newSock > 0)
    {
        add_proxy_client(newSock, SOCK_STATE_NEW_CLIENT, _rhost, _rport);

        return 1;
    }

    return -1;
}

int _dbuf_size(dynbuf_t *_dynbuf)
{
    unsigned int _len = 0;

    if (_dynbuf != NULL)
    {
        _len = dynbuf_len(_dynbuf);
        if (_len > 0)
        {
            return _len;
        }
    }
    return 0;
}

int _have_data(dynbuf_t *_dynbuf)
{
    unsigned int _len = 0;

    if (_dynbuf != NULL)
    {
        _len = dynbuf_len(_dynbuf);
        if (_len > 0)
        {
            return 1;
        }
    }
    return 0;
}

int gOutBuf_size()
{
    dynbuf_t *outbuf = NULL;
    int buflen = 0;

    outbuf = get_streams_outbuf();
    if (outbuf != NULL)
    {
        if ((buflen = dynbuf_len(outbuf)) > 0)
        {
            return buflen;
        }
    }

    return 0;
}

int add_sock2fds(SOCKET _maxfd, fd_set *readfds, fd_set *writefds)
{
    int maxfd = -1;

    maxfd = _maxfd;

    int index;
    for (index = 0; index < 500; index++)
    {
        int id = proxy_clients[index].id;
        SOCKET sockfd = proxy_clients[index].fd;
        uint32_t *state = &proxy_clients[index].state;
        dynbuf_t *inbuf = proxy_clients[index].inbuf;
		dynbuf_t *outbuf = proxy_clients[index].outbuf;

        if (sockfd > 0)
        {
            // SENDER
            if (*state == SOCK_STATE_LISTENER)
            {
                FD_SET(sockfd, readfds);
            }

            if (*state == SOCK_STATE_NEW_CLIENT)
            {
                FD_SET(sockfd, readfds);
            }

            if (*state == SENDER_STATE_FORWARD_START_OK /*&& _dbuf_size(outbuf) < 1024*/)
            {
                FD_SET(sockfd, readfds);
            }

            // hava data, add fd to writefds
            if (_have_data(outbuf) == 1 && *state == SENDER_STATE_FORWARD_START_OK)
            {
                FD_SET(sockfd, writefds);
            }


            // RECEIVER
            if (*state == SOCK_STATE_CONNECTING)
            {
                FD_SET(sockfd, writefds);
            }

            if (*state == RECEIVER_STATE_FORWARD_START_OK && gOutBuf_size() < 8000)
            {
                FD_SET(sockfd, readfds);
            }
            if (_have_data(outbuf) == 1 && *state == RECEIVER_STATE_FORWARD_START_OK)
            {
                FD_SET(sockfd, writefds);
            }

            if (maxfd != -1 && maxfd < sockfd)
            {
                maxfd = sockfd;
            }
        }

    }

    return maxfd;
}


int select_event(SOCKET _maxfd, fd_set *readfds, fd_set *writefds, long timer_ms)
{
    int ready;
    int maxfd = -1;

    struct timeval timeout;

    timeout.tv_sec = (long) (timer_ms / 1000);
    timeout.tv_usec = (long) ((timer_ms % 1000) * 1000);

    ready = select(_maxfd + 1, readfds, writefds, NULL, &timeout);
    if (ready == -1)
    {
        return -1;
    }

    // timeout
    if (ready == 0)
    {
        return 0;
    }

    int index;
    for (index = 0; index < 500; index++)
    {
        int id = proxy_clients[index].id;
        SOCKET sockfd = proxy_clients[index].fd;
        uint32_t *state = &proxy_clients[index].state;

        if (sockfd > 0)
        {
            if (FD_ISSET(sockfd, writefds))
            {
                streams_write(NULL, &proxy_clients[index]);
            }

            if (FD_ISSET(sockfd, readfds))
            {
                streams_read(NULL, &proxy_clients[index]);
            }
        }
    }

    return ready;
}

int write_outbuf(stCLIENT *client)
{
	SOCKET sockfd = client->fd;
	
	unsigned int buf_len = 0;
	do
	{
		//read outbuf, send data
		buf_len = dynbuf_len(client->outbuf);
		if (buf_len >= 1024)
		{
			buf_len = 1024;
		}
    
		void *data = (void *)dynbuf_dataptr(client->outbuf);
		if (data != NULL)
		{
			// write data -> remote sock
			send(sockfd, (char *)data, buf_len, 0);
    
			dynbuf_consume(client->outbuf, buf_len);
		}
    
	}while(buf_len != 0);
	
	return -1;
}


#if !defined(MSG_NOSIGNAL)
#define MSG_NOSIGNAL 0
#endif

int streams_read(void *host, stCLIENT *client)
{
    int id = client->id;
    SOCKET sockfd = client->fd;
    uint32_t *state = &(client->state);
    char *_rhost = client->remote_host;
    int _rport = client->remote_port;
    dynbuf_t *inbuf = client->inbuf;
    dynbuf_t *outbuf = client->outbuf;

    if (*state == SOCK_STATE_LISTENER)
    {
        // listen sock
        get_new_clinet(client);
    }


    if (*state == SENDER_STATE_FORWARD_START_OK || *state == SOCK_STATE_NEW_CLIENT)
    {
        //  sockfd block
        if (sock_is_read(sockfd, 0) == 1)
        {
            char buf[1024] = {0};
            int len = recv(sockfd, buf, 1024, 0);
            if (len <= 0)
            {
               /// printf("[-] SENDER sock recv error \r\n");
    
                write_outbuf_data(id, COMMAND_SOCKET_RECV_ERR, NULL, 0);
    
                // read error, close
                close_proxy_client(id);
            }
    
            if (len > 0)
            {
                dynbuf_append(inbuf, buf, len);
            }
			
            if (len > 0)
            {
                // 1. sender, new sock have data, start forward
                //if(*state == SOCK_STATE_NEW_CLIENT)
                if (!(client->s5flags & _FORWARD_OPEN))
                {
                    int _len = dynbuf_len(inbuf);
                    if (_len >= 3)
                    {
                        const unsigned char *ptr = (unsigned char *)dynbuf_dataptr(inbuf);
                        // socks5
                        if (ptr[0] == 0x05)
                        {
                            int ret = decode_socks5(client, client->inbuf, client->outbuf);
                            if(ret == 1)
                            {
                                // send dst addr,port. addr 255 max len
                                char rhost[512] = {0};
                                snprintf(rhost, sizeof(rhost), "%s:%d", client->remote_host, client->remote_port);
            
                                // printf("[-] 1.STREAM_STATE_FORWARD_START %d \r\n", id);
                                client->state = STREAM_STATE_FORWARD_START;
            
                                write_outbuf_data(id, STREAM_STATE_FORWARD_START, rhost, sizeof(rhost));
                            }
                        }
            
                        write_outbuf(client);
                    }
                }
                else
                {
                    // 2. sender, start forward yes, send data
                    unsigned int inbuf_len = 0;
                    //read inbuf, send data
                    while ((inbuf_len = dynbuf_len(inbuf)) > 0)
                    {
                        if (inbuf_len >= 1024)
                        {
                            inbuf_len = 1024;
                        }
            
                        void *data = (void *)dynbuf_dataptr(inbuf);
                        if (data != NULL)
                        {
                            write_outbuf_data(id, CLIENT_STATE_FORWARD_DATA, data, inbuf_len);
            
                            dynbuf_consume(inbuf, inbuf_len);
                        }
                    }
                }
            }
        }
    
    }


    // 2. receiver, read client data, send
    if (*state == RECEIVER_STATE_FORWARD_START_OK)
    {
        // sockfd nonblock
        //if (sock_is_read(sockfd, 0) == 1)
        {
            char buf[1024] = {0};
            int len = recv(sockfd, buf, 1024, 0);
            //if (len == -1 && (errno == EINTR || (errno == EAGAIN || errno == EWOULDBLOCK)))
            //  return 1;

            if (len <= 0)
            {
                //printf("[-] RECEIVER sock recv error \r\n");

                // read error
                write_outbuf_data(id, COMMAND_SOCKET_RECV_ERR, NULL, 0);

                // read remote error
                close_proxy_client(id);
            }
            else
            {
                //printf("[-] 2.CLIENT_STATE_FORWARD_DATA %d \r\n", id);

                write_outbuf_data(id, CLIENT_STATE_FORWARD_DATA, buf, len);
            }
        }

    }


    return 1;
}

int streams_write(void *host, stCLIENT *client)
{
    // 1. read inbuf
    // 2. write dat to client
    unsigned int o_len = 0;

    int id = client->id;
    SOCKET sockfd = client->fd;
    int state = client->state;
    dynbuf_t *inbuf = client->inbuf;
    dynbuf_t *outbuf = client->outbuf;

    // 1. receiver, check status ,connect ok ?
    if (state == SOCK_STATE_CONNECTING)
    {
        {
            int flags;
            int error = -1;
            int slen = sizeof(error);
            getsockopt(sockfd, SOL_SOCKET, SO_ERROR, (char *)&error, &slen);
            if (error == 0) // error = 0 connect true
            {
                unsigned long imode = 0;
                IOCTL_SOCKET(client->fd, FIONBIO, &imode); //set blocking mode

                // off nagle
                int enable = 1;
                setsockopt(client->fd, IPPROTO_TCP, TCP_NODELAY, (char *)&enable, sizeof(enable));

                struct linger stLinger;
                stLinger.l_onoff = 1;
                stLinger.l_linger = 5;
                //延迟关闭时间. close 时,保证发送完,再关闭.
                flags = setsockopt(client->fd, SOL_SOCKET, SO_LINGER, (char *)&stLinger, sizeof(struct linger));
                if (flags == -1)
                {
                    //SOCKET_CLOSE(sockfd);
                }
                else
                {
                    // printf("[-] 1.RECEIVER_STATE_FORWARD_START_OK %d \r\n", id);
                    client->state = RECEIVER_STATE_FORWARD_START_OK;

                    write_outbuf_data(id, RECEIVER_STATE_FORWARD_START_OK, NULL, 0);
                }
            }
            else
            {
                // open error
                write_outbuf_data(id, COMMAND_SOCKET_OPEN_ERR, NULL, 0);
				
                close_proxy_client(id);
            }
        }

    }


    //if (state == SENDER_STATE_FORWARD_START_OK || state == RECEIVER_STATE_FORWARD_START_OK)
    {
        // write data to stream
        if (outbuf != NULL)
        {
            o_len = dynbuf_len(outbuf);
            if (o_len > 0)
            {
                //if (sock_is_write(sockfd, 0) == 1)
                {
                    void *data = (void *)dynbuf_dataptr(outbuf);
                    if (data != NULL)
                    {
                        // write data -> remote sock
                        send(sockfd, (char *)data, o_len, 0);

                        dynbuf_consume(outbuf, o_len);
                    }
                }
            }
        }
    }

    return 1;
}

int write_data2stream(uint32_t sid, void *data, size_t len)
{
    int index;
    for (index = 0; index < 500; index++)
    {
        if (proxy_clients[index].id == sid)
        {
            dynbuf_append(proxy_clients[index].outbuf, data, len);

            return 1;
        }
    }

    return 0;
}

int add_proxy_client(SOCKET newsock, int sockType, char *dst_host, int dst_port)
{
    uint32_t newid = 0;

    if (sockType == SOCK_STATE_LISTENER)
    {
        newid = get_sock_sport(newsock, 1);
    }
    else
    {
        newid = get_sock_sport(newsock, 2);
    }

    int index;
    for (index = 0; index < 500; index++)
    {
        if (proxy_clients[index].id == 0) // add new sock
        {
            proxy_clients[index].id = newid;
            proxy_clients[index].fd = newsock;

            if (sockType == SOCK_STATE_LISTENER)
            {
                proxy_clients[index].state = sockType;

                //proxy_clients[index].lastTime = 0;
                //proxy_clients[index].command = 0;
				
                proxy_clients[index].remote_host = NULL;
                proxy_clients[index].remote_port = 0;
                set_stream_dst_host(&proxy_clients[index], dst_host, dst_port);

                proxy_clients[index].inbuf = dynbuf_new();
                proxy_clients[index].outbuf = dynbuf_new();
            }
            else
            {
                // SOCK_STATE_NEW_CLIENT
                proxy_clients[index].state = sockType;

                //proxy_clients[index].lastTime = 0;
                //proxy_clients[index].command = 0;
                
                proxy_clients[index].remote_host = NULL;
                proxy_clients[index].remote_port = 0;
                set_stream_dst_host(&proxy_clients[index], dst_host, dst_port);

                proxy_clients[index].inbuf = dynbuf_new();
                proxy_clients[index].outbuf = dynbuf_new();

            }

            break;
        }

        if (index >= 500)
        {
            SOCKET_CLOSE(newsock);

            return -1;
        }
    }

    return 1;
}

int add_proxy_client2(int id, SOCKET newsock, int sockType, char *dst_host, int dst_port)
{
    int index;
    for (index = 0; index < 500; index++)
    {
        if (proxy_clients[index].id == 0) // add new sock
        {
            proxy_clients[index].id = id;
            proxy_clients[index].fd = newsock;

            if (sockType == SOCK_STATE_LISTENER)
            {
                proxy_clients[index].state = sockType;

                //proxy_clients[index].lastTime = 0;

                //proxy_clients[index].command = 0;
                
                proxy_clients[index].remote_host = NULL;
                proxy_clients[index].remote_port = 0;
                set_stream_dst_host(&proxy_clients[index], dst_host, dst_port);

                proxy_clients[index].inbuf = dynbuf_new();
                proxy_clients[index].outbuf = dynbuf_new();
            }
            else
            {
                // SOCK_STATE_NEW_CLIENT or etc..
                proxy_clients[index].state = sockType;

                //proxy_clients[index].lastTime = 0;

                //proxy_clients[index].command = 0;
                
                proxy_clients[index].remote_host = NULL;
                proxy_clients[index].remote_port = 0;
                set_stream_dst_host(&proxy_clients[index], dst_host, dst_port);

                proxy_clients[index].inbuf = dynbuf_new();
                proxy_clients[index].outbuf = dynbuf_new();
            }

            break;
        }

        if (index >= 500)
        {
            SOCKET_CLOSE(newsock);

            return -1;
        }
    }

    return 1;
}


int init_proxy_env()
{
    gOutBuf = dynbuf_new();

    return 0;
}

int clear_outbuf()
{
    if (gOutBuf != NULL)
    {
        dynbuf_clear(gOutBuf);
    }    

    return 0;
}

int free_outbuf()
{
    if (gOutBuf != NULL)
    {
    dynbuf_free(gOutBuf);
    }

    gOutBuf = NULL;

    return 0;
}

dynbuf_t *get_streams_outbuf()
{
    if(dynbuf_len(gOutBuf) > 0)
    {
        return gOutBuf;
    }

    return NULL;
}

int write_outbuf_data(uint32_t sid, uint32_t command, void *data, size_t len)
{
    uint32_t buflen = 0;

    STREAM_HDR o_stream_hdr = {0};
    o_stream_hdr.command = command;
    o_stream_hdr.id = sid;

    if (data == NULL && len == 0)
    {
        o_stream_hdr.len = 0;

        buflen = sizeof(STREAM_HDR);

        dynbuf_append(gOutBuf, &o_stream_hdr, buflen);

        return buflen;
    }
    else
    {
        o_stream_hdr.len = len;

        memcpy(o_stream_hdr.data, data, len);

        buflen = sizeof(STREAM_HDR);

        dynbuf_append(gOutBuf, &o_stream_hdr, buflen);

        return buflen;
    }

    return -1;
}


#ifndef INET6_ADDRSTRLEN    /* for non IPv6 machines */
#define INET6_ADDRSTRLEN 46
#endif

int decode_socks5(stCLIENT *client, dynbuf_t *_input, dynbuf_t *_output)
{
    struct
    {
        uint8_t version;
        uint8_t command;
        uint8_t reserved;
        uint8_t atyp;
    } __attribute__ ((packed)) s5_req, s5_rsp;

    int id = client->id;
    SOCKET sockfd = client->fd;
    uint32_t *state = &(client->state);
    dynbuf_t *inbuf = client->inbuf;
    dynbuf_t *outbuf = client->outbuf;

    /*
    1. client --> socks5 server
    +----+----------+----------+
    |VER | NMETHODS | METHODS  |
    +----+----------+----------+
    | 1  |    1     | 1 to 255 |
    +----+----------+----------+

    1.1 server response:
    +----+--------+
    |VER | METHOD |
    +----+--------+
    | 1  |   1    |
    +----+--------+
    */
    uint32_t af = 0;
    uint32_t addrlen = 0;
    uint16_t dest_port = 0;
    char dest_addr[255 + 1], ntop[INET6_ADDRSTRLEN];
    const unsigned char *ptr = NULL;
    uint32_t have, need, i, found, nmethods;

    ptr = (unsigned char *)dynbuf_dataptr(inbuf);
    if (ptr[0] != 0x05)
	{
        return -1;
	}
    
    have = dynbuf_len(inbuf);

    // 1. check socks5 hdr: ver | nmethods | methods
    if (!(client->s5flags & SOCKS5_AUTHDONE))
    {
        if (have < 2)
            return 0;

        nmethods = ptr[1];
        if (have < nmethods + 2)
            return 0;
    
        // look for method: "NO AUTHENTICATION REQUIRED"
        for (found = 0, i = 2; i < nmethods + 2; i++)
        {
            if (ptr[i] == SOCKS5_NOAUTH)
            {
                found = 1;
                break;
            }
        }

        if (!found)
        {
            ///printf(" %d: method SOCKS5_NOAUTH not found \n", client->id);
            return -1;
        }

        dynbuf_consume(inbuf, nmethods + 2);

        // version, method
		uint8_t _resp[2] = {0x00};
		_resp[0] = 0x05;
		_resp[1] = SOCKS5_NOAUTH;
        dynbuf_append(outbuf, _resp, sizeof(_resp));
   
    
        client->s5flags |= SOCKS5_AUTHDONE;
		
        /// printf(" %d: socks5 auth done \n", client->id);
		
        return 0;               // need more
    }
    
   /// printf(" %d: socks5 post auth \n", client->id);

/*
    2. client request dst addr
    +----+-----+-------+------+----------+----------+
    |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    +----+-----+-------+------+----------+----------+
    | 1  |  1  | X'00' |  1   | Variable |    2     |
    +----+-----+-------+------+----------+----------+

    2.1 server response --> client
    +----+-----+-------+------+----------+----------+
    |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    +----+-----+-------+------+----------+----------+
    | 1  |  1  | X'00' |  1   | Variable |    2     |
    +----+-----+-------+------+----------+----------+
 */
    {
        if (have < sizeof(s5_req) + 1)
            return 0;           // need more

        // 2. get dst addr,port
        memcpy(&s5_req, ptr, sizeof(s5_req));
    
        if (s5_req.version != 0x05 ||
                s5_req.command != SOCKS5_CONNECT ||
                s5_req.reserved != 0x00)
        {
            //printf(" %d: only socks5 connect supported \n", client->id);
            return -1;
        }
		
        switch (s5_req.atyp)
        {
        case SOCKS5_IPV4:
            addrlen = 4;
            af = AF_INET;
            break;

        case SOCKS5_DOMAIN:
            addrlen = ptr[sizeof(s5_req)];
            af = -1;
            break;

        case SOCKS5_IPV6:
            addrlen = 16;
            af = AF_INET6;
            break;

        default:
            //printf(" %d: bad socks5 atyp %d \n", client->id, s5_req.atyp);
            return -1;
        }

        need = sizeof(s5_req) + addrlen + 2;

        if (s5_req.atyp == SOCKS5_DOMAIN)
            need++;

        // cmp DOMAIN len
        if (have < need)
            return 0;
    
        dynbuf_consume(inbuf, sizeof(s5_req));
    
        if (s5_req.atyp == SOCKS5_DOMAIN)
        {
            // delete domain length
            dynbuf_consume(inbuf, 1);
        }

        // get dst addr,port
        memcpy(dest_addr, ptr, addrlen);
        memcpy(&dest_port, ptr + addrlen, 2);
        {
            /// printf(" %d: parse addr/port \n", client->id);
            ///return -1;
        }
        dest_addr[addrlen] = '\0';
		
		dynbuf_consume(inbuf, addrlen + 2);
    
        //free(client->remote_host);
        //client->remote_host = NULL;
    
        if (s5_req.atyp == SOCKS5_DOMAIN)
        {
            if (addrlen >= NI_MAXHOST)
            {
                //printf(" %d: socks5 hostname \"%.100s\" too long \n", client->id, dest_addr);
                return -1;
            }
            client->remote_host = strdup(dest_addr);
        }
        else
        {
            if (inet_ntop(af, dest_addr, ntop, sizeof(ntop)) == NULL)
                return -1;
    
            client->remote_host = strdup(ntop);
        }
        client->remote_port = ntohs(dest_port);
    
       /// printf(" %d: socks5 host %s port %u cmd %u \n",
       ///        client->id, client->remote_host, client->remote_port, s5_req.command);


        s5_rsp.version = 0x05;
        s5_rsp.command = SOCKS5_SUCCESS;
        s5_rsp.reserved = 0;
        s5_rsp.atyp = SOCKS5_IPV4;
        dest_port = 0;
    
        //inet_pton(AF_INET6, ipv6_addr, from_addr.sin6_addr.s6_addr);
    
        // ip/port
        struct _ipv4_addr loc_ipv4;
        loc_ipv4.addr.s_addr = htonl(INADDR_ANY);
        loc_ipv4.port = 0;

        dynbuf_append(outbuf, &s5_rsp, sizeof(s5_rsp));
        dynbuf_append(outbuf, &loc_ipv4, sizeof(loc_ipv4));
		
        client->s5flags |= _FORWARD_OPEN;
       
       return 1;
    }

    return -1;
}

