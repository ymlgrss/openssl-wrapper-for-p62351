#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#define TLS_ERROR_NONE          0
#define TLS_ERROR_ZERO_RETURN   1
#define TLS_ERROR_WANT_READ     2
#define TLS_ERROR_WANT_WRITE    3
#define TLS_ERROR_OTHER         4

#include <WinSock2.h>
#include <Ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "p62351.h"

#pragma comment(lib, "Ws2_32.lib")

#define PORT 8000
#define HOST "127.0.0.1"

#define CHK_NULL(x) if ((x)==NULL) exit (-1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); getchar(); exit(-2); }

typedef struct QNode
{
	struct QNode *prior;
	struct QNode *next;
	p62351_tls_t *tls;
}node;

typedef struct Queue
{
	node *front;
	node *rear;
}queue;

queue *rd_queue;
queue *wt_queue;

static int rd_flag = 1;
static int wt_flag = 1;

void queue_init(queue *q)
{
	q->rear = NULL;
	q->front = q->rear;
}

void clean_queue(queue *q)
{
	node *n = q->front;
	while (n)
	{
		q->front = n->next;
		free(n);
		n = q->front;
	}
	q->rear = q->front;
}

void enqueue(queue* q, node *n)
{

	if (q->rear == NULL)
	{
		q->rear = n;
		q->front = q->rear;
	}
	else
	{
		q->rear->next = n;
		n->prior = q->rear;
		q->rear = n;
	}
}

int *dequeue(queue *q, node *n)
{
	if (q->front == NULL)
	{
		printf("队列已为空\n");
		return -1;
	}
	else
	{
		n = q->front;
		q->front = n->next;
		if (q->front == NULL)
		{
			q->rear = NULL;
		}
		free(n);
		return 0;
	}
}

void delnode(queue *q, node *n)
{
	if (n->prior)
		n->prior->next = n->next;
	else
		q->front = n->next;
	if (n->next)
		n->next->prior = n->prior;
	else
		q->rear = n->prior;
}

BOOL is_empty(queue* q)
{
	if (q->front || q->rear)
		return FALSE;
	else
		return TRUE;
}

static int read_queue(queue *q, char *buf, int len)
{
	int ret, err;
	int status = 0;
	node *n = q->front;

	while (n)
	{
		ret = p62351_tls_read(n->tls, buf, len, &err);
		if (ret > 0 && err == TLS_ERROR_NONE)
		{
			buf[ret] = 0; 
			if (strcmp(buf, "Hello server!") == 0)
			{
				enqueue(wt_queue, n);
				delnode(q, n);
			}

			status = 1;
			break;
		}
		else if (err == TLS_ERROR_WANT_READ || err == TLS_ERROR_WANT_WRITE || err == TLS_ERROR_ZERO_RETURN)
		{
			n = n->next;
			continue;
		}
		else
		{
			perror("tls error");
			status = 0;
			break;
		}
	}

	if (is_empty(q))
	{
		rd_flag = 1;
	}
	else
	{
		rd_flag = 0;
	}

	return status;
}

static int write_queue(queue *q, char *buf, int len)
{
	int ret, err;
	int status = 0;
	node *n = q->front;

	while (n)
	{
		ret = p62351_tls_write(n->tls, buf, len, &err);
		if (ret > 0 && err == TLS_ERROR_NONE)
		{
			printf("finished writing...\n");
			delnode(q, n);
			p62351_tls_free(n->tls);
			free(n);
			status = 1;
			break;
		}
		else if (err == TLS_ERROR_WANT_READ || err == TLS_ERROR_WANT_WRITE || err == TLS_ERROR_ZERO_RETURN)
		{
			n = n->next;
			continue;
		}
		else
		{
			perror("tls error");
			status = 0;
			break;
		}
	}

	if (is_empty(q))
	{
		wt_flag = 1;
	}
	else
	{
		wt_flag = 0;
	}

	return status;
}

void WSA_init()
{
	/* ------------------初始化WSA-------------------------------- */

	WORD socketVersion = MAKEWORD(2, 2);
	WSADATA data;
	if (WSAStartup(socketVersion, &data) != 0)
	{
		getchar();
		exit(1);
	}
	else
	{
		printf("wVersion: %d.%d\n", LOBYTE(data.wVersion), HIBYTE(data.wVersion));
		printf("wHighVersion: %d.%d\n", LOBYTE(data.wHighVersion), HIBYTE(data.wHighVersion));
		printf("szDescription: %s\n", data.szDescription);
		printf("szSystemStatus: %s\n", data.szSystemStatus);
	}
}

void set_nonblocking(int sock, u_long mode) {
	if (ioctlsocket(sock, FIONBIO, &mode) == -1) {
		printf("set non-blocking error!");
		getchar();
		exit(-1);
	}
}

void main()
{
	int err, ret;
	int s_server;
	struct sockaddr_in sa_server;
	u_long mode = 1;
	fd_set fds, newfds;
	rd_queue = (queue *)malloc(sizeof(queue));
	wt_queue = (queue *)malloc(sizeof(queue));
	p62351_tls_ctx_t *ctx;

	WSA_init();
	queue_init(rd_queue);
	queue_init(wt_queue);

	p62351_tls_ctx_config_t config = {      //TLS上下文对象配置信息 
		128000,        /* 自动重协商的字节数 */
		600,           /* 自动重协商的时间周期 */
		"ca.pem",      /* CA 根证书文件的路径 */
		"server.pfx",  /* 本端证书文件的路径 */
		"111111",      /* 本端证书文件的保护口令 */
		NULL,          /* CRL 文件路径  */
		12 * 3600,     /* CRL 文件自动更新周期 */
		600,		   /* 握手超时 */
	};

	ctx = p62351_tls_ctx_new(&config);
	if (!ctx)
	{
		fprintf(stderr, "p62351_tls_ctx_new() failed: %s\n", p62351_get_last_error_string());
		exit(1);
	}
	/* ------------------创建服务器TCP链接-------------------------- */

	s_server = socket(AF_INET, SOCK_STREAM, 0);									
	CHK_ERR(s_server, "socket");

	memset(&sa_server, 0, sizeof(sa_server));
	sa_server.sin_family = AF_INET;
	sa_server.sin_addr.s_addr = INADDR_ANY;
	sa_server.sin_port = htons(PORT);

	err = bind(s_server, (struct sockaddr*) &sa_server, sizeof(sa_server));		
	CHK_ERR(err, "bind");
	err = listen(s_server, 5);													
	CHK_ERR(err, "listen");

	set_nonblocking(s_server, mode);

	FD_ZERO(&fds);
	FD_SET(s_server, &fds);
	printf("server started...\n");

	for (;;)
	{
		int s_accept;
		struct sockaddr_in sa_accept;
		int len;
		int result;
		p62351_tls_t *tls;
		char recvData[1024];
		char *sendData;
		struct timeval timeout;

		timeout.tv_sec = 0;
		timeout.tv_usec = 1;

		newfds = fds;
		if (wt_flag && rd_flag)
		{
			printf("Waiting for connection...");
			result = select(0, &newfds, NULL, NULL, NULL);
		}
		else
		{
			result = select(0, &newfds, NULL, NULL, &timeout);
		}
		if (result > 0)
		{
			//如果服务器socket发生读变化，则接收连接
			if (FD_ISSET(s_server, &newfds))
			{
				len = sizeof(sa_accept);
				memset(&sa_accept, 0, len);
				s_accept = accept(s_server, (struct sockaddr*) &sa_accept, &len);
				if (s_accept != INVALID_SOCKET)
				{
					char hostbuf[NI_MAXHOST], portbuf[NI_MAXSERV];
					getnameinfo((struct sockaddr *) &sa_accept,
						sizeof(struct sockaddr), hostbuf, NI_MAXHOST,
						portbuf, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
					printf("Recieving connection from %s, port: %s\n", hostbuf, portbuf);
					set_nonblocking(s_accept, mode);

					tls = p62351_tls_new(ctx, s_accept, FALSE, TRUE);
					if (!tls)
					{
						fprintf(stderr, "p62351_tls_new() failed: %s\n", p62351_get_last_error_string());
						continue;
					}
					memset(recvData, 0, sizeof(recvData));
					ret = p62351_tls_read(tls, recvData, sizeof(recvData), &err);
					if (ret > 0 && err == 0)
					{
						recvData[ret] = 0;
						printf(recvData);
					}
					else
					{
						node *client = (node *)malloc(sizeof(node));
						CHK_NULL(client);
						client->prior = NULL;
						client->next = NULL;
						client->tls = tls;
						//client->is_finished = FALSE;
						enqueue(rd_queue, client);			//加入读队列
					}

				}
				else
				{
					perror("accept error\n");
					exit(-1);
				}
			}

		}
		else if (result == 0)
		{
			printf("timeout!\n");
		}
		else
		{
			perror("select error\n");
			getchar();
			exit(-1);
		}
		if (read_queue(rd_queue, recvData, sizeof(recvData)))
		{
			printf("Recieved from client: %s\n", recvData);
		}
		if (write_queue(wt_queue, "hello client!", strlen("hello client!")))
		{
			printf("Done.\n");
		}

	}
	clean_queue(rd_queue);
	clean_queue(wt_queue);
	closesocket(s_server);
}