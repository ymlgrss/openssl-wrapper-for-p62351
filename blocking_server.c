#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_DEPRECATE 

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#	include <WinSock2.h>
#	include <windows.h>
#else
#   include <stdbool.h>
#   include <arpa/inet.h>
#   include <netdb.h>
#   include <unistd.h>
#   include <netinet/in.h>
#   include <sys/select.h>
#endif

#include "p62351.h"

#ifdef _WIN32
#pragma comment(lib, "Ws2_32.lib")
#endif

#define PORT 8000
#define HOST "127.0.0.1"

int quit()
{
	getchar();
	exit(1);
}

int main()
{
	//声明
	p62351_tls_ctx_config_t config = {      //TLS上下文对象配置信息 
		128000,        /* 自动重协商的字节数 */
		600,           /* 自动重协商的时间周期 */
		"ca.pem",      /* CA 根证书文件的路径 */
		"server_1.pfx",  /* 本端证书文件的路径 */
		"123456",      /* 本端证书文件的保护口令 */
		NULL,          /* CRL 文件路径  */
		12 * 3600,     /* CRL 文件自动更新周期 */
		600,
	};
	p62351_tls_ctx_t *ctx;
	int s_server;
	struct sockaddr_in sin;
	p62351_tls_t *tls;

#ifdef _WIN32
	//初始化WSA
	WORD socketVersion = MAKEWORD(2, 2);
	WSADATA data;
	if (WSAStartup(socketVersion, &data) != 0)
	{
		quit();
	}
	else
	{
		printf("wVersion: %d.%d\n", LOBYTE(data.wVersion), HIBYTE(data.wVersion));
		printf("wHighVersion: %d.%d\n", LOBYTE(data.wHighVersion), HIBYTE(data.wHighVersion));
		printf("szDescription: %s\n", data.szDescription);
		printf("szSystemStatus: %s\n", data.szSystemStatus);
	}
#endif

	//创建TLS上下文对象
	ctx = p62351_tls_ctx_new(&config);
	if (!ctx)
	{
		fprintf(stderr, "p62351_tls_ctx_new() failed: %s\n", p62351_get_last_error_string());
		quit();
	}
	if (p62351_tls_add_peer_cert(ctx, "client.pem") != 0)
	{
		fprintf(stderr, "p62351_tls_add_peer_cert() failed: %s\n", p62351_get_last_error_string());
	}

	//创建socket
	s_server = socket(AF_INET, SOCK_STREAM, 0);
	if (s_server < 0)
	{
		printf("invalid socket!");
		quit();
	}

	//绑定IP和端口
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(PORT);
	sin.sin_addr.s_addr = inet_addr(HOST);
	if (bind(s_server, (struct sockaddr *)&sin, sizeof(sin)) < 0)
	{
		printf("bind error");
#ifdef _WIN32
		closesocket(s_server);
#else
		close(s_server);
#endif
		quit();
	}

	//开始监听
	if (listen(s_server, 1) < 0)
	{
		printf("listen error");
		quit();
	}

	//循环接收数据
	while(true)
	{
		int s_client;
		struct sockaddr_in addr;
		int addr_len = sizeof(addr);
		char recvData[256];
		char sendData[256];
		int ret, err;
		printf("\n等待新的连接\n");
		s_client = accept(s_server, NULL, NULL);
		if (s_client < 0)
		{
			printf("invalid socket");
			continue;
		}
		printf("接收到一个连接\n");
		tls = p62351_tls_new(ctx, s_client, false, false);
		if (!tls)
		{
			printf("p62351_tls_new() failed: %s\n", p62351_get_last_error_string());
			continue;
		}
		printf("协商密码套件: %s\n", p62351_tls_get_cipher_name(tls));       //得到协商出的加密套件名称
		printf("对端证书主题名: %s\n", p62351_tls_get_peer_cert_subject(tls)); //得到对端证书的主题名
		printf("对端证书签发者: %s\n", p62351_tls_get_peer_cert_issuer(tls));   //得到对端证书的签发者

		//接收数据
		for(;;)
		{
			printf("等待对端数据...\n");
			memset(recvData, 0, 256);
			ret = p62351_tls_read(tls, recvData, sizeof(recvData), &err);
			if (err != 0)
			{
				printf("tls_read() error");
				continue;
			}
			else
			{
				recvData[ret] = 0x00;
				printf("客户端报文：");
				printf("%s\n", recvData);
				printf("\n");
			}

			//发送数据
			memset(sendData, 0, 256);
			if (strcmp(recvData, "quit") != 0)
			{
				printf("请输入回送给客户端的报文：");
				gets(sendData);
				p62351_tls_write(tls, sendData, strlen(sendData), &err);
				if (err != 0)
				{
					printf("tls_write() error");
					quit();
				}
			}
			else
			{
				p62351_tls_write(tls, "exit", 5, &err);
				if (err != 0)
				{
					printf("tls_write() error");
					quit();
				}
				break;
			}
		}
	}
#ifdef _WIN32
	WSACleanup();
#endif
	p62351_tls_free(tls);
	getchar();
	return 0;
}