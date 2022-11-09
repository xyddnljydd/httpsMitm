#include <winsock2.h>
#include <windows.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include "SSLUtils.h"
#include "windivert.h"

#define MAXBUF          WINDIVERT_MTU_MAX
#define PROXY_PORT      34010
#define ALT_PORT        43010

/*
 * Proxy server configuration.
 */
typedef struct
{
    UINT16 proxy_port;
    UINT16 alt_port;
} PROXY_CONFIG, *PPROXY_CONFIG;

typedef struct
{
    SOCKET s;
    UINT16 alt_port;
    struct in_addr dest;
} PROXY_CONNECTION_CONFIG, *PPROXY_CONNECTION_CONFIG;

typedef struct
{
    BOOL inbound;
    SOCKET s;
    SOCKET t;
} PROXY_TRANSFER_CONFIG, *PPROXY_TRANSFER_CONFIG;

/*
 * Lock to sync output.
 */
static HANDLE lock;

/*
 * Prototypes.
 */
static DWORD proxy(LPVOID arg);
static DWORD proxy_connection_handler(LPVOID arg);

/*
 * Error handling.
 */
static void message(const char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    WaitForSingleObject(lock, INFINITE);
    vfprintf(stderr, msg, args);
    putc('\n', stderr);
    ReleaseMutex(lock);
    va_end(args);
}
#define error(msg, ...)                         \
    do {                                        \
        message("error: " msg, ## __VA_ARGS__); \
        exit(EXIT_FAILURE);                     \
    } while (FALSE)
#define warning(msg, ...)                       \
    message("warning: " msg, ## __VA_ARGS__)

/*
 * Entry.
 */
CRITICAL_SECTION g_critical;
int __cdecl main()
{
	int r;
	DWORD len;
	UINT packet_len;
	char filter[256];
	INT16 priority = 123;
	PPROXY_CONFIG config;
    HANDLE handle, thread;
	WINDIVERT_ADDRESS addr;
	PWINDIVERT_IPHDR ip_header;
	unsigned char packet[MAXBUF];
	PWINDIVERT_TCPHDR tcp_header;
    UINT16 port, proxy_port, alt_port;


	//初始化openssl
	SSL_library_init();
	SSL_load_error_strings();
	InitializeCriticalSection(&g_critical);//初始化临界区
	initCa();

    port = 443;
    proxy_port = (port == PROXY_PORT? PROXY_PORT+1: PROXY_PORT);//代理端口
    alt_port = (port == ALT_PORT? ALT_PORT+1: ALT_PORT);//发送数据到外部的端口
    lock = CreateMutex(NULL, FALSE, NULL);
    if (lock == NULL)
    {
        printf("error: failed to create mutex (%d)\n", GetLastError());
        exit(EXIT_FAILURE);
    }

    // Divert all traffic to/from `port', `proxy_port' and `alt_port'.
    r = snprintf(filter, sizeof(filter),
        "tcp and "
        "(tcp.DstPort == %d or tcp.DstPort == %d or tcp.DstPort == %d or "
         "tcp.SrcPort == %d or tcp.SrcPort == %d or tcp.SrcPort == %d)",
        port, proxy_port, alt_port, port, proxy_port, alt_port);
    if (r < 0 || r >= sizeof(filter))
    {
        error("failed to create filter string");
    }
    handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, priority, 0);
    if (handle == INVALID_HANDLE_VALUE)
    {
        error("failed to open the WinDivert device (%d)", GetLastError());
    }

    // Spawn proxy thread,
    config = (PPROXY_CONFIG)malloc(sizeof(PROXY_CONFIG));
    if (config == NULL)
    {
        error("failed to allocate memory");
    }
    config->proxy_port = proxy_port;
    config->alt_port = alt_port;
    thread = CreateThread(NULL, 1, (LPTHREAD_START_ROUTINE)proxy, (LPVOID)config, 0, NULL);
    if (thread == NULL)
    {
        error("failed to create thread (%d)", GetLastError());
    }
    CloseHandle(thread);

    // Main loop:
    while (TRUE)
    {
        if (!WinDivertRecv(handle, packet, sizeof(packet), &packet_len, &addr))
        {
            warning("failed to read packet (%d)", GetLastError());
            continue;
        }

        WinDivertHelperParsePacket(packet, packet_len, &ip_header, NULL, NULL, NULL, NULL, &tcp_header, NULL, NULL, NULL, NULL, NULL);
        if (ip_header == NULL || tcp_header == NULL)
        {
            warning("failed to parse packet (%d)", GetLastError());
            continue;
        }

        if (addr.Outbound)
        {
            if (tcp_header->DstPort == htons(port))
            {
                // Reflect: PORT ---> PROXY
                UINT32 dst_addr = ip_header->DstAddr;
                tcp_header->DstPort = htons(proxy_port);
                ip_header->DstAddr = ip_header->SrcAddr;
                ip_header->SrcAddr = dst_addr;
                addr.Outbound = FALSE;
            }
            else if (tcp_header->SrcPort == htons(proxy_port))
            {
                // Reflect: PROXY ---> PORT
                UINT32 dst_addr = ip_header->DstAddr;
                tcp_header->SrcPort = htons(port);
                ip_header->DstAddr = ip_header->SrcAddr;
                ip_header->SrcAddr = dst_addr;
                addr.Outbound = FALSE;
            }
            else if (tcp_header->DstPort == htons(alt_port))
            {
                // Redirect: ALT ---> PORT
                tcp_header->DstPort = htons(port);
            }
        }
        else
        {
            if (tcp_header->SrcPort == htons(port))
            {
                // Redirect: PORT ---> ALT
                tcp_header->SrcPort = htons(alt_port);
            }
        }

        WinDivertHelperCalcChecksums(packet, packet_len, &addr, 0);
        if (!WinDivertSend(handle, packet, packet_len, NULL, &addr))
        {
            warning("failed to send packet (%d)", GetLastError());
            continue;
        }
    }
	DeleteCriticalSection(&g_critical);
    return 0;
}

/*
 * Proxy server thread.
 */
static DWORD proxy(LPVOID arg)
{
    PPROXY_CONFIG config = (PPROXY_CONFIG)arg;
    UINT16 proxy_port = config->proxy_port;
    UINT16 alt_port = config->alt_port;
    int on = 1;
    WSADATA wsa_data;
    WORD wsa_version = MAKEWORD(2, 2);
    struct sockaddr_in addr;
    SOCKET s;
    HANDLE thread;
    
    free(config);

    if (WSAStartup(wsa_version, &wsa_data) != 0)
    {
        error("failed to start WSA (%d)", GetLastError());
    }
    
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET)
    {
        error("failed to create socket (%d)", WSAGetLastError());
    }

    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(int)) == SOCKET_ERROR)
    {
        error("failed to re-use address (%d)", GetLastError());
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(proxy_port);
    if (bind(s, (SOCKADDR *)&addr, sizeof(addr)) == SOCKET_ERROR)
    {
        error("failed to bind socket (%d)", WSAGetLastError());
    }

    if (listen(s, SOMAXCONN) == SOCKET_ERROR)
    {
        error("failed to listen socket (%d)", WSAGetLastError());
    }

    while (TRUE)
    {
        // Wait for a new connection.
        PPROXY_CONNECTION_CONFIG config;
        int size = sizeof(addr);
        SOCKET t = accept(s, (SOCKADDR *)&addr, &size);//等待发往目标端口的连接
        if (t == INVALID_SOCKET)
        {
            warning("failed to accept socket (%d)", WSAGetLastError());
            continue;
        }

        // Spawn proxy connection handler thread.
        config = (PPROXY_CONNECTION_CONFIG)malloc(sizeof(PROXY_CONNECTION_CONFIG));
        if (config == NULL)
        {
            error("failed to allocate memory");
        }
        config->s = t;
        config->alt_port = alt_port;
        config->dest = addr.sin_addr;
        thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)proxy_connection_handler, (LPVOID)config, 0, NULL);//这里创建一个新的线程去处理这个socket
        if (thread == NULL)
        {
            warning("failed to create thread (%d)", GetLastError());
            closesocket(t);
            free(config);
            continue;
        }
        CloseHandle(thread);
    }
}

/*
 * Proxy connection handler thread.
 */
#define MAX_LINE        65
int transfers(PVOID argument)
{
	int len, len2;
	char buf[8192] = { 0 };
	PTRANSFER  pData = (PTRANSFER)argument;
	BOOL inbound = pData->inbound;
	SSL* client_ssl = pData->client_ssl;
	SSL* server_ssl = pData->server_ssl;
	free(argument);
	while (TRUE)
	{
		//读取数据
		len = SSL_read(client_ssl, buf, sizeof(buf));
		if (len <= 0)
		{
			//SSL_Error("SSL_read failed");
			SSL_shutdown(client_ssl);
			SSL_shutdown(server_ssl);
			return 0;
		}


		// Dump stream information to the screen.
		HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
		WaitForSingleObject(lock, INFINITE);
		printf("[%.4d] ", len);
		SetConsoleTextAttribute(console, (inbound ? FOREGROUND_RED : FOREGROUND_GREEN));
		for (int i = 0; i < len && i < MAX_LINE; i++)
		{
			if (isprint(buf[i]))
				putchar(buf[i]);
			else
				printf(".");
		}
		SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
		printf("%s\n", (len > MAX_LINE ? "..." : ""));
		ReleaseMutex(lock);

		//写数据
		for (int i = 0; i < len; )
		{
			len2 = SSL_write(server_ssl, buf + i, len - i);
			if (len2 <= 0)
			{
				//SSL_Error("SSL_write failed");
				SSL_shutdown(server_ssl);
				SSL_shutdown(client_ssl);
				return 0;
			}
			i += len2;
		}

	}
	return 0;
}

int serverNameCallback(SSL* ssl, int* ad, void* arg)
{
	PCONNDATA pConnData = (PCONNDATA)arg;
	if (ssl == NULL)
	{
		SSL_Error("serverNameCallback ssl NULL");
		return SSL_TLSEXT_ERR_NOACK;
	}
	//初始化一个ssl
	SSL* client_ssl = Client_SSL_Init();
	if (NULL == client_ssl)
	{
		SSL_shutdown(ssl);
		SSL_Error((char*)"client_ssl error");
		return SSL_TLSEXT_ERR_NOACK;
	}

	//指定ssl的dns name
	const char* servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	if (servername)
	{
		SSL_set_tlsext_host_name(client_ssl, servername);
	}

	//绑定连接的socket
	SSL_set_fd(client_ssl, pConnData->t);
	int ret = SSL_connect(client_ssl);
	if (ret <= 0)
	{
		SSL_free(client_ssl);
		SSL_shutdown(ssl);
		SSL_Error("SSL_connect error");
		return SSL_TLSEXT_ERR_NOACK;
	}

	//获取x509dns name指向的数据 https://blog.csdn.net/propro1314/article/details/72571807 
	X509* server_x509 = SSL_get_peer_certificate(client_ssl);
	if (!server_x509)
	{
		SSL_shutdown(client_ssl);
		SSL_free(client_ssl);
		SSL_shutdown(ssl);
		SSL_Error("Get server_x509 error");
		return SSL_TLSEXT_ERR_NOACK;
	}
	EVP_PKEY* pKey = NULL;
	X509* px509 = UpdateX509(server_x509, &pKey);
	if (px509 && pKey)
	{
		SSL_set_SSL_CTX(ssl, GetSSLCTX(px509, pKey));//更新证书
		EVP_PKEY_free(pKey);
		X509_free(px509);
	}
	else
	{
		SSL_Error("UpdateX509 error");
	}
	X509_free(server_x509);

	pConnData->client_ssl = client_ssl;
	SetEvent(pConnData->hEvent);//设置有信号

	return SSL_TLSEXT_ERR_OK;
}

static DWORD proxy_connection_handler(LPVOID arg)
{
    PPROXY_TRANSFER_CONFIG config1, config2;
    PPROXY_CONNECTION_CONFIG config = (PPROXY_CONNECTION_CONFIG)arg;
    SOCKET s = config->s, t;
    UINT16 alt_port = config->alt_port;
    struct in_addr dest = config->dest;
    struct sockaddr_in addr;
    
    free(config);

    t = socket(AF_INET, SOCK_STREAM, 0);
    if (t == INVALID_SOCKET)
    {
        warning("failed to create socket (%d)", WSAGetLastError());
        closesocket(s);
        return 0;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(alt_port);
    addr.sin_addr = dest;
    if (connect(t, (SOCKADDR *)&addr, sizeof(addr)) == SOCKET_ERROR)
    {
        warning("failed to connect socket (%d) ip: %s", WSAGetLastError(), inet_ntoa(addr.sin_addr));
        closesocket(s);
        closesocket(t);
        return 0;
    }

	//这里需要搞一个回调函数，用来更新证书，此时返回的证书是没有dns name的证书
	PCONNDATA pConnData = (PCONNDATA)malloc(sizeof(CONNDATA));
	if (!pConnData)
	{
		warning("failed malloc PCONNDATA");
		closesocket(s);
		closesocket(t);
		return 0;
	}
	memset(pConnData, 0, sizeof(CONNDATA));
	pConnData->t = t;
	pConnData->hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	SSL* server_ssl = Server_SSL_Init(serverNameCallback, pConnData);//https://stackoom.com/question/1Wr8z
	if (NULL == server_ssl)//初始化ssl失败
	{
		SSL_Error("server_ssl error");
		closesocket(s);
		closesocket(t);
		return 0;
	}

	SSL_set_fd(server_ssl, s);
	int ret = SSL_accept(server_ssl);
	if (ret <= 0)//接受数据失败
	{
		SSL_free(server_ssl);
		closesocket(s);
		closesocket(t);
		SSL_Error("server_ssl SSL_accept error");
		return 0;
	}

	//等待客户端连接完成
	WaitForSingleObject(pConnData->hEvent, INFINITE);
	CloseHandle(pConnData->hEvent);
	PTRANSFER data = (PTRANSFER)malloc(sizeof(TRANSFER));
	PTRANSFER data2 = (PTRANSFER)malloc(sizeof(TRANSFER));
	if (data && data2)
	{
		memset(data, 0, sizeof(PTRANSFER));
		memset(data2, 0, sizeof(PTRANSFER));
		data->client_ssl = server_ssl;
		data->server_ssl = pConnData->client_ssl;
		data->inbound = FALSE;

		data2->client_ssl = pConnData->client_ssl;
		data2->server_ssl = server_ssl;
		data2->inbound = TRUE;

		free(pConnData);
		pConnData = NULL;
		HANDLE h_thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)transfers, data, 0, NULL);
		if (h_thread == NULL)
		{
			warning("failed to create thread (%d)", GetLastError());
			closesocket(s);
			closesocket(t);
			free(data);
			free(data2);
			return 0;
		}
		transfers(data2);
		WaitForSingleObject(h_thread, INFINITE);
		CloseHandle(h_thread);
	}

    closesocket(s);
    closesocket(t);
    return 0;
}
