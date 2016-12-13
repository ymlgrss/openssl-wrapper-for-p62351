#define TLS_ERROR_NONE          0
#define TLS_ERROR_ZERO_RETURN   1
#define TLS_ERROR_WANT_READ     2
#define TLS_ERROR_WANT_WRITE    3
#define TLS_ERROR_OTHER         4


typedef struct p62351_tls_ctx_config_s
{
	/** 自动重协商的字节数 */
	int renegotiate_bytes;
	/** 自动重协商的时间周期 */
	int renegotiate_timeout;
	/** CA 根证书文件的路径 */
	const char *ca_file;
	/** 本端证书文件的路径 */
	const char *cert_file;
	/** 本端证书文件的保护口令 */
	const char *cert_password;
	/** CRL 文件路径 */
	const char *crl_file;
	/** CRL 文件自动更新周期 */
	int crl_update_interval;
	/** 握手超时时间，单位为秒 */
	int handshake_timeout;
} p62351_tls_ctx_config_t;

/**
* TLS 上下文对象
*
* 该对象用来进行全局配置，以便根据统一的配置新建 TLS 对象。可以理解为这是一个
* 工厂对象。
*/
typedef struct p62351_tls_ctx_s p62351_tls_ctx_t;

/**
* TLS 连接对象
*
* 一个 TLS 连接对象对应于一条 TLS 连接。
*/
typedef struct p62351_tls_s p62351_tls_t;

/**
* 新建 TLS 上下文对象
*
* 同时对 p62351 协议库进行全局初始化。
*
* @param[in] config TLS 配置参数
* @return 新建出来的 TLS 上下文对象，NULL 表示失败。
*/
p62351_tls_ctx_t *p62351_tls_ctx_new(const p62351_tls_ctx_config_t *config);

/**
* 添加对端证书
*
* 添加允许认证的对端证书，在上一个接口之后调用，一次添加一个。如果没有调用过该
* 函数，则说明接受出自授权的证书机构的所有证书。
*
* @param[in] ctx TLS 上下文对象
* @param[in] certpath 待添加的证书对象的文件路径
* @return 0 表示添加成功
*/
int p62351_tls_add_peer_cert(p62351_tls_ctx_t *ctx, const char *certpath);

/**
* 新建 TLS 连接对象
* 通过 TLS 上下文对象建立新的 TLS 连接对象，表示一条 TLS 连接，同时指定底层的
* socket 句柄，该 TLS 连接的角色，是客户端（发起 TLS 连接的一方）还是服务
* 端（接收 TLS 连接的一方），以及该连接的读写模式是阻塞模式还是非阻塞模式。
*
* 要求在调用该函数之前，sock 已经由应用程序初始化：如果是客户端，要求已经成功
* 调用操作系统提供的connect函数；如果是服务端，则要求是通过操作系统提供的
* accept 函数得到的用来与对端进行通信的 socket 句柄。
*
* @param[in] ctx TLS 上下文对象
* @param[in] sock 该 TLS 连接所要使用的 socket 网络连接句柄
* @param[in] is_client 该 TLS 连接是否客户端
* @param[in] is_blocking 该 TLS 连接是否使用阻塞模式
* @return 新建立的 TLS 连接对象，NULL 表示失败。
*/
p62351_tls_t *p62351_tls_new(p62351_tls_ctx_t *ctx, int sock, int is_client, int is_nonblocking);

/**
* 从对端读取数据
*
* @param[in] tls TLS 连接对象
* @param[in] buf 读取缓冲区指针
* @param[in] len 读取缓冲区大小
* @param[out] err TLS 执行状态码
* @return 0 表示读取成功
*/
int p62351_tls_read(p62351_tls_t *tls, char *buf, int len, int *err);

/**
* 发送数据到对端
*
* @param[in] tls TLS 连接对象
* @param[in] buf 待写数据缓冲区指针
* @param[in] len 待写数据缓冲区长度
* @param[out] err TLS 执行状态码
* @return 0 表示写入成功
*/
int p62351_tls_write(p62351_tls_t *tls, const char *buf, int len, int *err);

/** 释放 TLS 连接对象 */
void p62351_tls_free(p62351_tls_t *tls);
/** 释放 TLS 上下文对象 */
void p62351_tls_ctx_free(p62351_tls_ctx_t *ctx);

/**
* 得到上一个协议库接口的错误信息字符串。
*
* 该字符串的内存由协议库内部维护，不需要用户手动释放。每个线程都有一个独立的
* 存储区域。
*
* @return 错误信息字符串
*/
const char *p62351_get_last_error_string(void);

/** 得到协商出的加密套件名称。不需要用户手动释放。 */
const char *p62351_tls_get_cipher_name(p62351_tls_t *tls);
/** 得到对端证书的主题名。不需要用户手动释放。 */
const char *p62351_tls_get_peer_cert_subject(p62351_tls_t *tls);
/** 得到对端证书的签发者。不需要用户手动释放。 */
const char *p62351_tls_get_peer_cert_issuer(p62351_tls_t *tls);

