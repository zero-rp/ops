#include <uv.h>
#include <cJSON.h>
#include <common/sds.h>
#include "data.h"
#include "ops.h"
#include "bridge.h"
#include "http.h"
#include "web.h"
#include "public.h"

#if HAVE_QUIC
#include <lsquic.h>
#endif

//全局
typedef struct _ops_global {
#if HAVE_QUIC
    struct {
        uv_udp_t udp;
        uv_timer_t event;
        struct lsquic_stream_if stream_if;
        struct lsquic_engine_api engine_api;
        struct lsquic_engine_settings engine_settings;
        lsquic_engine_t* engine;
        SSL_CTX* ssl_ctx;
    }quic;
#endif
    uv_loop_t* loop;
    ops_config config;
    ops_bridge_manager* bridge_manager;
    ops_http* http;
    ops_web* web;
    ops_public* public;
}ops_global;

//获取配置
const ops_config* opc_get_config(ops_global* global) {
    return &global->config;
}
//
uv_loop_t* ops_get_loop(ops_global* global) {
    return global->loop;
}

ops_http* ops_get_http(ops_global* global) {
    return global->http;
}

ops_bridge_manager* ops_get_bridge_manager(ops_global* global) {
    return global->bridge_manager;
}

ops_web* ops_get_web(ops_global* global) {
    return global->web;
}

ops_public* ops_get_public(ops_global* global) {
    return global->public;
}
//----------------------------------------------------------quic
#if HAVE_QUIC
static SSL_CTX* get_ssl_ctx(void* peer_ctx, const struct sockaddr* unused) {
    ops_global* global = (ops_global*)peer_ctx;
    return global->quic.ssl_ctx;
}
#define ALPN_QUIC "\x04quic"
static int select_alpn(SSL* ssl, const unsigned char** out, unsigned char* outlen, const unsigned char* in, unsigned int inlen, void* arg) {
    unsigned int    srvlen;
    unsigned char* srv;
    srv = ALPN_QUIC;
    srvlen = sizeof(ALPN_QUIC) - 1;
    if (SSL_select_next_proto((unsigned char**)out, outlen, srv, srvlen, in, inlen) != OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    return SSL_TLSEXT_ERR_OK;
}
static void quic_timer_cb(uv_timer_t* handle);
static void quic_process_conns(ops_global* global) {
    int diff = 0;
    lsquic_engine_process_conns(global->quic.engine);
    if (lsquic_engine_earliest_adv_tick(global->quic.engine, &diff)) {
        if (diff < 0 || (unsigned)diff < global->quic.engine_settings.es_clock_granularity) {
            uv_timer_start(&global->quic.event, quic_timer_cb, global->quic.engine_settings.es_clock_granularity / 1000, 0);
        }
        else {
            uv_timer_start(&global->quic.event, quic_timer_cb, diff / 1000, 0);
        }
    }
}
static void quic_timer_cb(uv_timer_t* handle) {
    ops_global* global = (ops_global*)handle->data;
    quic_process_conns(global);
}
typedef struct quic_send_t {
    uv_udp_send_t req;
    uv_buf_t* buf;
    int len;
} quic_send_t;
static void quic_send_cb(quic_send_t* req, int status) {
    if (req->buf) {
        for (size_t i = 0; i < req->len; i++) {
            if (req->buf[i].base) {
                free(req->buf[i].base);
            }
        }
        free(req->buf);
    }
    free(req);
}
static int send_packets_out(void* ctx, const struct lsquic_out_spec* specs, unsigned n_specs) {
    ops_global* global = (ops_global*)ctx;
    int n = 0;
    for (n = 0; n < n_specs; ++n) {
        quic_send_t* req = malloc(sizeof(quic_send_t));
        if (!req)
            break;
        req->buf = malloc(sizeof(uv_buf_t) * specs[n].iovlen);
        if (!req->buf) {
            free(req->buf);
            break;
        }
        req->len = specs[n].iovlen;
        for (size_t i = 0; i < specs[n].iovlen; i++) {
            req->buf[i].base = malloc(specs[n].iov[i].iov_len);
            if (req->buf[i].base) {
                req->buf[i].len = specs[n].iov[i].iov_len;
                memcpy(req->buf[i].base, specs[n].iov[i].iov_base, specs[n].iov[i].iov_len);
            }
        }
        if (uv_udp_send(&req->req, &global->quic.udp, req->buf, specs[n].iovlen, specs[n].dest_sa, quic_send_cb) != 0) {
            break;
        }
    }
    return (int)n;
}
static void bridge_udp_recv_cb(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags) {
    ops_global* global = (ops_global*)handle->data;
    if (nread) {
        struct sockaddr_in6 local;
        int namelen = sizeof(local);
        uv_udp_getsockname(handle, &local, &namelen);
        lsquic_engine_packet_in(global->quic.engine, buf->base, nread, &local, addr, global, 0);
        quic_process_conns(global);
        free(buf->base);
    }
}
//新连接
static lsquic_conn_ctx_t* quic_on_new_conn(void* stream_if_ctx, lsquic_conn_t* conn) {
    ops_global* global = (ops_global*)stream_if_ctx;
    ops_bridge* bridge = (ops_bridge*)malloc(sizeof(ops_bridge));//为tcp bridge申请资源
    if (!bridge) {
        lsquic_conn_close(conn);
        return NULL;
    }
    memset(bridge, 0, sizeof(*bridge));
    bridge->global = global;
    bridge->type = 2;
    bridge->conn = conn;
    //新客户
    printf("New Client\r\n");
    return bridge;
}
//链接关闭
static void quic_on_conn_closed(lsquic_conn_t* conn) {
    ops_bridge* bridge = (ops_bridge*)lsquic_conn_get_ctx(conn);
    bridge_on_close(bridge);
    lsquic_conn_set_ctx(conn, NULL);
}
//新流
static struct lsquic_stream_ctx* quic_on_new_stream(void* unused, struct lsquic_stream* stream) {
    ops_bridge* bridge = (ops_bridge*)lsquic_conn_get_ctx(lsquic_stream_conn(stream));
    //开始读
    lsquic_stream_wantread(stream, 1);
    //主流
    if (bridge->stream == NULL) {
        bridge->stream = stream;
    }
    return bridge;
}
static size_t quic_readf(void* ctx, const unsigned char* buf, size_t len, int fin) {
    ops_bridge* bridge = (ops_bridge*)ctx;
    char* tmp = malloc(len);
    memcpy(tmp, buf, len);
    bridge_on_read(bridge, tmp, len);
    return len;
}
static void quic_on_read(struct lsquic_stream* stream, struct lsquic_stream_ctx* stream_ctx) {
    lsquic_stream_readf(stream, quic_readf, stream_ctx);
}
static void quic_on_write(struct lsquic_stream* stream, struct lsquic_stream_ctx* stream_ctx) {
    ops_bridge* bridge = (ops_bridge*)stream_ctx;
    if (stream == bridge->stream && bridge->send) {
        send_buffer* buffer = bridge->send;
        do {
            ssize_t ok = lsquic_stream_write(stream, buffer->data + buffer->pos, buffer->size - buffer->pos);
            if (ok < 0) {
                break;
            }
            //本次写完
            if (ok == buffer->size - buffer->pos) {
                free(buffer->data);
                send_buffer* temp = buffer;
                buffer = buffer->next;
                bridge->send = buffer;
                free(temp);
                //队列写完
                if (buffer == NULL) {
                    bridge->send = NULL;
                    bridge->tail = NULL;
                    lsquic_stream_wantwrite(stream, 0);
                    break;
                }
            }
            else {
                //没写完,等下一次发送
                buffer->pos += ok;
                break;
            }
        } while (buffer != NULL);
    }
    lsquic_stream_flush(stream);
}
//流关闭
static void quic_on_close(lsquic_stream_t* stream, lsquic_stream_ctx_t* stream_ctx) {
    ops_bridge* bridge = (ops_bridge*)stream_ctx;
    if (bridge->stream == stream) {
        bridge->stream = NULL;
    }
}

static void bridge_init_quic(ops_global* global) {
    struct sockaddr_in6 _addr;
    lsquic_global_init(LSQUIC_GLOBAL_SERVER);

    //lsquic_set_log_level("DEBUG");
    //lsquic_log_to_fstream(stderr, LLTS_HHMMSSMS);

    lsquic_engine_init_settings(&global->quic.engine_settings, LSENG_SERVER);

    global->quic.stream_if.on_new_conn = quic_on_new_conn;
    global->quic.stream_if.on_conn_closed = quic_on_conn_closed;
    global->quic.stream_if.on_new_stream = quic_on_new_stream;
    global->quic.stream_if.on_read = quic_on_read;
    global->quic.stream_if.on_write = quic_on_write;
    global->quic.stream_if.on_close = quic_on_close;

    global->quic.engine_api.ea_settings = &global->quic.engine_settings;
    global->quic.engine_api.ea_stream_if = &global->quic.stream_if;
    global->quic.engine_api.ea_stream_if_ctx = global;
    global->quic.engine_api.ea_packets_out = send_packets_out;
    global->quic.engine_api.ea_packets_out_ctx = global;
    global->quic.engine_api.ea_get_ssl_ctx = get_ssl_ctx;
    global->quic.engine_api.ea_cert_lu_ctx = global;

    char err_buf[100];
    if (0 != lsquic_engine_check_settings(global->quic.engine_api.ea_settings, LSENG_SERVER, err_buf, sizeof(err_buf))) {
        return;
    }

    global->quic.engine = lsquic_engine_new(LSENG_SERVER, &global->quic.engine_api);

    //初始化ssl
    //---------
    global->quic.ssl_ctx = SSL_CTX_new(TLS_method());

    SSL_CTX_set_min_proto_version(global->quic.ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(global->quic.ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_default_verify_paths(global->quic.ssl_ctx);
    SSL_CTX_set_alpn_select_cb(global->quic.ssl_ctx, select_alpn, global);
    SSL_CTX_set_early_data_enabled(global->quic.ssl_ctx, 1);

    if (global->config.rand_cert) {
        // 生成随机证书和私钥
        X509* x509 = X509_new();
        EVP_PKEY* pkey = EVP_PKEY_new();
        RSA* rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
        EVP_PKEY_assign_RSA(pkey, rsa);

        X509_set_pubkey(x509, pkey);
        X509_NAME* name = X509_NAME_new();
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"localhost", -1, -1, 0);
        X509_set_subject_name(x509, name);
        X509_set_issuer_name(x509, name);
        X509_gmtime_adj(X509_get_notBefore(x509), 0);
        X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);
        X509_sign(x509, pkey, EVP_sha1());

        // 将证书和私钥加载到SSL_CTX
        SSL_CTX_use_certificate(global->quic.ssl_ctx, x509);
        SSL_CTX_use_PrivateKey(global->quic.ssl_ctx, pkey);

        // 检查证书和私钥是否匹配
        if (!SSL_CTX_check_private_key(global->quic.ssl_ctx)) {
            fprintf(stderr, "Private key does not match the certificate public key\n");
            return;
        }

        // 清理资源
        X509_free(x509);
        EVP_PKEY_free(pkey);
    }
    else {
        if (1 != SSL_CTX_use_certificate_chain_file(global->quic.ssl_ctx, global->config.cert_file)) {
            return;
        }

        else if (1 != SSL_CTX_use_PrivateKey_file(global->quic.ssl_ctx, global->config.key_file, SSL_FILETYPE_PEM)) {
            return;
        }
    }
    const int was = SSL_CTX_set_session_cache_mode(global->quic.ssl_ctx, 1);


    //事件定时器
    uv_timer_init(loop, &global->quic.event);
    global->quic.event.data = global;

    //监听udp端口
    uv_udp_init(loop, &global->quic.udp);
    global->quic.udp.data = global;
    uv_ip6_addr("::0", global->config.bridge_port, &_addr);
    uv_udp_bind(&global->quic.udp, &_addr, 0);
    uv_udp_recv_start(&global->quic.udp, alloc_buffer, bridge_udp_recv_cb);
}

#endif
//全局初始化
static int init_global(ops_global* global) {
#if HAVE_QUIC
    bridge_init_quic(global);
#endif
    //启动网桥
    global->bridge_manager = bridge_manager_new(global);
    //启动http转发
    global->http = http_new(global, global->bridge_manager);
    //启动web管理
    global->web = web_new(global);
    //启动公网服务
    global->public = public_new(global, global->bridge_manager);
    //初始化数据
    data_init(global->config.db_file, global, global->bridge_manager);
    return 0;
}
//win系统服务
#if defined(_WIN32) || defined(_WIN64)
ops_global* _global = NULL;
int install_service = 0;
int run_service = 0;
char* szServiceName = NULL;
SERVICE_STATUS status;
SERVICE_STATUS_HANDLE hServiceStatus;

void WINAPI ServiceStrl(DWORD dwOpcode) {
    switch (dwOpcode)
    {
    case SERVICE_CONTROL_STOP:
        status.dwCurrentState = SERVICE_STOP_PENDING;
        SetServiceStatus(hServiceStatus, &status);
        //结束服务
        ExitProcess(0);
        break;
    case SERVICE_CONTROL_PAUSE:
        break;
    case SERVICE_CONTROL_CONTINUE:
        break;
    case SERVICE_CONTROL_INTERROGATE:
        break;
    case SERVICE_CONTROL_SHUTDOWN:
        break;
    default:
        //LogEvent(_T("Bad service request"));
        break;
    }
}
void WINAPI ServiceMain() {
    status.dwCurrentState = SERVICE_START_PENDING;
    status.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    //注册服务控制  
    hServiceStatus = RegisterServiceCtrlHandler(szServiceName, ServiceStrl);
    if (hServiceStatus == NULL) {
        //LogEvent("Handler not installed");
        return;
    }
    SetServiceStatus(hServiceStatus, &status);

    status.dwWin32ExitCode = S_OK;
    status.dwCheckPoint = 0;
    status.dwWaitHint = 0;
    status.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(hServiceStatus, &status);

    //初始化
    if (init_global(_global)) {
        return 1;
    }
    //
    uv_run(_global->loop, UV_RUN_DEFAULT);

    status.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(hServiceStatus, &status);
    //LogEvent("Service stopped");
}
//判断服务是否安装
BOOL IsInstalled() {
    BOOL bResult = FALSE;

    //打开服务控制管理器  
    SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hSCM != NULL) {
        //打开服务  
        SC_HANDLE hService = OpenService(hSCM, szServiceName, SERVICE_QUERY_CONFIG);
        if (hService != NULL) {
            bResult = TRUE;
            CloseServiceHandle(hService);
        }
        CloseServiceHandle(hSCM);
    }
    return bResult;
}
BOOL Uninstall() {
    if (!IsInstalled(szServiceName))
        return TRUE;

    SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

    if (hSCM == NULL) {
        MessageBox(NULL, "Couldn't open service manager", szServiceName, MB_OK);
        return FALSE;
    }

    SC_HANDLE hService = OpenService(hSCM, szServiceName, SERVICE_STOP | DELETE);

    if (hService == NULL) {
        CloseServiceHandle(hSCM);
        MessageBox(NULL, "Couldn't open service", szServiceName, MB_OK);
        return FALSE;
    }
    SERVICE_STATUS status;
    ControlService(hService, SERVICE_CONTROL_STOP, &status);

    //删除服务  
    BOOL bDelete = DeleteService(hService);
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);

    if (bDelete)
        return TRUE;
    return FALSE;
}
BOOL Install(int argc, char* argv[]) {
    if (IsInstalled(szServiceName)) {
        return TRUE;
    }
    //打开服务控制管理器  
    SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hSCM == NULL) {
        MessageBox(NULL, "Couldn't open service manager", szServiceName, MB_OK);
        return FALSE;
    }

    // Get the executable file path  
    TCHAR szFilePath[MAX_PATH];
    GetModuleFileName(NULL, szFilePath, MAX_PATH);
    TCHAR szCmd[512] = { 0 };
    strcat(szCmd, szFilePath);
    for (size_t i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-install") == 0) {
            strcat(szCmd, " -service ");
            i++;
            strcat(szCmd, argv[i]);
        }
        else {
            strcat(szCmd, " ");
            strcat(szCmd, argv[i]);
            i++;
            strcat(szCmd, " ");
            strcat(szCmd, argv[i]);
        }
    }

    //创建服务  
    SC_HANDLE hService = CreateService(
        hSCM, szServiceName, szServiceName,
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
        szCmd, NULL, NULL, "", NULL, NULL);

    if (hService == NULL) {
        CloseServiceHandle(hSCM);
        MessageBox(NULL, "Couldn't create service", szServiceName, MB_OK);
        return FALSE;
    }

    StartService(hService, 0, NULL);

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return TRUE;
}
#endif
//加载配置
static load_config(ops_global* global, int argc, char* argv[]) {
    //默认参数
    global->config.db_file = "data.db";
    global->config.bridge_port = 8025;
    global->config.web_port = 8088;
    global->config.https_proxy_port = 443;
    global->config.http_proxy_port = 80;
    global->config.admin_user = "admin";
    global->config.admin_pass = "1234";
    global->config.rand_cert = 1;

    //从配置文件加载参数
    const char* config_file = "ops.json";
    for (size_t i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0) {
            i++;
            config_file = argv[i];
            break;
        }
    }
    FILE* config_fd = fopen(config_file, "r");
    cJSON* config_json = NULL;
    if (config_fd) {
        fseek(config_fd, 0, SEEK_END);
        long size = ftell(config_fd);
        fseek(config_fd, 0, SEEK_SET);
        char* data = (char*)malloc(size + 1);
        fread(data, 1, size, config_fd);
        data[size] = '\0';
        config_json = cJSON_Parse(data);
        fclose(config_fd);
        free(data);
    }
    if (config_json) {
        cJSON* item = cJSON_GetObjectItem(config_json, "user");
        if (item && item->valuestring) {
            global->config.admin_user = strdup(item->valuestring);
        }
        item = cJSON_GetObjectItem(config_json, "pass");
        if (item && item->valuestring) {
            global->config.admin_pass = strdup(item->valuestring);
        }
        item = cJSON_GetObjectItem(config_json, "bridge_port");
        if (item && item->valueint) {
            global->config.bridge_port = item->valueint;
        }
        item = cJSON_GetObjectItem(config_json, "web_port");
        if (item && item->valueint) {
            global->config.web_port = item->valueint;
        }
        item = cJSON_GetObjectItem(config_json, "http_proxy_port");
        if (item && item->valueint) {
            global->config.http_proxy_port = item->valueint;
        }
        item = cJSON_GetObjectItem(config_json, "https_proxy_port");
        if (item && item->valueint) {
            global->config.https_proxy_port = item->valueint;
        }
        item = cJSON_GetObjectItem(config_json, "db_file");
        if (item && item->valuestring) {
            global->config.db_file = strdup(item->valuestring);
        }
        item = cJSON_GetObjectItem(config_json, "cert_file");
        if (item && item->valuestring) {
            global->config.cert_file = strdup(item->valuestring);
        }
        item = cJSON_GetObjectItem(config_json, "key_file");
        if (item && item->valuestring) {
            global->config.key_file = strdup(item->valuestring);
        }
        cJSON_free(config_json);
    }
    //从命令行加载参数,最高优先级
    for (size_t i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0) {
            i++;
            global->config.bridge_port = atoi(argv[i]);
        }
        else if (strcmp(argv[i], "-w") == 0) {
            i++;
            global->config.web_port = atoi(argv[i]);
        }
        else if (strcmp(argv[i], "-h") == 0) {
            i++;
            global->config.http_proxy_port = atoi(argv[i]);
        }
        else if (strcmp(argv[i], "-s") == 0) {
            i++;
            global->config.https_proxy_port = atoi(argv[i]);
        }
        else if (strcmp(argv[i], "-d") == 0) {
            i++;
            global->config.db_file = strdup(argv[i]);
        }
        else if (strcmp(argv[i], "-cert") == 0) {
            i++;
            global->config.cert_file = strdup(argv[i]);
        }
        else if (strcmp(argv[i], "-key") == 0) {
            i++;
            global->config.key_file = strdup(argv[i]);
        }
        else if (strcmp(argv[i], "-web_user") == 0) {
            i++;
            global->config.admin_user = strdup(argv[i]);
        }
        else if (strcmp(argv[i], "-web_pass") == 0) {
            i++;
            global->config.admin_pass = strdup(argv[i]);
        }
#if defined(_WIN32) || defined(_WIN64)
        else if (strcmp(argv[i], "-install") == 0) {
            i++;
            szServiceName = argv[i];
            install_service = 1;
        }
        else if (strcmp(argv[i], "-uninstall") == 0) {
            i++;
            szServiceName = argv[i];
            install_service = -1;
        }
        else if (strcmp(argv[i], "-service") == 0) {
            i++;
            szServiceName = argv[i];
            run_service = 1;
        }
#endif
    }
}

int main(int argc, char* argv[]) {
    //启动监听
    ops_global* global = (ops_global*)malloc(sizeof(*global));
    if (global == NULL)
        return 0;
    memset(global, 0, sizeof(*global));
    //
    global->loop = uv_default_loop();
    //加载参数
    load_config(global, argc, argv);
#if defined(_WIN32) || defined(_WIN64)
    if (install_service == 1) {
        Install(argc, argv);
        return 0;
    }
    if (install_service == -1) {
        Uninstall();
        return 0;
    }
    if (run_service) {
        _global = global;
        //初始化
        hServiceStatus = NULL;
        status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
        status.dwCurrentState = SERVICE_STOPPED;
        status.dwControlsAccepted = SERVICE_ACCEPT_STOP;
        status.dwWin32ExitCode = 0;
        status.dwServiceSpecificExitCode = 0;
        status.dwCheckPoint = 0;
        status.dwWaitHint = 0;
        SERVICE_TABLE_ENTRY st[] = {
            { szServiceName, (LPSERVICE_MAIN_FUNCTION)ServiceMain },
            { NULL, NULL }
        };
        if (!StartServiceCtrlDispatcher(st)) {
            return 1;
        }
        return 0;
    }
#endif
    //初始化
    if (init_global(global)) {
        return 1;
    }
    //
    uv_run(global->loop, UV_RUN_DEFAULT);
    return 0;
}

