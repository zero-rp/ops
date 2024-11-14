#include <uv.h>
#include <cJSON.h>
#include <uv/tree.h>
#include <openssl/ssl.h>
#include <common/common.h>
#if HAVE_QUIC
#include <lsquic.h>
#endif
#include "opc.h"
#include "bridge.h"


//全局对象
typedef struct _opc_global {
#if HAVE_QUIC
    struct {
        uv_udp_t udp;
        uv_timer_t event;
        struct lsquic_stream_if stream_if;
        struct lsquic_engine_api engine_api;
        struct lsquic_engine_settings engine_settings;
        lsquic_engine_t* engine;
        SSL_CTX* ssl_ctx;
        char* token;
        int token_len;
    }quic;
#endif
    uv_timer_t timer;                //重连定时器
    opc_bridge* bridge;
    opc_config config;                  //
    uv_loop_t* loop;
}opc_global;



//----------------------------------------------------------quic
#if HAVE_QUIC
static void quic_timer_cb(uv_timer_t* handle);
static void quic_process_conns(opc_global* global) {
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
    opc_global* global = (opc_global*)handle->data;
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
    opc_global* global = (opc_global*)ctx;
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
    opc_global* global = (opc_global*)handle->data;
    if (nread) {
        struct sockaddr_in6 local;
        int namelen = sizeof(local);
        uv_udp_getsockname(handle, &local, &namelen);
        lsquic_engine_packet_in(global->quic.engine, buf->base, nread, &local, addr, global, 0);
        quic_process_conns(global);
        free(buf->base);
    }
}
//获取ssl_ctx
static SSL_CTX* get_ssl_ctx(void* peer_ctx, const struct sockaddr* unused) {
    opc_global* global = peer_ctx;
    return global->quic.ssl_ctx;
}
//新连接
static lsquic_conn_ctx_t* quic_on_new_conn(void* stream_if_ctx, lsquic_conn_t* conn) {
    opc_bridge* bridge = (opc_bridge*)lsquic_conn_get_ctx(conn);
    return bridge;
}
//链接关闭
static void quic_on_conn_closed(lsquic_conn_t* conn) {
    opc_bridge* bridge = (opc_bridge*)lsquic_conn_get_ctx(conn);
    bridge->conn = NULL;
    bridge_on_close(bridge);
    lsquic_conn_set_ctx(conn, NULL);
}
//握手完成
static void quic_on_hsk_done(lsquic_conn_t* c, enum lsquic_hsk_status s) {
    //创建流
    lsquic_conn_make_stream(c);
}
static void quic_on_new_token(lsquic_conn_t* c, const unsigned char* token, size_t token_size) {
    opc_global* global = (opc_global*)c;
    if (global->quic.token)
        free(global->quic.token);
    global->quic.token = malloc(token_size);
    memcpy(global->quic.token, token, token_size);
    global->quic.token_len = token_size;
}
//新流
static struct lsquic_stream_ctx* quic_on_new_stream(void* unused, struct lsquic_stream* stream) {
    opc_global* global = (opc_global*)unused;
    opc_bridge* bridge = (opc_bridge*)lsquic_conn_get_ctx(lsquic_stream_conn(stream));
    lsquic_stream_set_ctx(stream, bridge);
    //开始读
    lsquic_stream_wantread(stream, 1);
    //主流
    if (bridge->stream == NULL) {
        bridge->stream = stream;
        bridge_on_connect(bridge);
    }
    return bridge;
}
static size_t quic_readf(void* ctx, const unsigned char* buf, size_t len, int fin) {
    char* tmp = malloc(len);
    memcpy(tmp, buf, len);
    bridge_on_read((opc_bridge*)ctx, (char*)tmp, len);
    return len;
}
static void quic_on_read(struct lsquic_stream* stream, struct lsquic_stream_ctx* stream_ctx) {
    lsquic_stream_readf(stream, quic_readf, stream_ctx);
}
static void quic_on_write(struct lsquic_stream* stream, struct lsquic_stream_ctx* stream_ctx) {
    opc_bridge* bridge = (opc_bridge*)stream_ctx;
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
    opc_bridge* bridge = (opc_bridge*)stream_ctx;
    if (bridge->stream == stream) {
        bridge->stream = NULL;
    }
}

static void bridge_init_quic(opc_global* global) {
    struct sockaddr_in6 _addr;
    lsquic_global_init(LSQUIC_GLOBAL_CLIENT);

    //lsquic_set_log_level("DEBUG");
    //lsquic_log_to_fstream(stderr, LLTS_HHMMSSMS);

    lsquic_engine_init_settings(&global->quic.engine_settings, 0);

    global->quic.stream_if.on_new_conn = quic_on_new_conn;
    global->quic.stream_if.on_conn_closed = quic_on_conn_closed;
    global->quic.stream_if.on_new_stream = quic_on_new_stream;
    global->quic.stream_if.on_read = quic_on_read;
    global->quic.stream_if.on_write = quic_on_write;
    global->quic.stream_if.on_close = quic_on_close;
    global->quic.stream_if.on_hsk_done = quic_on_hsk_done;
    global->quic.stream_if.on_new_token = quic_on_new_token;

    global->quic.engine_api.ea_settings = &global->quic.engine_settings;
    global->quic.engine_api.ea_stream_if = &global->quic.stream_if;
    global->quic.engine_api.ea_stream_if_ctx = global;
    global->quic.engine_api.ea_packets_out = send_packets_out;
    global->quic.engine_api.ea_packets_out_ctx = global;
    global->quic.engine_api.ea_cert_lu_ctx = global;
    global->quic.engine_api.ea_get_ssl_ctx = &get_ssl_ctx;

    char err_buf[100];
    if (0 != lsquic_engine_check_settings(global->quic.engine_api.ea_settings, 0, err_buf, sizeof(err_buf))) {
        return;
    }

    global->quic.engine = lsquic_engine_new(0, &global->quic.engine_api);

    //SSL
    global->quic.ssl_ctx = SSL_CTX_new(TLS_method());
    SSL_CTX_set_min_proto_version(global->quic.ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(global->quic.ssl_ctx, TLS1_3_VERSION);
    //设置ALPN
    SSL_CTX_set_alpn_protos(global->quic.ssl_ctx, "\x04quic", 5);

    //事件定时器
    uv_timer_init(loop, &global->quic.event);
    global->quic.event.data = global;

    //监听udp端口
    uv_udp_init(loop, &global->quic.udp);
    global->quic.udp.data = global;
    //指定了本地端口
    if (global->config.bind_ip) {

    }
    else {
        uv_ip6_addr("::0", 0, &_addr);
    }
    uv_udp_bind(&global->quic.udp, &_addr, 0);
    uv_udp_recv_start(&global->quic.udp, alloc_buffer, bridge_udp_recv_cb);
}

#endif

//获取配置
const opc_config* opc_get_config(opc_global* global) {
    return &global->config;
}
//
uv_loop_t* opc_get_loop(opc_global* global) {
    return global->loop;
}

//全局初始化
static int init_global(opc_global* global) {
    //重连定时器
    uv_timer_init(global->loop, &global->timer);
    global->timer.data = global;


#if HAVE_QUIC
    bridge_init_quic(global);
#endif

}

static void obj_check(uv_timer_t* handle) {
    obj_print();
}

//重连回调
static void timer_cb(uv_timer_t* handle) {
    opc_global* global = (opc_global*)handle->data;
    //创建网桥
    global->bridge = bridge_new(global);
    //开始连接
    if (bridge_connect(global->bridge) != 0) {
        bridge_delete(global->bridge);
        global->bridge = NULL;
        //重连
        uv_timer_start(&global->timer, timer_cb, 1000 * 5, 0);
    }
}
//连接断开
void opc_on_close(opc_global* global) {
    //回收
    bridge_delete(global->bridge);
    global->bridge = NULL;
    //重连
    uv_timer_start(&global->timer, timer_cb, 1000 * 5, 0);
}

//启动
static int run(opc_global* global) {
    //初始化
    init_global(global);
    //触发重连
    uv_timer_start(&global->timer, timer_cb, 0, 0);

#ifdef _DEBUG
    //启动定时器
    uv_timer_t timer;
    uv_timer_init(global->loop, &timer);
    uv_timer_start(&timer, obj_check, 5000, 5000);
#endif
    //启动循环
    uv_run(global->loop, UV_RUN_DEFAULT);
    return 0;
}
//win系统服务
#if defined(_WIN32) || defined(_WIN64)
opc_global* _global = NULL;
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

    run(_global);

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
//安卓
#ifdef __ANDROID__
#include <jni.h>

uv_thread_t* android_tid = NULL;

static void android_thr(void* arg) {
    opc_global* global = (opc_global*)malloc(sizeof(opc_global));
    if (global == NULL)
        return;
    memset(global, 0, sizeof(*global));
    global->loop = uv_default_loop();

    run(global);
}



jint JNICALL Java_org_ops_client_MainActivity_init(JNIEnv* env, jobject* this) {
    char* str = "Hello from C++";
    if (android_tid) {
        return -1;
    }
    android_tid = (uv_thread_t*)malloc(sizeof(*android_tid));
    if (uv_thread_create(android_tid, android_thr, NULL) == 0) {
        return 0;
    }
    return -2;
}
#else
//加载配置
static int load_config(opc_global* global, int argc, char* argv[]) {
    //默认参数
    global->config.server_ip = "127.0.0.1";
    global->config.server_port = 8025;
    global->config.use_quic = 0;

    //从配置文件加载参数
    const char* config_file = "opc.json";
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
        cJSON* item = cJSON_GetObjectItem(config_json, "server_ip");
        if (item && item->valuestring) {
            global->config.server_ip = strdup(item->valuestring);
        }
        item = cJSON_GetObjectItem(config_json, "server_port");
        if (item && item->valueint) {
            global->config.server_port = item->valueint;
        }
        item = cJSON_GetObjectItem(config_json, "auth_key");
        if (item && item->valuestring) {
            global->config.auth_key = strdup(item->valuestring);
        }
        item = cJSON_GetObjectItem(config_json, "bind_ip");
        if (item && item->valuestring) {
            global->config.bind_ip = strdup(item->valuestring);
        }
        item = cJSON_GetObjectItem(config_json, "quic");
        if (item && item->valuestring) {
            global->config.use_quic = item->valueint;
        }
        cJSON_free(config_json);
    }
    //从命令行加载参数
    for (size_t i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0) {
            i++;
            global->config.server_ip = strdup(argv[i]);
        }
        else if (strcmp(argv[i], "-b") == 0) {
            i++;
            global->config.bind_ip = strdup(argv[i]);
        }
        else if (strcmp(argv[i], "-p") == 0) {
            i++;
            global->config.server_port = atoi(argv[i]);
        }
        else if (strcmp(argv[i], "-a") == 0) {
            i++;
            global->config.auth_key = strdup(argv[i]);
        }
        else if (strcmp(argv[i], "-c") == 0) {

        }
        else if (strcmp(argv[i], "-i") == 0) {
            char* buf = malloc(500);
            scanf("%s", buf);
            global->config.auth_key = buf;
        }
        else if (strcmp(argv[i], "-q") == 0) {
            global->config.use_quic = 1;
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
    return 0;
}

int main(int argc, char* argv[]) {
    opc_global* global = (opc_global*)malloc(sizeof(opc_global));
    if (global == NULL)
        return 0;
    memset(global, 0, sizeof(*global));
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
    run(global);
    return 0;
}
#endif
