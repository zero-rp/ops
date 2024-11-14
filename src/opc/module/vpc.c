#include <stdint.h>
#include <stdlib.h>
#include <uv.h>
#include <uv/tree.h>
#include <common/obj.h>
#include "vpc.h"

//VPC
typedef struct _opc_vpc {
    RB_ENTRY(_opc_vpc) entry;                       //
    obj_field ref;                                        //计数
    uint32_t id;                                    //成员id
    uint16_t vid;                                   //
    struct in_addr ipv4;                            //ipv4地址
    struct in_addr ipv4_mask;                       //ipv4掩码
    uint8_t prefix_v4;                              //ipv4前缀
    struct in6_addr ipv6;                           //ipv6地址
    struct in6_addr ipv6_mask;                      //ipv6掩码
    uint8_t prefix_v6;                              //ipv6前缀
    void* data;                                     //接口数据
    struct _module_vpc* mod;
}opc_vpc;
RB_HEAD(_opc_vpc_tree, _opc_vpc);

typedef struct _module_vpc {
    opc_module mod;
    obj_field ref;                                        //计数
    opc_bridge* bridge;
    struct _opc_vpc_tree vpc;
}module_vpc;

static int _opc_vpc_compare(opc_vpc* w1, opc_vpc* w2) {
    if (w1->id < w2->id) return -1;
    if (w1->id > w2->id) return 1;
    return 0;
}
RB_GENERATE_STATIC(_opc_vpc_tree, _opc_vpc, entry, _opc_vpc_compare)


static void vpc_on_packet(opc_vpc* vpc, uint8_t* packet, int size);
static void cidr_to_netmask_v4(int prefix, struct in_addr* netmask) {
    netmask->s_addr = htonl(~((1 << (32 - prefix)) - 1));
}
static void cidr_to_netmask_v6(int prefix, struct in6_addr* netmask) {
    for (int i = 0; i < 16; i++) {
        if (prefix > 8) {
            netmask->s6_addr[i] = 0xFF;
            prefix -= 8;
        }
        else {
            netmask->s6_addr[i] = (0xFF << (8 - prefix)) & 0xFF;
            prefix = 0;
        }
    }
}
static uint16_t ip_checksum(uint8_t* buf, int len) {
    uint32_t sum = 0;
    for (; len > 1; len -= 2, buf += 2)
        sum += *(uint16_t*)buf;
    if (len)
        sum += *buf;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

#if defined(_WIN32) || defined(_WIN64)
#include <iphlpapi.h>
#include "wintun.h"

static WINTUN_CREATE_ADAPTER_FUNC* WintunCreateAdapter;
static WINTUN_CLOSE_ADAPTER_FUNC* WintunCloseAdapter;
static WINTUN_OPEN_ADAPTER_FUNC* WintunOpenAdapter;
static WINTUN_GET_ADAPTER_LUID_FUNC* WintunGetAdapterLUID;
static WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC* WintunGetRunningDriverVersion;
static WINTUN_DELETE_DRIVER_FUNC* WintunDeleteDriver;
static WINTUN_SET_LOGGER_FUNC* WintunSetLogger;
static WINTUN_START_SESSION_FUNC* WintunStartSession;
static WINTUN_END_SESSION_FUNC* WintunEndSession;
static WINTUN_GET_READ_WAIT_EVENT_FUNC* WintunGetReadWaitEvent;
static WINTUN_RECEIVE_PACKET_FUNC* WintunReceivePacket;
static WINTUN_RELEASE_RECEIVE_PACKET_FUNC* WintunReleaseReceivePacket;
static WINTUN_ALLOCATE_SEND_PACKET_FUNC* WintunAllocateSendPacket;
static WINTUN_SEND_PACKET_FUNC* WintunSendPacket;

static HMODULE InitializeWintun(void) {
    HMODULE Wintun =
        LoadLibraryA("wintun.dll");
    if (!Wintun)
        return NULL;
#define X(Name) ((*(FARPROC *)&Name = GetProcAddress(Wintun, #Name)) == NULL)
    if (X(WintunCreateAdapter) || X(WintunCloseAdapter) || X(WintunOpenAdapter) || X(WintunGetAdapterLUID) ||
        X(WintunGetRunningDriverVersion) || X(WintunDeleteDriver) || X(WintunSetLogger) || X(WintunStartSession) ||
        X(WintunEndSession) || X(WintunGetReadWaitEvent) || X(WintunReceivePacket) || X(WintunReleaseReceivePacket) ||
        X(WintunAllocateSendPacket) || X(WintunSendPacket))
#undef X
    {
        DWORD LastError = GetLastError();
        FreeLibrary(Wintun);
        SetLastError(LastError);
        return NULL;
    }
    return Wintun;
}

typedef void* QUEUE[2];

typedef struct _win_tun_packet {
    QUEUE wq;                    //队列
    int size;
    uint8_t data[0];
}win_tun_packet;

typedef struct _win_tun {
    WINTUN_ADAPTER_HANDLE Adapter;  //网卡
    WINTUN_SESSION_HANDLE Session;  //会话
    HANDLE Thread;                  //线程
    HANDLE QuitEvent;               //退出事件
    int HaveQuit;
    uv_async_t async;               //同步对象
    QUEUE wq;                       //队列
    int write;                      //锁
    int read;
    struct in_addr ipv4;                        //ipv4地址
    struct in_addr ipv4_mask;                   //ipv4掩码
    struct in_addr6 ipv6;                       //ipv6地址
    struct in_addr6 ipv6_mask;                  //ipv6掩码
    opc_vpc* vpc;
}win_tun;

static inline void rwlock_rlock(win_tun* lock) {
    for (;;) {
        while (lock->write) {
            _mm_mfence();
        }
        InterlockedExchangeAdd(&lock->read, 1);
        if (lock->write) {
            InterlockedExchangeAdd(&lock->read, -1);
        }
        else {
            break;
        }
    }
}
static inline void rwlock_wlock(win_tun* lock) {
    while (InterlockedExchange(&lock->write, 1)) {}
    while (lock->read) {
        _mm_mfence();
    }
}
static inline void rwlock_wunlock(win_tun* lock) {
    InterlockedExchange(&lock->write, 0);
}
static inline void rwlock_runlock(win_tun* lock) {
    InterlockedExchangeAdd(&lock->read, -1);
}

#define QUEUE_NEXT(q)       (*(QUEUE **) &((*(q))[0]))
#define QUEUE_PREV(q)       (*(QUEUE **) &((*(q))[1]))
#define QUEUE_PREV_NEXT(q)  (QUEUE_NEXT(QUEUE_PREV(q)))
#define QUEUE_NEXT_PREV(q)  (QUEUE_PREV(QUEUE_NEXT(q)))

#define QUEUE_INSERT_TAIL(h, q)                                               \
  do {                                                                        \
    QUEUE_NEXT(q) = (h);                                                      \
    QUEUE_PREV(q) = QUEUE_PREV(h);                                            \
    QUEUE_PREV_NEXT(q) = (q);                                                 \
    QUEUE_PREV(h) = (q);                                                      \
  }                                                                           \
  while (0)
#define QUEUE_EMPTY(q)                                                        \
  ((const QUEUE *) (q) == (const QUEUE *) QUEUE_NEXT(q))
#define QUEUE_HEAD(q)                                                         \
  (QUEUE_NEXT(q))
#define QUEUE_REMOVE(q)                                                       \
  do {                                                                        \
    QUEUE_PREV_NEXT(q) = QUEUE_NEXT(q);                                       \
    QUEUE_NEXT_PREV(q) = QUEUE_PREV(q);                                       \
  }                                                                           \
  while (0)
#define QUEUE_DATA(ptr, type, field)                                          \
  ((type *) ((char *) (ptr) - offsetof(type, field)))
#define QUEUE_INIT(q)                                                         \
  do {                                                                        \
    QUEUE_NEXT(q) = (q);                                                      \
    QUEUE_PREV(q) = (q);                                                      \
  }                                                                           \
  while (0)
//接口数据
static DWORD WINAPI ReceivePackets(_Inout_ DWORD_PTR Ptr) {
    win_tun* tun = (win_tun*)Ptr;
    HANDLE WaitHandles[] = { WintunGetReadWaitEvent(tun->Session), tun->QuitEvent };
    while (!tun->HaveQuit) {
        DWORD PacketSize;
        BYTE* Packet = WintunReceivePacket(tun->Session, &PacketSize);
        if (Packet) {
            //过滤
            uint8_t ip_version = Packet[0] >> 4;
            if (PacketSize < 20) {
                goto end;
            }
            if (ip_version == 4) {
                //目标为自身IP和广播IP不转发
                if ((*(uint32_t*)(&tun->ipv4) == *(uint32_t*)(&Packet[16])) || Packet[19] == 0xff) {
                    goto end;
                }
            }
            else if (ip_version == 6 && PacketSize >= 40) {

            }
            else {
                goto end;
            }
            //发给自己的

            //写入
            win_tun_packet* packet = malloc(sizeof(win_tun_packet) + PacketSize);
            if (packet) {
                memset(packet, 0, sizeof(*packet));
                packet->size = PacketSize;
                memcpy(&packet->data, Packet, PacketSize);
                rwlock_wlock(tun);
                QUEUE_INSERT_TAIL(&tun->wq, &packet->wq);
                rwlock_wunlock(tun);
                uv_async_send(&tun->async);
            }
        end:
            WintunReleaseReceivePacket(tun->Session, Packet);
        }
        else {
            DWORD LastError = GetLastError();
            switch (LastError)
            {
            case ERROR_NO_MORE_ITEMS:
                if (WaitForMultipleObjects(_countof(WaitHandles), WaitHandles, FALSE, INFINITE) == WAIT_OBJECT_0)
                    continue;
                return ERROR_SUCCESS;
            default:
                return LastError;
            }
        }
    }
    return ERROR_SUCCESS;
}

static void win_tun_async_cb(uv_async_t* handle) {
    win_tun* tun = (win_tun*)handle->data;
    while (1) {
        rwlock_rlock(tun);
        if (QUEUE_EMPTY(&tun->wq)) {
            rwlock_runlock(tun);
            break;
        }
        QUEUE* wq = QUEUE_HEAD(&tun->wq);
        QUEUE_REMOVE(wq);
        rwlock_runlock(tun);
        win_tun_packet* packet = QUEUE_DATA(wq, win_tun_packet, wq);
        vpc_on_packet(tun->vpc, packet->data, packet->size);
        free(packet);
    }
}
static HMODULE tun_mod;                    //动态库
//创建
static win_tun* new_tun(opc_vpc* vpc) {
    win_tun* tun = malloc(sizeof(*tun));
    if (!tun) {
        return NULL;
    }
    memset(tun, 0, sizeof(*tun));
    //加载模块
    if (!tun_mod) {
        tun_mod = InitializeWintun();
        if (!tun_mod) {
            free(tun);
            return NULL;
        }
    }
    //创建网卡
    GUID Guid = { vpc->id, 0xcafe, 0xbeef, { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef } };
    wchar_t name[256] = { 0 };
    _snwprintf(name, sizeof(name), L"opc %d", vpc->id);
    tun->Adapter = WintunCreateAdapter(name, L"opc", &Guid);
    if (!tun->Adapter) {
        free(tun);
        return NULL;
    }
    //设置IPv4
    MIB_UNICASTIPADDRESS_ROW AddressRow;
    InitializeUnicastIpAddressEntry(&AddressRow);
    WintunGetAdapterLUID(tun->Adapter, &AddressRow.InterfaceLuid);
    AddressRow.Address.Ipv4.sin_family = AF_INET;
    memcpy(&AddressRow.Address.Ipv4.sin_addr, &vpc->ipv4, sizeof(AddressRow.Address.Ipv4.sin_addr));
    AddressRow.OnLinkPrefixLength = vpc->prefix_v4;
    AddressRow.DadState = IpDadStatePreferred;
    int LastError = CreateUnicastIpAddressEntry(&AddressRow);
    if (LastError != ERROR_SUCCESS && LastError != ERROR_OBJECT_ALREADY_EXISTS) {
        WintunCloseAdapter(tun->Adapter);
        free(tun);
        return NULL;
    }
    memcpy(&tun->ipv4, &vpc->ipv4, sizeof(tun->ipv4));
    memcpy(&tun->ipv4_mask, &vpc->ipv4_mask, sizeof(tun->ipv4_mask));
    //设置IPv6
    memset(&AddressRow, 0, sizeof(AddressRow));
    InitializeUnicastIpAddressEntry(&AddressRow);
    WintunGetAdapterLUID(tun->Adapter, &AddressRow.InterfaceLuid);
    AddressRow.Address.Ipv6.sin6_family = AF_INET6;
    memcpy(&AddressRow.Address.Ipv6.sin6_addr, &vpc->ipv6, sizeof(AddressRow.Address.Ipv6.sin6_addr));
    AddressRow.OnLinkPrefixLength = vpc->prefix_v6;
    AddressRow.DadState = IpDadStatePreferred;
    LastError = CreateUnicastIpAddressEntry(&AddressRow);
    if (LastError != ERROR_SUCCESS && LastError != ERROR_OBJECT_ALREADY_EXISTS) {
        WintunCloseAdapter(tun->Adapter);
        free(tun);
        return NULL;
    }
    memcpy(&tun->ipv6, &vpc->ipv6, sizeof(tun->ipv6));
    memcpy(&tun->ipv6_mask, &vpc->ipv6_mask, sizeof(tun->ipv6_mask));
    //
    tun->vpc = obj_ref(vpc); //ref_24
    //创建同步对象
    tun->async.data = tun;
    uv_async_init(bridge_loop(vpc->mod->bridge), &tun->async, win_tun_async_cb);
    QUEUE_INIT(&tun->wq);
    //启动会话
    tun->Session = WintunStartSession(tun->Adapter, 0x400000);
    tun->QuitEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    //创建接收线程
    tun->Thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ReceivePackets, (LPVOID)tun, 0, NULL);
    return tun;
}
//
static void tun_close_cb(uv_handle_t* handle) {
    win_tun* tun = (win_tun*)handle->data;
    //等待线程退出
    if (tun->Thread) {
        WaitForSingleObject(tun->Thread, INFINITE);
        CloseHandle(tun->Thread);
    }
    //回收队列
    while (1) {
        if (QUEUE_EMPTY(&tun->wq)) {
            break;
        }
        QUEUE* wq = QUEUE_HEAD(&tun->wq);
        QUEUE_REMOVE(wq);
        win_tun_packet* packet = QUEUE_DATA(wq, win_tun_packet, wq);
        free(packet);
    }
    if (tun->Session) {
        WintunEndSession(tun->Session);
    }
    if (tun->Adapter) {
        WintunCloseAdapter(tun->Adapter);
    }
    if (tun->QuitEvent) {
        CloseHandle(tun->QuitEvent);
    }
    obj_unref(tun->vpc);//ref_24
    free(tun);
}
//关闭
static void delete_tun(win_tun* tun) {
    //关闭异步对象
    uv_close(&tun->async, tun_close_cb);
    //通知线程退出
    tun->HaveQuit = TRUE;
    SetEvent(tun->QuitEvent);
}
//往接口发送数据
static void send_tun(opc_vpc* vpc, const char* data, int size) {
    win_tun* tun = vpc->data;
    BYTE* Packet = WintunAllocateSendPacket(tun->Session, size);
    if (Packet) {
        memcpy(Packet, data, size);
        WintunSendPacket(tun->Session, Packet);
    }
}
#else

#include <linux/if_tun.h>
#include <net/if.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>


typedef struct _linux_tun {
    uv_tcp_t tcp;
    int fd;
    struct in_addr ipv4;                        //ipv4地址
    struct in_addr ipv4_mask;                   //ipv4掩码
    struct in6_addr ipv6;                       //ipv6地址
    struct in6_addr ipv6_mask;                   //ipv4掩码
    opc_vpc* vpc;
}linux_tun;
static void alloc_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    buf->len = suggested_size;
    buf->base = malloc(suggested_size);
}
static void write_cb(uv_write_t* req, int status) {
    free(req->data);
}
static void tun_read_cb(uv_stream_t* tcp, ssize_t nread, const uv_buf_t* buf) {
    linux_tun* tun = (linux_tun*)tcp->data;
    if (nread <= 0) {
        if (UV_EOF != nread) {
            //连接异常断开

        }
        else {
            //shutdown

        }
        return;
    }
    uint8_t* packet = buf->base;

    //过滤
    uint8_t ip_version = packet[0] >> 4;
    if (nread < 20) {
        goto end;
    }
    if (ip_version == 4) {
        //目标为自身IP和广播IP不转发
        if ((*(uint32_t*)(&tun->ipv4) == *(uint32_t*)(&packet[16])) || packet[19] == 0xff) {
            goto end;
        }
    }
    else if (ip_version == 6 && nread >= 40) {

    }
    else {
        goto end;
    }
    vpc_on_packet(tun->vpc, packet, nread);
end:
    free(buf->base);
}
//创建
static linux_tun* new_tun(opc_vpc* vpc) {
    linux_tun* tun = malloc(sizeof(*tun));
    if (!tun) {
        return NULL;
    }
    memset(tun, 0, sizeof(*tun));
    tun->vpc = obj_ref(vpc);//ref_25

    if ((tun->fd = open("/dev/net/tun", O_RDWR)) < 0) {
        free(tun);
        return  NULL;
    }

    int flags = fcntl(tun->fd, F_GETFL);
    fcntl(tun->fd, F_SETFL, flags | O_NONBLOCK);

    char dev[256] = { 0 };
    snprintf(dev, sizeof(dev), "opc%d", tun->vpc->id);
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, dev);

    // 获得网络接口的flag
    ifr.ifr_flags |= IFF_TUN | IFF_NO_PI;

    // 设置网络结构的参数
    ioctl(tun->fd, TUNSETIFF, (void*)&ifr);

    struct sockaddr_in addr;
    int sockfd, err = -1;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    memcpy(&addr.sin_addr, &vpc->ipv4, sizeof(addr.sin_addr));

    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, dev);
    memcpy(&ifr.ifr_addr, &addr, sizeof(addr));

    //设定ip地址
    if ((err = ioctl(sockfd, SIOCSIFADDR, (void*)&ifr)) < 0) {
        perror("ioctl SIOSIFADDR");
        goto done;
    }

    /* 获得接口的标志 */
    if ((err = ioctl(sockfd, SIOCGIFFLAGS, (void*)&ifr)) < 0) {
        perror("ioctl SIOCGIFADDR");
        goto done;
    }
    /* 设置接口的标志 */
    ifr.ifr_flags |= IFF_UP;
    // ifup tap0 #启动设备
    if ((err = ioctl(sockfd, SIOCSIFFLAGS, (void*)&ifr)) < 0) {
        perror("ioctl SIOCSIFFLAGS");
        goto done;
    }
    //设定子网掩码
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    memcpy(&addr.sin_addr, &vpc->ipv4_mask, sizeof(addr.sin_addr));
    memcpy(&ifr.ifr_netmask, &addr, sizeof(addr));
    if ((err = ioctl(sockfd, SIOCSIFNETMASK, (void*)&ifr)) < 0) {
        perror("ioctl SIOCSIFNETMASK");
        goto done;
    }

    memcpy(&tun->ipv4, &vpc->ipv4, sizeof(tun->ipv4));
    memcpy(&tun->ipv4_mask, &vpc->ipv4_mask, sizeof(tun->ipv4_mask));



    memcpy(&tun->ipv6, &vpc->ipv6, sizeof(tun->ipv6));
    memcpy(&tun->ipv6_mask, &vpc->ipv6_mask, sizeof(tun->ipv6_mask));

done:
    close(sockfd);

    uv_tcp_init(bridge_loop(vpc->mod->bridge), &tun->tcp);
    tun->tcp.data = tun;
    uv_tcp_open(&tun->tcp, tun->fd);
    uv_read_start((uv_stream_t*)&tun->tcp, alloc_buffer, tun_read_cb);
    return tun;
}
static void tun_close_cb(uv_handle_t* handle) {
    linux_tun* tun = (linux_tun*)handle->data;
    obj_unref(tun->vpc);//ref_25
    free(tun);
}
//关闭
static void delete_tun(linux_tun* tun) {
    uv_close(&tun->tcp, tun_close_cb);
}
//往接口发送数据
static void send_tun(opc_vpc* vpc, const char* data, int size) {
    linux_tun* tun = (linux_tun*)(vpc->data);
    uv_buf_t buf[] = { 0 };
    buf->len = size;
    buf->base = malloc(buf->len);
    if (buf->base == NULL) {
        return;
    }
    memcpy(buf->base, data, size);
    uv_write_t* req = (uv_write_t*)malloc(sizeof(uv_write_t));
    if (req == NULL) {
        free(buf->base);
        return;
    }
    req->data = buf->base;
    uv_write(req, &tun->tcp, &buf, 1, write_cb);
}
#endif

//收到接口数据包
static void vpc_on_packet(opc_vpc* vpc, uint8_t* packet, int size) {
    //发送数据
    bridge_send_mod(vpc->mod->bridge, MODULE_VPC, vpc_packet_data, vpc->vid, vpc->id, packet, size);
}
//
static void vpc_obj_free(opc_vpc* p) {
    RB_REMOVE(_opc_vpc_tree, &p->mod->vpc, p);
    obj_unref(p->mod);//ref_22
}
//删除vpc
static void vpc_del(opc_vpc* vpc) {
    if (vpc->data) {
        delete_tun(vpc->data);
    }
    obj_unref(vpc);//ref_21
}
static void _vpc(module_vpc* mod, uint32_t stream_id, uint32_t service_id, uint8_t* data, int size) {
    uint8_t ctl = data[0];
    char* pos = &data[1];
    switch (ctl)
    {
    case CTL_MEMBER_ADD: {
        int count = ntohl(*(uint32_t*)pos);
        pos += 4;
        for (size_t i = 0; i < count; i++) {
            ops_member mem;
            memcpy(&mem, pos, sizeof(mem));
            pos += sizeof(mem);
            mem.id = ntohl(mem.id);
            mem.vid = ntohs(mem.vid);

            obj_new(vpc, opc_vpc);//ref_21
            if (!vpc) {
                continue;
            }
            vpc->ref.del = vpc_obj_free;
            vpc->mod = obj_ref(mod);//ref_22
            vpc->id = mem.id;
            vpc->vid = mem.vid;

            memcpy(&vpc->ipv4, &mem.ipv4, sizeof(vpc->ipv4));
            vpc->prefix_v4 = mem.prefix_v4;
            cidr_to_netmask_v4(mem.prefix_v4, &vpc->ipv4_mask);

            memcpy(&vpc->ipv6, &mem.ipv6, sizeof(vpc->ipv6));
            vpc->prefix_v6 = mem.prefix_v6;
            cidr_to_netmask_v6(mem.prefix_v6, &vpc->ipv6_mask);

            //创建接口
            vpc->data = new_tun(vpc);
            //记录
            RB_INSERT(_opc_vpc_tree, &mod->vpc, vpc);
        }
        break;
    }
    case CTL_MEMBER_DEL: {
        uint32_t id = ntohl(*(uint32_t*)pos);
        opc_vpc the = {
            .id = id
        };
        opc_vpc* vpc = RB_FIND(_opc_vpc_tree, &mod->vpc, &the);
        if (vpc) {
            vpc_del(vpc);
        }
        break;
    }
    default:
        break;
    }
}
static void _data(module_vpc* mod, uint32_t stream_id, uint32_t service_id, uint8_t* data, int size) {
    opc_vpc the = {
        .id = stream_id
    };
    opc_vpc* vpc = RB_FIND(_opc_vpc_tree, &mod->vpc, &the);
    if (!vpc) {
        return;
    }
    //处理icmp,ping命令
    uint8_t ip_version = data[0] >> 4;
    if (ip_version == 4 && data[9] == 1 && data[20] == 8) {
        //修改目标地址
        uint8_t tmp[4];
        memcpy(tmp, &data[12], 4);
        memcpy(&data[12], &data[16], 4);
        memcpy(&data[16], tmp, 4);
        *(uint16_t*)&data[10] = 0;//清零
        *(uint16_t*)&data[10] = ip_checksum(data, 20);
        data[20] = 0;//ping 应答
        *(uint16_t*)&data[22] = 0;//清零
        *(uint16_t*)&data[22] = ip_checksum(&data[20], size - 20);
        bridge_send_mod(mod->bridge, MODULE_VPC, vpc_packet_data, vpc->vid, vpc->id, data, size);
        return;
    }
    else if (ip_version == 6 && data[6] == 1 && data[40] == 8) {
        //修改目标地址
        uint8_t tmp[16];
        memcpy(tmp, &data[8], 16);
        memcpy(&data[8], &data[24], 16);
        memcpy(&data[24], tmp, 16);
        data[40] = 0;//ping 应答
        *(uint16_t*)&data[42] = 0;//清零
        *(uint16_t*)&data[42] = ip_checksum(&data[40], size - 40);
        bridge_send_mod(mod->bridge, MODULE_VPC, vpc_packet_data, vpc->vid, vpc->id, data, size);
        return;
    }
    send_tun(vpc, data, size);
}

//处理数据
static void vpc_data(module_vpc* mod, uint8_t type, uint32_t stream_id, uint32_t service_id, uint8_t* data, int size) {
    switch (type)
    {
    case vpc_packet_vpc:
        _vpc(mod, stream_id, service_id, data, size);
        break;
    case vpc_packet_data:
        _data(mod, stream_id, service_id, data, size);
        break;
    default:
        break;
    }
}
//创建目标模块
module_vpc* vpc_module_new(opc_bridge* bridge) {
    obj_new(mod, module_vpc);
    if (!mod) {
        return NULL;
    }
    mod->bridge = bridge_ref(bridge);
    mod->mod.on_data = (opc_module_on_data)vpc_data;
    RB_INIT(&mod->vpc);
    return mod;
}
//回收资源
void vpc_module_delete(module_vpc* mod) {
    opc_vpc* c = NULL;
    opc_vpc* cc = NULL;
    RB_FOREACH_SAFE(c, _opc_vpc_tree, &mod->vpc, cc) {
        vpc_del(c);
        cc = NULL;
    }
}
