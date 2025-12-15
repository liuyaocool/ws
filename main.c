#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <asm/socket.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <liburing.h>

#define HALF_SYS_BITS (sizeof(void*) * 4)
#define BUFFER_SIZE 4096
#define UR_CQE_SIZE 128
#define CLIENT_SIZE (128)
#define DATA_SIZE (CLIENT_SIZE * 8) // CLIENT_SIZE = 1+2 的情况
// 此id在ws RFC 6455协议中是硬编码的
#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define IS_CRLF(c) *(c) == '\r' && *(c + 1) == '\n'

struct ucli {
    int fd;
    uint32_t ip;
    uint16_t port;
    // struct sockaddr_in addr; // client addr
    // socklen_t len; // addr len
};
struct udata {
    // struct ucli *cli; // NULL 为可用状态
    uint8_t buf[BUFFER_SIZE];
    int offset;
    int use; // 发送使用统计（给几个用户发送）, -1为可用
    // void *handler;
    void (*handler)(struct io_uring_cqe *, int, int);
};

struct ucli uclis[CLIENT_SIZE];
struct udata udatas[DATA_SIZE]; // 0专为accept
struct io_uring read_ring; // 使用liburing库函数操作可实现线程安全
struct io_uring write_ring;
struct sockaddr_in accept_addr;
socklen_t accept_len = sizeof(accept_addr);
int server_fd = -1;

void init();
void cleanup(int);
int create_websocket(int);
void base64_en(const unsigned char *, size_t, char *);
void submit_accept();
void* uring_handle(void *);

#include "debug.c"

int main(int argc, char const *argv[]) {
    if (argc < 2){
        printf("Usage: %s <port>\n", argv[0]);
        exit(0);
    }
    signal(SIGINT, cleanup); // 2 中断信号 Ctrl+C
    signal(SIGTERM, cleanup); // 15 终止信号 kill或其他程序请求终止
    
    pthread_t write_t;
    int port = atoi(argv[1]), ret;
    server_fd = create_websocket(port);
    
    struct io_uring_params params = {0};
    if ((ret = io_uring_queue_init_params(UR_CQE_SIZE, &read_ring, &params)) < 0) {
        fprintf(stderr, "io_uring 初始化失败: %s\n", strerror(-ret));
        goto err_exit;
    }
    if ((ret = io_uring_queue_init_params(UR_CQE_SIZE, &write_ring, &params)) < 0) {
        fprintf(stderr, "io_uring write 初始化失败: %s\n", strerror(-ret));
        goto err_exit;
    }
    if ((ret = pthread_create(&write_t, NULL, uring_handle, (void *) &write_ring)) != 0) {
        fprintf(stderr, "线程创建失败: %s\n", strerror(ret));
        goto err_exit;
    }

    printf("WebSocket服务运行 http://127.0.0.1:%d\n", port);

    init();

    submit_accept();

    uring_handle((void *) &read_ring);

    return 0;

    err_exit:
    close(server_fd);
    exit(EXIT_FAILURE);
}

void* uring_handle(void *arg) {
    struct io_uring *ring = (struct io_uring *) arg;
    struct io_uring_cqe *cqes[10], *cqe;
    size_t i = 0;
    long data;
    int didx, cidx, ur_ret, count;
    while (-1 != server_fd) {
        // 获取提交队列状态
        if (ring->sq.sqe_tail > ring->sq.sqe_head) {
            // printf("submit %d\n", ring->sq.sqe_tail - ring->sq.sqe_head);
            io_uring_submit(ring); // 系统调用 用户态切换
        }
        ur_ret = io_uring_wait_cqe(ring, &cqe);
        if (ur_ret < 0) {
            if (ur_ret == -EINTR) continue; // 被信号中断
            fprintf(stderr, "io_uring_wait_cqe 失败: %s\n", strerror(-ur_ret));
            break;
        }
        count = io_uring_peek_batch_cqe(ring, cqes, 10);
        for (i = 0; i < count; i++) {
            cqe = cqes[i];
            data = (long)io_uring_cqe_get_data(cqe);
            cidx = data >> HALF_SYS_BITS;
            didx = data << HALF_SYS_BITS >> HALF_SYS_BITS;
            udatas[didx].handler(cqe, cidx, didx);
            // ((void (*)(int, struct io_uring_cqe*))udatas[idx].handler)(idx, cqe);
            // 单个处理
            // io_uring_cqe_seen(&ring, cqe);
        }
        io_uring_cq_advance(ring, count);
    }
}

void init() {
    for (size_t i = 0; i < CLIENT_SIZE; i++) {
        uclis[i].fd = -1;
        // memset(&uclis[i].addr, 0, sizeof(uclis[i].addr));
        // uclis[i].len = sizeof(uclis[i].addr);
    }
    for (size_t i = 1; i < DATA_SIZE; i++)
        udatas[i].use = -1;
}

void cleanup(int sig) {
    printf("\n正在关闭服务器...\n");
    close(server_fd);
    server_fd = -1;
    // exit(sig);
}

int get_cli() {
    for (size_t i = 0; i < CLIENT_SIZE; i++)
        if (uclis[i].fd == -1) {
            uclis[i].fd = 0;
            return i;
        }
    return -1;
}

int get_udata() {
    for (size_t i = 1; i < DATA_SIZE; i++)
        if (udatas[i].use == -1) {
            // !!!!!! 一个fd的read 影响了其他fd， 找了半天才发现 这里是==
            // udatas[i].use == 0;
            udatas[i].use = 0;
            udatas[i].offset = 0;
            return i;
        }
    return -1;
}

void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// 生成 WebSocket 接受密钥
void generate_accept_key(const char* client_key, char* accept_key) {
    char combined[256];
    unsigned char sha1[20];
    
    snprintf(combined, sizeof(combined), "%s%s", client_key, WS_GUID);
    SHA1((unsigned char*)combined, strlen(combined), sha1);
    
    base64_en(sha1, 20, accept_key);
}

void set_data(struct io_uring_sqe* sqe, int cidx, int didx) {
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wshift-count-overflow"
    io_uring_sqe_set_data(sqe, (void*)(long)(((long)cidx) << HALF_SYS_BITS | didx));
    #pragma GCC diagnostic pop
}

void submit_read(int cidx, int didx) {
    struct io_uring_sqe* sqe = io_uring_get_sqe(&read_ring);
    if (!sqe) {
        fprintf(stderr, "无法获取 SQE 用于 read \n");
        return;
    }
    // 或 &udatas[didx].buf[offset]
    io_uring_prep_recv(sqe, uclis[cidx].fd, udatas[didx].buf + udatas[didx].offset, BUFFER_SIZE - udatas[didx].offset, 0);
    set_data(sqe, cidx, didx);
}

void submit_write(struct io_uring * ring, int cidx, int didx, int len) {
    // 获取 SQE
    struct io_uring_sqe* sqe = io_uring_get_sqe(ring);
    if (!sqe) {
        fprintf(stderr, "无法获取 SQE 用于first写操作\n");
        return;
    }
    // 准备写操作
    io_uring_prep_send(sqe, uclis[cidx].fd, udatas[didx].buf, len, 0);
    set_data(sqe, cidx, didx);
}

void submit_close(int cidx, int didx) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&read_ring);
    if (!sqe) {
        fprintf(stderr, "无法获取 SQE 用于 close\n");
        return;
    }
    io_uring_prep_close(sqe, uclis[cidx].fd);
    set_data(sqe, cidx, didx);
}

// write_thread
void handler_write(struct io_uring_cqe *cqe, int cidx, int didx) {
    // printf("handler_write (fd:%d %d:%d)数据长度 %d \n", uclis[cidx].fd, uclis[cidx].ip, uclis[cidx].port, cqe->res);
    if (udatas[didx].use > 0) {
        udatas[didx].use--;
    }
    if (udatas[didx].use == 0) {
        udatas[didx].use = -1;
    }
}

// read_thread
void handler_close(struct io_uring_cqe *cqe, int cidx, int didx) {
    printc(RED, "-------- %d(fd:%d %d:%d)\n", cidx, uclis[cidx].fd, uclis[cidx].ip, uclis[cidx].port);
    close(uclis[cidx].fd);
    uclis[cidx].fd = -1;
    udatas[didx].use = -1;
}

// 解码数据
int de_data(const int didx, size_t len, const int oidx) {
    len += udatas[didx].offset;
    uint8_t *buf = udatas[didx].buf;
    bool masked = (buf[1] & 0x80) != 0;
    size_t header_len = 2;
    uint64_t data_len = buf[1] & 0x7F;
    if (data_len == 126) {
        if (len < 4) goto frame_miss;  // 帧头不完整
        data_len = ((uint64_t)buf[2] << 8) | buf[3];
        header_len = 4;
    } else if (data_len == 127) {
        if (len < 10) goto frame_miss;  // 帧头不完整
        data_len = 0;
        // 注意：只取低 63 位（RFC 规定最高位必须为 0）
        for (int i = 0; i < 8; i++) {
            data_len = (data_len << 8) | buf[2 + i];
        }
        header_len = 10;
    }
    uint8_t mask[4];
    if (masked) {
        if (len < header_len + 4) goto frame_miss; // 帧头不完整
        memcpy(mask, buf + header_len, 4);
        header_len += 4;
    }
    printf("len=%d, header_len=%d data_len=%d \n", len, header_len, data_len);
    if (len < header_len + data_len) goto frame_miss; // 帧不完整
    size_t dest_len = 0;
    uint8_t *dest_data;
    uint8_t *out = udatas[oidx].buf;
    // 第一字节: FIN=1 (0x80) | opcode
    out[0] = 0x80 | (buf[0] & 0x0F);
    // 第二字节: MASK=0 | payload length
    if (data_len <= 125) {
        out[1] = (uint8_t)data_len;
        dest_data = out + 2;
        dest_len = 2 + data_len;
    } else if (data_len <= 65535) {
        out[1] = 126; // 表示接下来 2 字节是长度
        out[2] = (data_len >> 8) & 0xFF;
        out[3] = data_len & 0xFF;
        dest_data = out + 4;
        dest_len = 4 + data_len;
    } else {
        // 注意：RFC 允许 8 字节长度（127），但大多数场景不需要
        // 若需支持 >64KB，可扩展（但浏览器可能不兼容）
        return 0; // 暂不支持超大帧
    }
    uint8_t *data = buf + header_len;

    if (masked) {
        for (size_t i = 0; i < data_len; i++) {
            dest_data[i] = data[i] ^ mask[i % 4];
        }
    } else {
        memcpy(dest_data, data, data_len);
    }

    int this_len = header_len + data_len;
    // 多余的数据留给下次
    if ((udatas[didx].offset = len - this_len) > 0) {
        memmove(buf, buf+this_len, udatas[didx].offset);
    }
    
    // printf("len=%d data = %s\n", data_len, dest_data);
    return dest_len;

    frame_miss:
    udatas[didx].offset = len;
    return 0;

}
// read_thread
void handler_read(struct io_uring_cqe *cqe, int cidx, int didx) {
    uint8_t opcode = udatas[didx].buf[0] & 0xF;
    // 1:最后一帧 0:还有数据未完成
    // 因为我每次都是发送完整的帧， 且完整的帧都是在buffer范围内的, 所以fin总是1
    // bool fin = (udatas[didx].buf[0] & 0x80) != 0;
    // printf(">>>>>> fd=%d len=%d fin=%d opcode=%d\n", uclis[cidx].fd, cqe->res, fin, opcode);
    if (cqe->res <= 0 || 8 == opcode){
        udatas[didx].handler = handler_close;
        submit_close(cidx, didx);
        return;
    }
    int send_idx = get_udata();
    int send_len = de_data(didx, cqe->res, send_idx);
    // switch (opcode) {
    //     case 0: break; // 继续帧 数据分片 浏览器不会传
    //     case 1: break; // 文本帧
    //     case 2: break; // 二进制帧
    //     case 8: return; // 关闭帧
    //     case 9: break; // ping
    //     case 10: break; // pong
    //     default: break;
    // }
    if (send_len > 0) {
        udatas[send_idx].use = 0;
        udatas[send_idx].handler = handler_write;
        for (size_t i = 0; i < CLIENT_SIZE; i++) {
            if (uclis[i].fd >= 0 && uclis[i].fd != uclis[cidx].fd) {
                printc(BLUE, ">>>>>>>> write to %d %d, len %d -----\n", i, uclis[i].fd, send_len);
                udatas[send_idx].use++;
                submit_write(&write_ring, i, send_idx, send_len);
            }
        }
        io_uring_submit(&write_ring);
    } else {
        udatas[send_idx].use = -1;
        printf("...... fd=%d op=%d len=%d send_len=%d 收到数据不完整: %d\n", 
            uclis[cidx].fd, opcode, udatas[didx].buf[1] & 0x7F, send_len, cqe->res);
    }
    submit_read(cidx, didx);
}

void handler_first_write(struct io_uring_cqe *cqe, int cidx, int didx) {
    print_first_write(cidx);
    int bytes_sent = cqe->res;
    udatas[didx].handler = handler_read;
    submit_read(cidx, didx);
}

void handler_first_read(struct io_uring_cqe *cqe, int cidx, int didx) {
    int len = cqe->res;
    if (!IS_CRLF(udatas[didx].buf + len-4) || !IS_CRLF(udatas[didx].buf + len-2)) {
        printf("非完整数据: %s\n", udatas[didx].buf);
        return;
    }
    if (!strstr((char *)udatas[didx].buf, "Upgrade: websocket")) {
        printf("非ws请求: %s\n", udatas[didx].buf);
        return;
    }
    char* key_start = strstr((char *)udatas[didx].buf, "Sec-WebSocket-Key: ");
    // key 长度固定24
    if (!key_start || !IS_CRLF(key_start+19+24)) {
        printf("Sec-WebSocket-Key 头出错: %s\n", udatas[didx].buf);
        return;
    }
    char client_key[25], accept_key[29];
    strncpy(client_key, key_start+19, 24);
    client_key[24] = '\0';
    generate_accept_key(client_key, accept_key);
    
    memcpy(udatas[didx].buf, 
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: ", 
        97);
    memcpy(udatas[didx].buf + 97, accept_key, 28);
    memcpy(udatas[didx].buf + 97 + 28, "\r\n\r\n", 4);
    udatas[didx].handler = handler_first_write;

    submit_write(&read_ring, cidx, didx, 97+28+4);
}

void handler_accept(struct io_uring_cqe *cqe, int cidx, int didx) {
    int fd;
    if ((fd = cqe->res) >= 0) {
        cidx = get_cli();
        uclis[cidx].fd = fd;
        uclis[cidx].ip = accept_addr.sin_addr.s_addr;
        uclis[cidx].port = accept_addr.sin_port;
        didx = get_udata();
        udatas[didx].handler = handler_first_read;
        set_nonblocking(fd);
        submit_read(cidx, didx);
    }
    submit_accept();
}

void submit_accept() {
    struct io_uring_sqe* sqe = io_uring_get_sqe(&read_ring);
    if (!sqe) {
        fprintf(stderr, "无法获取 SQE 用于 accept \n");
        return;
    }
    udatas[0].handler = handler_accept;
    // io_uring_prep_accept(sqe, server_fd, (struct sockaddr*)&uclis[cidx].addr, &uclis[cidx].len, 0);
    io_uring_prep_accept(sqe, server_fd, (struct sockaddr*)&accept_addr, &accept_len, 0);
    io_uring_sqe_set_data(sqe, (void*)(long)0);
}

int create_websocket(int port) {
    struct sockaddr_in addr;
    int fd, opt = 1;
    // 创建 socket
    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
    // bind 时复用处于 TIME_WAIT 状态的本地地址（IP + 端口）， 简单点说就是快速重启不会报错
    // 不要加 SO_REUSEPORT， 会导致多个进程可绑定同一个端口
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt failed");
        goto err_over;
    }
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind failed");
        goto err_over;
    }
    if (listen(fd, 10) < 0) {
        perror("listen failed");
        goto err_over;        
    }
    return fd;

    err_over:
    shutdown(fd, SHUT_RDWR);
    exit(EXIT_FAILURE);
}

void base64_en(const unsigned char *data, size_t input_length, char *encoded_data) {
    // Base64 编码表
    const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    // 计算输出长度 (每3字节输入对应4字节输出)
    size_t output_len = 4 * ((input_length + 2) / 3);
    // 编码过程
    for (size_t i = 0, j = 0; i < input_length;) {
        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;
        // 将3个字节组合成24位
        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;
        // 将24位分成4个6位组，并编码
        encoded_data[j++] = base64_table[(triple >> 18) & 0x3F];
        encoded_data[j++] = base64_table[(triple >> 12) & 0x3F];
        encoded_data[j++] = base64_table[(triple >> 6)  & 0x3F];
        encoded_data[j++] = base64_table[triple & 0x3F];
    }
    // 添加 padding
    switch (input_length % 3) {
        case 1:
            encoded_data[output_len - 1] = '=';
            encoded_data[output_len - 2] = '=';
            break;
        case 2:
            encoded_data[output_len - 1] = '=';
            break;
    }
    encoded_data[output_len] = '\0';
}
