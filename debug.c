#include <stdarg.h>

// 方法1：基础颜色枚举
typedef enum {
    RESET = 0,          // 重置
    BLACK = 30,         // 黑色
    RED,                // 红色 (31)
    GREEN,              // 绿色 (32)
    YELLOW,             // 黄色 (33)
    BLUE,               // 蓝色 (34)
    MAGENTA,            // 品红 (35)
    CYAN,               // 青色 (36)
    WHITE,              // 白色 (37)
    BRIGHT_BLACK = 90,  // 亮黑
    BRIGHT_RED,         // 亮红 (91)
    BRIGHT_GREEN,       // 亮绿 (92)
    BRIGHT_YELLOW,      // 亮黄 (93)
    BRIGHT_BLUE,        // 亮蓝 (94)
    BRIGHT_MAGENTA,     // 亮品红 (95)
    BRIGHT_CYAN,        // 亮青 (96)
    BRIGHT_WHITE,       // 亮白 (97)
} Color;

// 带换行版本
void printc(Color color, const char* format, ...) {
    printf("\033[%dm", color);
    
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    
    printf("\033[0m");  // 重置
}

void print_first_write(int cidx) {
    printf("\033[%dm", GREEN);
    printf("++++++++ client-%d(fd=%d) connect: %s:%d （", cidx, uclis[cidx].fd, 
        inet_ntoa((struct in_addr){.s_addr = uclis[cidx].ip}), uclis[cidx].port);
    for (size_t i = 0; i < CLIENT_SIZE; i++)
        if (uclis[i].fd != -1)
            printf("%d=%d ", i, uclis[i].fd);
    printf("）\033[0m\n");
}