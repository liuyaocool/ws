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

void printc_start(Color color) {
    printf("\033[%dm", color);
}

void printc_end() {
    printf("\033[0m");  // 重置
}

// 带换行版本
void printc(Color color, const char* format, ...) {
    printc_start(color);
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    printc_end();
}