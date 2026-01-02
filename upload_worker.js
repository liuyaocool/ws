// upload-worker.js - Worker线程，纯数据处理
// const socketUrl = `ws://${location.host}/ws-api`;
const socketUrl = `ws://127.0.0.1:8080`;

const FRAME_LEN = 4096, 
    MAX_PART_LEN = FRAME_LEN-14, 
    socket = new WebSocket(socketUrl);
socket.binaryType = 'arraybuffer';

// 1. message - 接收主线程消息（最常用）
self.addEventListener('message', (e) => {
    switch(e.data.type) {
        case "send_file": sendFile(e.data.file); break;
        case "send_text": sendText(e.data.text); break;
        case "socket_close": disconnect(); break;
    }
});

function sendText(text) {
    if (!text || !text.trim())
        return;
    let success = false;
    if (socket && socket.readyState === WebSocket.OPEN) {
        socket.send(text);
        success = true;
    }
    self.postMessage({
        type: 'send_text',
        success: success,
        msg: text
    });
}

function sendFile(file) {
    // (0x34 << 8) | 0x45 
    const id = new Uint8Array(2),
        partSize = MAX_PART_LEN - 4;
    crypto.getRandomValues(id);
    let start = 0, index = 0, blob, fileMeta;
    sendText(JSON.stringify(fileMeta = {
        type: 'file', 
        id: id[0] << 8 | id[1], 
        partCount: Math.trunc(file.size / partSize) + (file.size % partSize > 0 ? 1 : 0),
        size: file.size, 
        name: file.name, 
        ftype: file.type,
    }));
    do {
        socket.send(new Blob([
                new Uint8Array([id[0], id[1], index >> 8, index & 0xff]),
                // [start, end)
                blob = file.slice(start, start + partSize)
            ], {type: 'application/octet-stream'}
        ));
        self.postMessage({
            type: 'progress',
            id: fileMeta.id,
            loaded: start + blob.size,
            total: file.size,
            name: file.name,
        });
        start += partSize;
        index++;
    } while (start < file.size);
}

socket.onopen = function(event) {
    self.postMessage({
        type: 'open',
    });
};

socket.onmessage = function(e) {
    self.postMessage({
        type: 'message',
        data: e.data,
    });
};

socket.onclose = function(event) {
    console.log(event);
    self.postMessage({
        type: 'close',
        wasClean: event.wasClean,
        code: event.code,
        reason: event.reason,
    });
};

socket.onerror = function(error) {
    self.postMessage({
        type: 'error',
        error: error.message,
    });
    console.error('WebSocket错误:', error.message);
};

function disconnect() {
    if (socket) {
        socket.close();
        socket = null;
    }
}


// 2. error - Worker内部错误（同步错误）
self.addEventListener('error', (e) => {});
// 3. unhandledrejection - 未捕获的Promise错误
self.addEventListener('unhandledrejection', (e) => e.preventDefault());
// 4. rejectionhandled - 延迟处理的Promise拒绝
self.addEventListener('rejectionhandled', (e) => {});
// 5. messageerror - 消息反序列化失败
self.addEventListener('messageerror', (e) => {});
// 6. online/offline - 网络状态（部分浏览器支持）
if ('onLine' in self.navigator) {
    self.addEventListener('online', () => {});
    self.addEventListener('offline', () => {});
}
// 7. languagechange - 语言变化
self.addEventListener('languagechange', () => {});
