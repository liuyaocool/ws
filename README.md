# 线程模型

- ThreadMain: accept+read
- Thread1: write

# 函数流程

submit_accept (server_fd, addr)
-> handler_accept
    submit_read (cli_fd, cli_buf)
-> handler_first_read
    submit_first_write (cli_fd, cli_buf)
-> handler_first_write
    submit_read  (cli_fd, cli_buf)
-> handler_read
    submit_write * n (cli_fd *n, data_buf *1) ------------Thread1
    submit_read (cli_fd, cli_buf)

# server run

```bash
# compile
make
# run
./bin/main 8081
```

# browser connect

```javascript
new WebSocket("ws://127.0.0.1/ws-api");
```