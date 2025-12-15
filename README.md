# 函数流程

submit_accept 
-> handler_accept
    submit_first_read
-> handler_first_read
    submit_first_write
-> handler_first_write
    submit_read
-> handler_read
    submit_write * n
    submit_read

# server run

```bash
# compile
make
# run
./bin/main 8081
```

# browser connect

```javascript
new WebSocket("ws://127.0.0.1:8081");
```