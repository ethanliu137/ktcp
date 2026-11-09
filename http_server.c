//#include <stdio.h>
//#include <sys/types.h>
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/completion.h>
#include <linux/fs.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/tcp.h>
#include <linux/version.h>
#include <linux/workqueue.h>
#include <linux/string.h>
#include <linux/mempool.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/spinlock.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 17, 0)
#define kthread_complete_and_exit(comp, code) complete_and_exit(comp, code)
#endif

#include "http_parser.h"
#include "http_server.h"

#define SEND_BUFFER_SIZE 256  // 設定傳出去的大小(snprintf)
#define PATH_SIZE 256         // 存放檔案路徑 array 大小
#define CRLF "\r\n"

// http compress
#define COMPRESS_ALGORITHM "deflate"

// 建立 hash table 
DEFINE_HASHTABLE(ht, 8); // 建立 256(2^8) 個 bucket，以利快速搜尋
spinlock_t hash_lock; // 建立 spinlock，避免同時寫入 hash table

#define HTTP_RESPONSE_200_DUMMY                               \
    ""                                                        \
    "HTTP/1.1 200 OK" CRLF "Server: " KBUILD_MODNAME CRLF     \
    "Content-Type: text/plain" CRLF "Content-Length: 12" CRLF \
    "Connection: Close" CRLF CRLF "Hello World!" CRLF
#define HTTP_RESPONSE_200_KEEPALIVE_DUMMY                     \
    ""                                                        \
    "HTTP/1.1 200 OK" CRLF "Server: " KBUILD_MODNAME CRLF     \
    "Content-Type: text/plain" CRLF "Content-Length: 12" CRLF \
    "Connection: Keep-Alive" CRLF CRLF "Hello World!" CRLF
#define HTTP_RESPONSE_501                                              \
    ""                                                                 \
    "HTTP/1.1 501 Not Implemented" CRLF "Server: " KBUILD_MODNAME CRLF \
    "Content-Type: text/plain" CRLF "Content-Length: 21" CRLF          \
    "Connection: Close" CRLF CRLF "501 Not Implemented" CRLF
#define HTTP_RESPONSE_501_KEEPALIVE                                    \
    ""                                                                 \
    "HTTP/1.1 501 Not Implemented" CRLF "Server: " KBUILD_MODNAME CRLF \
    "Content-Type: text/plain" CRLF "Content-Length: 21" CRLF          \
    "Connection: KeepAlive" CRLF CRLF "501 Not Implemented" CRLF

// 把 snprintf 跟 http_server_send 整合起來，讓 code 更加乾淨
#define SEND_HTTP_MSG(socket, buf, format, ...)           \
    snprintf(buf, SEND_BUFFER_SIZE, format, __VA_ARGS__); \
    http_server_send(socket, buf, strlen(buf))

// mime map，資料格式(type:副檔名, mime:對應的MIME type)
struct mime_type{
    const char* type;
    const char* mime;
};

struct mime_type mime_map[] = {
    {".html", "text/html"},
    {".htm", "text/html"},
    {".css", "text/css"},
    {".js", "application/javascript"},
    {".json", "application/json"},
    {".png", "image/png"},
    {".jpg", "image/jpeg"},
    {".jpeg", "image/jpeg"},
    {".gif", "image/gif"},
    {".txt", "text/plain"},
    {NULL, NULL}
};

/* 把回應都先存起來，之後同樣的 request 進來，
就照順序把這些片段送給 client，不用重新產生。 */
struct cache_content{
    struct list_head cache; // 負責連結各個 response
    char buf[SEND_BUFFER_SIZE]; // 這個片段要response的內容
};

// <request url, response>的map
struct hash_content{
    struct list_head *head; // value，指向完整 response 內容，例如<tr><td><a href="/a.txt">a.txt</a></td></tr>\r\n
    char *request; // key: request url
    struct hlist_node node; // 串連hash table的節點
    void *timer_node; // 計時器，用來移除過期的節點
};

// 工作資訊
struct http_request {
    struct socket *socket;    // 該 work 連線的 socket
    enum http_method method;  // 連線方式，GET、POST...
    char request_url[128];
    int complete;
    // 讀目錄時，每讀到一個檔案要呼叫的處理函式(配合 trace_dir)
    struct dir_context dir_context;
    // 新增 `串列節點` 與 `work 本體`
    struct list_head node;
    struct work_struct khttpd_work;
    // directory cache 的 linklist
    struct list_head *cache_list;
};

static int http_server_recv(struct socket *sock, char *buf, size_t size)
{
    struct kvec iov = {.iov_base = (void *) buf, .iov_len = size};
    struct msghdr msg = {
        .msg_name = 0,
        .msg_namelen = 0,
        .msg_control = NULL,
        .msg_controllen = 0,
        .msg_flags = 0,
    };
    return kernel_recvmsg(sock, &msg, &iov, 1, size, msg.msg_flags);
}

static int http_server_send(struct socket *sock, const char *buf, size_t size)
{
    struct msghdr msg = {
        .msg_name = NULL,
        .msg_namelen = 0,
        .msg_control = NULL,
        .msg_controllen = 0,
        .msg_flags = 0,
    };
    int done = 0;
    while (done < size) {
        struct kvec iov = {
            .iov_base = (void *) ((char *) buf + done),
            .iov_len = size - done,
        };
        int length = kernel_sendmsg(sock, &msg, &iov, 1, iov.iov_len);
        if (length < 0) {
            pr_err("write error: %d\n", length);
            break;
        }
        done += length;
    }
    return done;
}

// function prototype
static bool handle_directory(struct http_request *request);
static bool tracedir(struct dir_context *dir_context,
                     const char *name,
                     int namelen,
                     loff_t offset,
                     u64 ino,
                     unsigned int dtype);
const char* get_mime_str(char* request_url);
static struct list_head* find_cache(char* url);

// 處理 response
static int http_server_response(struct http_request *request, int keep_alive)
{
    pr_info("requested_url = %s\n", request->request_url);
    if (request->method != HTTP_GET) {  // 除了 GET 以外其他都回答 501
        char *response =
            keep_alive ? HTTP_RESPONSE_501_KEEPALIVE : HTTP_RESPONSE_501;
        http_server_send(request->socket, response, strlen(response));
        return 0;
    }

    // 把目錄裡的內容包起來回傳給 client
    request->dir_context.actor = tracedir;
    request->dir_context.pos = 0;
    handle_directory(request);
    return 0;
}

static int http_parser_callback_message_begin(http_parser *parser)
{
    struct http_request *request = parser->data;
    request->method = 0;
    request->request_url[0] = '\0';
    request->complete = 0;
    return 0;
}

static int http_parser_callback_request_url(http_parser *parser,
                                            const char *p,
                                            size_t len)
{
    struct http_request *request = parser->data;
    if (p[len - 1] == '/')
        len--;
    strncat(request->request_url, p, len);
    return 0;
}

static int http_parser_callback_header_field(http_parser *parser,
                                             const char *p,
                                             size_t len)
{
    return 0;
}

static int http_parser_callback_header_value(http_parser *parser,
                                             const char *p,
                                             size_t len)
{
    return 0;
}

static int http_parser_callback_headers_complete(http_parser *parser)
{
    struct http_request *request = parser->data;
    request->method = parser->method;
    return 0;
}

static int http_parser_callback_body(http_parser *parser,
                                     const char *p,
                                     size_t len)
{
    return 0;
}

static int http_parser_callback_message_complete(http_parser *parser)
{
    struct http_request *request = parser->data;
    http_server_response(request, http_should_keep_alive(parser));
    request->complete = 1;
    return 0;
}

// 處理連線任務，收資料 -> 解析 http request -> 送出 response
// 從原本 kthread 改成 CMWQ 的方式
// kthread : 當有連線時，daemon 會建立一個新的 kthread 去處理該連線
// CMWQ : 當有連線，daemon 會包成一個 work 丟進 workqueue
static void http_server_worker(struct work_struct *work)
{
    struct http_request *worker =
        container_of(work, struct http_request, khttpd_work);
    struct socket *socket = worker->socket;

    char *buf;
    struct http_parser parser;
    struct http_parser_settings setting = {
        .on_message_begin = http_parser_callback_message_begin,
        .on_url = http_parser_callback_request_url,
        .on_header_field = http_parser_callback_header_field,
        .on_header_value = http_parser_callback_header_value,
        .on_headers_complete = http_parser_callback_headers_complete,
        .on_body = http_parser_callback_body,
        .on_message_complete = http_parser_callback_message_complete,
    };

    buf = mempool_alloc(http_buf_pool, GFP_KERNEL);
    if (!buf) {
        pr_err("can't allocate memory!\n");
        goto out;
    }

    http_parser_init(&parser, HTTP_REQUEST);
    parser.data = worker;

    while (!daemon_list.is_stopped) {
        int ret = http_server_recv(socket, buf, RECV_BUFFER_SIZE - 1);
        if (ret <= 0) {
            if (ret) {
                pr_err("recv error: %d\n", ret);
            }
            goto out_free_buf;
        }
        http_parser_execute(&parser, &setting, buf, ret);
        if (worker->complete && !http_should_keep_alive(&parser))
            goto out_free_buf;
        memset(buf, 0, RECV_BUFFER_SIZE);
    }
out_free_buf:
    mempool_free(buf, http_buf_pool);
out:
    kernel_sock_shutdown(socket, SHUT_RDWR);
    /* Does not return, and completes from core kernel code, so no
     * module code runs after this.
     */
}

// 將新連線建立 work，再把它放進 daemon list 內 ; daemon
// 為目前所有還在處理中的連線
static struct work_struct *create_work(struct socket *sk)
{
    struct http_request *work = kzalloc(sizeof(*work), GFP_KERNEL);
    if (!work)
        return NULL;

    work->socket = sk;
    INIT_WORK(&work->khttpd_work, http_server_worker);
    list_add(&work->node, &daemon_list.head);

    return &work->khttpd_work;
}

// 當 khttpd 整個關閉時，會將關閉並釋放所有連線的 work
static void free_work(void)
{
    struct http_request *tar, *tmp;

    list_for_each_entry_safe (tar, tmp, &daemon_list.head, node) {
        kernel_sock_shutdown(tar->socket, SHUT_RDWR);
        flush_work(&tar->khttpd_work);
        sock_release(tar->socket);
        kfree(tar);
    }
}

int http_server_daemon(void *arg)
{
    struct socket *socket;
    struct work_struct *worker;
    struct http_server_param *param = (struct http_server_param *) arg;

    allow_signal(SIGKILL);
    allow_signal(SIGTERM);

    // 初始化記錄所有連線的串列
    INIT_LIST_HEAD(&daemon_list.head);
    daemon_list.is_stopped = false;

    while (!kthread_should_stop()) {
        int err = kernel_accept(param->listen_socket, &socket, 0);

        if (err < 0) {
            if (signal_pending(current))
                break;
            /* -EAGAIN means the accept timeout expired; loop back to reap */
            if (err != -EAGAIN)
                pr_err("kernel_accept() error: %d\n", err);
            continue;
        }
        /* Accepted sockets inherit the listener's timeout. Restore the
         * default so idle keep-alive connections are not dropped.
         */
        WRITE_ONCE(socket->sk->sk_rcvtimeo, MAX_SCHEDULE_TIMEOUT);
        worker = create_work(socket);
        if (!worker) {
            pr_err("can't allocate memory for connection\n");
            kernel_sock_shutdown(socket, SHUT_RDWR);
            sock_release(socket);
            continue;
        }

        queue_work(khttpd_wq, worker);
    }
    /* The loop also ends on a signal, so drain here, not in khttpd_exit() */
    daemon_list.is_stopped = true;
    free_work();
    return 0;
}

// iterate_dir 的 callback：每讀到一個檔案就呼叫一次，跳過 "."，保留 ".."
// 以便回上一層 將檔名包成 <tr>， 以 chunked 格式傳送給 client
static bool tracedir(struct dir_context *dir_context,
                     const char *name,
                     int namelen,
                     loff_t offset,
                     u64 ino,
                     unsigned int dtype)
{
    struct http_request *request =
        container_of(dir_context, struct http_request, dir_context);

    if(namelen == 1 && name[0] == '.'){
        return true;
    }
    
    struct cache_content *content = kmalloc(sizeof(struct cache_content), GFP_KERNEL);
    if(!content){
        pr_err("can't allocate memory for cache content\n");
        return false;
    }

    snprintf(content->buf, SEND_BUFFER_SIZE, "%lx\r\n<tr><td><a href=\"%s\">%s</a></td></tr>\r\n", 34 + strlen(href_link) + strlen(name), href_link, name);
    add_to_list_tail(&content->cache, request->cache_list);         

    return true;
}

// 把兩個字串接起來存進 pwd
static void catstr(char *pwd, const char *first, const char *second)
{
    snprintf(pwd, PATH_SIZE, "%s%s", first, second);
}

// 讀整個檔案，回傳讀到的 byte 數
static int read_file(struct file *fp, char *buf)
{
    loff_t pos = 0;
    return kernel_read(fp, buf, fp->f_inode->i_size, &pos);
}

// 將 http 拆成 header, body 傳送
// 這段回傳 header
static void send_http_header(struct socket *socket,
                             int status,
                             const char *status_msg,
                             const char *type,
                             int length,
                             const char *conn_msg)
{
    char buf[SEND_BUFFER_SIZE] = {0};
    SEND_HTTP_MSG(socket, buf,
                  "HTTP/1.1 %d %s\r\nContent-Type: %s\r\n"
                  "Content-Length: %d\r\nConnection: %s\r\n\r\n",
                  status, status_msg, type, length, conn_msg);
}
// 這段回傳 body
static void send_http_content(struct socket *socket, const char *content)
{
    char buf[SEND_BUFFER_SIZE] = {0};
    SEND_HTTP_MSG(socket, buf, "%s", content);
}
// ================== cache content ==================
/* 確認是否已經看過了，有的話回傳list_head */
static list_head* find_cache(char* url){
    u32 original_key = jhash(url, strlen(url), 0);
    u8 key = (u8)(original_key % 256);
    struct hash_content *curr;
    struct list_head *res = NULL;

    rcu_read_lock();
    hash_for_each_possible_rcu(ht, curr, node, key){
        if(strcmp(curr -> request, url) == 0){
            res = curr -> head;
            break;
        }
    }
    rcu_read_unlock();

    return res;
}

bool hash_insert(const char* request_url, struct list_head *head){
    u32 original_key = jhash(request_url, strlen(request_url), 0); // 把 url 變成一段 32bit 的 hash value
    u8 key = (u8)(original_key % 256);
    
    // init hash_content
    struct hash_content *content = kmalloc(sizeof(struct hash_content), GFP_KERNEL);
    content -> head = head;
    content -> request = kmalloc(strlen(request_url) + 1, GFP_KERNEL);
    memcpy(content -> request, request_url, strlen(request_url) + 1);

    spin_lock(&hash_lock); // 用spinlock避免重複寫入、同時改指標。只要走訪幾個node，所以不太會佔用過多時間，所以選擇spinlock
    struct hash_content *curr = NULL;
    hash_for_each_possible_rcu(ht, curr, node, key){
        char *curr_request_url = curr -> request;
        if(strcmp(curr_request_url, request_url) == 0){ // 如果已經有這個 url 的 cache content，就不再新增
            spin_unlock(&hash_lock);
            kfree(content -> request);
            kfree(content);
            return false;

        }
    }
    hash_add_rcu(ht, &content -> node, key);
    spin_unlock(&hash_lock);

    return true;
}

static void send_cache(struct socket *socket, struct list_head *cache_list){
    struct cache_content *cache_tmp;

    list_for_each_entry(cache_tmp, cache_list, cache){
        http_server_send(socket, cache_tmp -> buf, strlen(cache_tmp -> buf));
    }
}
// ===================================================

// ================= compress =========================
bool compress(const char *input,
              unsigned int input_len,
              char *output,
              unsigned int *output_len)
{
    struct crypto_comp *comp;

    comp = crypto_alloc_comp(COMPRESS_ALGORITHM, 0, 0);
    if(IS_ERR(comp)){
        pr_err("Failed to allocate compression object\n");
        return false;
    }
    int ret = crypto_comp_compress(comp, input, input_len, output, output_len);
    if(ret){
        pr_err("Compression failed with error code: %d\n", ret);
        crypto_free_comp(comp);
        return false;
    }

    crypto_free_comp(comp);
    return true;
}
// ====================================================
// 回應瀏覽器的請求，產生一 "目錄檔案列表" 的網頁，負責檢查是否為 GET、送
// header、 送 HTML 開頭和結尾、打開目錄並call iterate_dir 讀取該目錄內容
static bool handle_directory(struct http_request *request)
{
    struct file *fp;
    char pwd[PATH_SIZE] = {0};

    // 檢查是否已經有存在，如果有存在，就直接送出 cache content，並關閉 socket。須於 flip_open 前，才能有效發揮作用
    struct list_head *curr_cache = find_cache(request -> request_url);
    if(curr_cache){
        send_cache(request->socket, curr_cache);
        kernel_sock_shutdown(request->socket, SHUT_RDWR);
        filp_close(fp, NULL);
        return true;
    }

    catstr(pwd, daemon_list.dir_path, request->request_url);
    fp = filp_open(pwd, O_RDONLY, 0);
    if (IS_ERR(fp)) {
        send_http_header(request->socket, HTTP_STATUS_NOT_FOUND,
                         http_status_str(HTTP_STATUS_NOT_FOUND), "text/plain",
                         13, "Close");
        send_http_content(request->socket, "404 Not Found");
        return false;
    }

    if (S_ISDIR(fp->f_inode->i_mode)) {  // 如果是目錄，將整個目錄下的檔案名稱回傳給client
        char const *html_head =
            "<html><head><style>\r\n"
            "body{font-family: monospace; font-size: 15px;}\r\n"
            "td {padding: 1.5px 6px;}\r\n"
            "</style></head><body><table>\r\n";
        char const *body = "</table></body></html>\r\n";

        // 初始化 cache 串列
        struct list_head *head = kmalloc(sizeof(struct list_head), GFP_KERNEL); // 配置cache content memory
        struct cache_content *content_header = kmalloc(sizeof(struct cache_content), GFP_KERNEL);
        struct cache_content *content_body = kmalloc(sizeof(struct cache_content), GFP_KERNEL);
        struct cache_content *content_html = kmalloc(sizeof(struct cache_content), GFP_KERNEL);

        INIT_LIST_HEAD(head);
        request -> cache_list = head;

        // 回傳 header，並把 header 存進 cache content
        snprintf(content_header->buf, SEND_BUFFER_SIZE, "%s%s%s%s",
            "HTTP/1.1 200 OK\r\n", "Connection: Keep-Alive\r\n",
            "Content-Type: text/html\r\n",
            "Transfer-Encoding: chunked\r\n\r\n");
        add_to_list_tail(&content_header->cache, request->cache_list);
        
        // 回傳 html 開頭，並把 html 開頭存進 cache content
        snprintf(content_html->buf, SEND_BUFFER_SIZE, "%zx\r\n%s\r\n",
                strlen(html_head), html_head);
        add_to_list_tail(&content_html->cache, request->cache_list);
        
        // 找個目錄，讀取裡面的檔案名稱，並把檔案名稱包成 <tr>，以 chunked 格式傳送給 client
        iterate_dir(fp, &request->dir_context);
        
        // 回傳 html 結尾，並把 html 結尾存進 cache content
        snprintf(content_body->buf, SEND_BUFFER_SIZE, "%zx\r\n%s\r\n0\r\n\r\n",
                strlen(body), body);
        add_to_list_tail(&content_body->cache, request->cache_list);
        
        send_cache(request->socket, request->cache_list); // 先送
        if (!hash_insert(request->request_url, request->cache_list)) // 再存
            free_cache_list(request->cache_list); // 別人已存過，釋放自己這份
        
        kernel_sock_shutdown(request->socket, SHUT_RDWR);
    } else if (
        S_ISREG(fp->f_inode
                    ->i_mode)) {  // 如果是一般文件的話，就回傳檔案資料給client
        char buf[SEND_BUFFER_SIZE];
        char *read_data = kmalloc(fp->f_inode->i_size, GFP_KERNEL);
        char *comp_data = NULL;
        usigned int comp_len = 0;
        int ret = read_file(fp, read_data);

        if(!read_data || ret < 0) goto out_free;

        comp_len = ret + 1024;
        comp_data = kmalloc(comp_len, GFP_KERNEL);
        if(!comp_data) goto out_free;
        if(!compress(read_data, ret, comp_data, &comp+len)){ // 壓縮檔案內容
            goto out_free;
        }
        
        SEND_HTTP_MSG(request->socket, buf,
                  "HTTP/1.1 200 OK\r\nContent-Encoding: deflate\r\n"
                  "Content-Type: %s\r\nContent-Length: %u\r\n"
                  "Connection: Close\r\n\r\n",
                  get_mime_str(request->request_url), comp_len);

        http_server_send(request->socket, comp_data, comp_len);

    out_free:
        kfree(comp_data);
        kfree(read_data);
    }


    filp_close(fp, NULL);
    return true;
}

// MIME
const char* get_mime_str(char* request_url){
    char* request_type = strchr(request_url, '.');
    int index = 0;
    if(!request_type) return "text/plain";

    while(mime_map[index].type){
        if(!strcmp(mime_map[index].type, request_type)){
            return mime_map[index].mime;
        }
        index++;
    }
    return "text/plain";
}