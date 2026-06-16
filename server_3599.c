// Registration: IT24103599 | PORT: 50599 | SID: 1035

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <openssl/sha.h>

#define PORT 50599
#define BUFFER_SIZE 8192
#define MAX_PAYLOAD 4096
#define SID "1035"
#define TOKEN_TIMEOUT 300
#define MAX_LOGIN_ATTEMPTS 3
#define LOCKOUT_TIME 300
#define RATE_LIMIT_WINDOW 60
#define MAX_REQUESTS 10


typedef struct User {
    char username[50];
    char salt[32];
    char hash[128];

    time_t registered_at;
    time_t last_login;

    int failed_attempts;
    time_t lockout_until;

    struct User *next;
} User;
typedef struct Session {
    char token[256];
    char username[50];
    time_t last_active;
    struct Session *next;
} Session;

typedef struct RateLimit {
    char ip[INET_ADDRSTRLEN];
    int count;
    time_t window_start;
    struct RateLimit *next;
} RateLimit;

User *users = NULL;
Session *sessions = NULL;
RateLimit *rate_limits = NULL;
FILE *log_file = NULL;

void write_log(const char *ip, int port, pid_t pid, const char *user, const char *token,  
               const char *cmd, const char *result) {
    char timestamp[64];
    time_t now = time(NULL);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    char user_str[50] = "-";
    if (user && strlen(user) > 0) {
        strcpy(user_str, user);
    }
    char token_str[256] = "-";
    if (token && strlen(token) > 0) {
        strcpy(token_str, token); }

    fprintf(log_file, "[%s] %s:%d PID:%d USER:%s TOKEN:%s CMD:%s RESULT:%s\n",
            timestamp, ip, port, pid, user_str, token_str, cmd, result);
    fflush(log_file);
}


void save_users_to_disk() {
    char path[256];
    snprintf(path, sizeof(path), "/srv/ie2102/IT24103599/users.db");
    
    FILE *file = fopen(path, "w");
    if (!file) return;
    
    User *curr = users;
    while (curr) {
        fprintf(file,
        "%s:%s:%s:%ld:%ld:%d:%ld\n",
        curr->username,
        curr->salt,
        curr->hash,
        curr->registered_at,
        curr->last_login,
        curr->failed_attempts,
        curr->lockout_until);
        curr = curr->next;
    }
    fclose(file);
}

void load_users_from_disk() {
    char path[256];
    snprintf(path, sizeof(path), "/srv/ie2102/IT24103599/users.db");
    
    FILE *file = fopen(path, "r");
    if (!file) return;
    
    char line[512];
    while (fgets(line, sizeof(line), file)) {
        User *new_user = malloc(sizeof(User));
        if (!new_user) continue;
        
        char *username = strtok(line, ":");
        char *salt = strtok(NULL, ":");
        char *hash = strtok(NULL, ":");
        char *registered = strtok(NULL, ":");
        char *lastlogin = strtok(NULL, ":");
        char *attempts = strtok(NULL, ":");
        char *lockout = strtok(NULL, ":");
        
        if (username && salt && hash) {
            strcpy(new_user->username, username);
            strcpy(new_user->salt, salt);
            strcpy(new_user->hash, hash);
            new_user->registered_at =
                registered ? atol(registered) : time(NULL);

            new_user->last_login =
                lastlogin ? atol(lastlogin) : 0;

            new_user->failed_attempts =
                attempts ? atoi(attempts) : 0;

            new_user->lockout_until =
                lockout ? atol(lockout) : 0;
            new_user->next = users;
            users = new_user;
        } else {
            free(new_user);
        }
    }
    fclose(file);
}


void generate_salt(char *salt, int len) {
    const char *chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (int i = 0; i < len - 1; i++) {
        salt[i] = chars[rand() % 62];
    }
    salt[len - 1] = '\0';
}

void hash_password(const char *password, const char *salt, char *output) {
    char combined[256];
    unsigned char hash[SHA256_DIGEST_LENGTH];
    
    snprintf(combined, sizeof(combined), "%s%s", password, salt);
    SHA256((unsigned char*)combined, strlen(combined), hash);
    
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[SHA256_DIGEST_LENGTH * 2] = '\0';
}


void create_user_directory(const char *username) {
    char path[256];
    snprintf(path, sizeof(path), "/srv/ie2102/IT24103599/%s", username);
    mkdir(path, 0755);
}

int validate_username(const char *username) {
    int len = strlen(username);
    if (len < 3 || len > 20) return 0;
    for (int i = 0; username[i]; i++) {
        if (!isalnum(username[i]) && username[i] != '_') return 0;
    }
    return 1;
}
int validate_password(const char *password)
{
    int upper = 0;
    int lower = 0;
    int digit = 0;
    int special = 0;

    if (strlen(password) < 8)
        return 0;

    for (int i = 0; password[i]; i++)
    {
        if (isupper(password[i]))
            upper = 1;
        else if (islower(password[i]))
            lower = 1;
        else if (isdigit(password[i]))
            digit = 1;
        else
            special = 1;
    }

    return upper && lower && digit && special;
}

User* find_user(const char *username) {
    User *curr = users;
    while (curr) {
        if (strcmp(curr->username, username) == 0) return curr;
        curr = curr->next;
    }
    return NULL;
}


int is_locked_out(const char *username) {
    User *user = find_user(username);
    if (user && user->lockout_until > time(NULL)) {
        return 1;
    }
    return 0;
}


void generate_token(char *token) {
    srand(time(NULL) ^ getpid());
    sprintf(token, "%08x%08x%08x%08x_%ld_%d",
            rand(), rand(), rand(), rand(),
            time(NULL), getpid());
}

int create_session(const char *username, char *token_out) {
    generate_token(token_out);
    
    Session *new_session = malloc(sizeof(Session));
    if (!new_session) return 0;
    
    strcpy(new_session->token, token_out);
    strcpy(new_session->username, username);
    new_session->last_active = time(NULL);
    new_session->next = sessions;
    sessions = new_session;
    
    return 1;
}

int validate_token(const char *token, char *username_out) {
    time_t now = time(NULL);
    Session *curr = sessions;
    Session *prev = NULL;
    
    while (curr) {
        if (strcmp(curr->token, token) == 0) {
            if (now - curr->last_active < TOKEN_TIMEOUT) {
                curr->last_active = now;
                strcpy(username_out, curr->username);
                return 1;
            } else {
                if (prev) prev->next = curr->next;
                else sessions = curr->next;
                free(curr);
                return 0;
            }
        }
        prev = curr;
        curr = curr->next;
    }
    return 0;
}


int rate_limit_check(const char *ip) {
    time_t now = time(NULL);
    RateLimit *curr = rate_limits;
    
    while (curr) {
        if (strcmp(curr->ip, ip) == 0) {
            if (now - curr->window_start >= RATE_LIMIT_WINDOW) {
                curr->count = 1;
                curr->window_start = now;
                return 1;
            }
            if (curr->count < MAX_REQUESTS) {
                curr->count++;
                return 1;
            }
            return 0;
        }
        curr = curr->next;
    }
    
    RateLimit *new = malloc(sizeof(RateLimit));
    if (new) {
        strcpy(new->ip, ip);
        new->count = 1;
        new->window_start = now;
        new->next = rate_limits;
        rate_limits = new;
        return 1;
    }
    return 1;
}


int parse_messages(char *buffer, int buffer_len, char *payload_out, int *consumed) {
    *consumed = 0;
    
    if (strncmp(buffer, "LEN:", 4) != 0) {
        return -1;
    }
    
    char *newline = strchr(buffer + 4, '\n');
    if (!newline) {
        return 0;
    }
    
    char len_str[32];
    int len_len = newline - (buffer + 4);
    if (len_len >= 32) len_len = 31;
    strncpy(len_str, buffer + 4, len_len);
    len_str[len_len] = '\0';
    
    int payload_len = atoi(len_str);
    
    if (payload_len <= 0) {
        return -2;
    }
    
    if (payload_len > MAX_PAYLOAD) {
        return -3;
    }
    
    char *payload_start = newline + 1;
    int payload_offset = payload_start - buffer;
    
    if (payload_offset + payload_len > buffer_len) {
        return 0;
    }
    
    strncpy(payload_out, payload_start, payload_len);
    payload_out[payload_len] = '\0';
    
    *consumed = payload_offset + payload_len;
    return 1;
}


int handle_register(const char *username, const char *password, char *response) {
    char username_lower[50];
    strcpy(username_lower, username);

    for (int i = 0; username_lower[i]; i++)
    {
       username_lower[i] = tolower(username_lower[i]);
    }

    if (find_user(username_lower)) {
        sprintf(response, "ERR 102 SID:%s Username already exists", SID);
        return 0;
    }
    
    if (!validate_username(username_lower)) {
        sprintf(response, "ERR 101 SID:%s Invalid username format", SID);
        return 0;
    }
    
    if (!validate_password(password))
{
    sprintf(response,
        "ERR 400 SID:%s Password must contain uppercase, lowercase, digit and special character (min 8 chars)",
        SID);
    return 0;
} 
    User *new_user = malloc(sizeof(User));
    if (!new_user) {
        sprintf(response, "ERR 500 SID:%s Internal error", SID);
        return 0;
    }
    
    strcpy(new_user->username, username_lower);
    generate_salt(new_user->salt, sizeof(new_user->salt));
    hash_password(password, new_user->salt, new_user->hash);
    new_user->registered_at = time(NULL);
    new_user->last_login = 0;
    new_user->failed_attempts = 0;
    new_user->lockout_until = 0;
    new_user->next = users;
    users = new_user;
    
    create_user_directory(username_lower);
    save_users_to_disk();
    
    sprintf(response, "OK 200 SID:%s Registration successful", SID);
    return 1;
}

int handle_login(const char *username, const char *password, char *response, char *token_out) {
    char username_lower[50];
    strcpy(username_lower, username);

    for (int i = 0; username_lower[i]; i++)
    {
        username_lower[i] = tolower(username_lower[i]);
    }
        
    User *user = find_user(username_lower);
    

    if (!user) {
        sprintf(response, "ERR 401 SID:%s Invalid credentials", SID);
        return 0;
    }
    

    if (user->lockout_until > time(NULL)) {
        sprintf(response, "ERR 403 SID:%s Account locked. Try again later", SID);
        return 0;
    }
    

    char computed_hash[128];
    hash_password(password, user->salt, computed_hash);
    
    if (strcmp(computed_hash, user->hash) != 0) {
        user->failed_attempts++;
        
        if (user->failed_attempts >= MAX_LOGIN_ATTEMPTS) {
            user->lockout_until = time(NULL) + LOCKOUT_TIME;
            save_users_to_disk();
            sprintf(response, "ERR 403 SID:%s Account locked after %d failed attempts", SID, MAX_LOGIN_ATTEMPTS);
            return 0;
        }
        
        save_users_to_disk();
        sprintf(response, "ERR 401 SID:%s Invalid credentials", SID);
        return 0;
    }
    
    // Successful login
    user->failed_attempts = 0;
    user->lockout_until = 0;
    user->last_login = time(NULL);
    save_users_to_disk();
    
    create_session(username_lower, token_out);
    sprintf(response, "OK 200 SID:%s Login successful Token:%s", SID, token_out);
    return 1;
}

int handle_logout(const char *token, char *response) {
    Session *curr = sessions;
    Session *prev = NULL;
    
    while (curr) {
        if (strcmp(curr->token, token) == 0) {
            if (prev) prev->next = curr->next;
            else sessions = curr->next;
            free(curr);
            sprintf(response, "OK 200 SID:%s Logout successful", SID);
            return 1;
        }
        prev = curr;
        curr = curr->next;
    }
    
    sprintf(response, "ERR 402 SID:%s Invalid token", SID);
    return 0;
}

int handle_protected(const char *token, char *response, char *username_out) {
    if (validate_token(token, username_out)) {
        sprintf(response, "OK 200 SID:%s Protected command executed for %s", SID, username_out);
        return 1;
    }
    sprintf(response, "ERR 401 SID:%s Authentication required or token expired", SID);
    return 0;
}
int handle_profile(const char *token,
                   char *response)
{
    char username[50];

    if (!validate_token(token, username))
    {
        sprintf(response,
                "ERR 401 SID:%s Invalid token",
                SID);
        return 0;
    }

    User *user = find_user(username);

    if (!user)
    {
        sprintf(response,
                "ERR 404 SID:%s User not found",
                SID);
        return 0;
    }

    char reg[64];
    char login[64];

    strftime(reg,
             sizeof(reg),
             "%Y-%m-%d %H:%M:%S",
             localtime(&user->registered_at));

    if (user->last_login)
    {
        strftime(login,
                 sizeof(login),
                 "%Y-%m-%d %H:%M:%S",
                 localtime(&user->last_login));
    }
    else
    {
        strcpy(login, "Never");
    }

    sprintf(response,
            "OK 200 SID:%s USER:%s REGISTERED:%s LAST_LOGIN:%s",
            SID,
            user->username,
            reg,
            login);

    return 1;
}

void handle_client(int client_fd, struct sockaddr_in client_addr) {
    char buffer[BUFFER_SIZE];
    char payload[MAX_PAYLOAD + 1];
    char response[BUFFER_SIZE];
    char framed_response[BUFFER_SIZE + 32];
    int total_recv = 0;
    pid_t child_pid = getpid();
    char client_ip[INET_ADDRSTRLEN];
    int client_port = ntohs(client_addr.sin_port);
    
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
    
    write_log(client_ip, client_port, child_pid, NULL, "-", "CONNECT", "Client connected");
    
    while (1) {
        int n = recv(client_fd, buffer + total_recv, BUFFER_SIZE - total_recv - 1, 0);
        if (n <= 0) {
            break;
        }
        
        total_recv += n;
        buffer[total_recv] = '\0';
        

        if (!rate_limit_check(client_ip)) {
            sprintf(response, "ERR 429 SID:%s Rate limit exceeded. Max %d requests/min", SID, MAX_REQUESTS);
            sprintf(framed_response, "LEN:%d\n%s", (int)strlen(response), response);
            send(client_fd, framed_response, strlen(framed_response), 0);
            write_log(client_ip, client_port, child_pid, NULL, "-", "RATE_LIMIT", response);
            continue;
        }
        
        int consumed;
        int parse_result = parse_messages(buffer, total_recv, payload, &consumed);
        
        if (parse_result == -1) {
            sprintf(response, "ERR 400 SID:%s Invalid format. Expected LEN:<n>\\n<payload>", SID);
            sprintf(framed_response, "LEN:%d\n%s", (int)strlen(response), response);
            send(client_fd, framed_response, strlen(framed_response), 0);
            write_log(client_ip, client_port, child_pid, NULL, "-", "INVALID_FORMAT", response);
            break;
        } else if (parse_result == -2) {
            sprintf(response, "ERR 400 SID:%s Invalid payload length", SID);
            sprintf(framed_response, "LEN:%d\n%s", (int)strlen(response), response);
            send(client_fd, framed_response, strlen(framed_response), 0);
            write_log(client_ip, client_port, child_pid, NULL, "-", "INVALID_LENGTH", response);
            break;
        } else if (parse_result == -3) {
            sprintf(response, "ERR 413 SID:%s Payload exceeds %d bytes", SID, MAX_PAYLOAD);
            sprintf(framed_response, "LEN:%d\n%s", (int)strlen(response), response);
            send(client_fd, framed_response, strlen(framed_response), 0);
            write_log(client_ip, client_port, child_pid, NULL, "-", "PAYLOAD_OVERFLOW", response);
            break;
        } else if (parse_result == 0) {
            continue;
        }
        

        char cmd[32], arg1[256], arg2[256], token[256];
        char token_out[256];
        char auth_user[50];
        
        int num_args = sscanf(payload, "%s %s %s %s", cmd, arg1, arg2, token);
        
        if (num_args < 1) {
            sprintf(response, "ERR 400 SID:%s No command provided", SID);
            sprintf(framed_response, "LEN:%d\n%s", (int)strlen(response), response);
            send(client_fd, framed_response, strlen(framed_response), 0);
            write_log(client_ip, client_port, child_pid, NULL, "-", "UNKNOWN", response);
            continue;
        }
        

        
        if (strcmp(cmd, "REGISTER") == 0) {
            if (num_args != 3) {
                sprintf(response, "ERR 400 SID:%s Usage: REGISTER <username> <password>", SID);
            } else {
                handle_register(arg1, arg2, response);
                write_log(client_ip, client_port, child_pid, arg1, "-", "REGISTER", response);
            }
            
        } else if (strcmp(cmd, "LOGIN") == 0) {
            if (num_args != 3) {
                sprintf(response, "ERR 400 SID:%s Usage: LOGIN <username> <password>", SID);
                write_log(client_ip, client_port, child_pid, arg1, "-", "LOGIN", "INVALID_USAGE");
            } else {
                if (handle_login(arg1, arg2, response, token_out)) {

                    char log_resp[256];
                    strcpy(log_resp, response);
                    char *token_pos = strstr(log_resp, " Token:");
                    if (token_pos) *token_pos = '\0';
                    write_log(client_ip, client_port, child_pid, arg1, "-", "LOGIN", log_resp);
                } else {
                    write_log(client_ip, client_port, child_pid, arg1, "-", "LOGIN", response);
                }
            }
            
        } else if (strcmp(cmd, "LOGOUT") == 0) {
            if (num_args != 2) {
                sprintf(response, "ERR 400 SID:%s Usage: LOGOUT <token>", SID);
            } else {
                handle_logout(arg1, response);
                write_log(client_ip, client_port, child_pid, NULL, "-", "LOGOUT", response);
            }
            
        } else if (strcmp(cmd, "PROTECTED") == 0) {
            if (num_args != 2) {
                sprintf(response, "ERR 400 SID:%s Usage: PROTECTED <token>", SID);
                write_log(client_ip, client_port, child_pid, NULL, "-", "PROTECTED", "INVALID_USAGE");
            } else {
                if (handle_protected(arg1, response, auth_user)) {
                    write_log(client_ip, client_port, child_pid, auth_user, "-", "PROTECTED", response);
                } else {
                    write_log(client_ip, client_port, child_pid, NULL, "-", "PROTECTED", response);
                }
            }
        }  else if (strcmp(cmd, "PROFILE") == 0)
           {
             if (num_args != 2){
                 sprintf(response, "ERR 400 SID:%s Usage: PROFILE <token>", SID);
             } else {
                 handle_profile(arg1, response);

                 write_log(client_ip,
                           client_port,
                           child_pid,
                           NULL, "-",
                           "PROFILE",
                           response);
              }
            
        } else if (strcmp(cmd, "STATUS") == 0) {
            sprintf(response, "OK 200 SID:%s Server running", SID);
            write_log(client_ip, client_port, child_pid, NULL, "-", "STATUS", response);
            
        } else {
            sprintf(response, "ERR 400 SID:%s Unknown command: %s", SID, cmd);
            write_log(client_ip, client_port, child_pid, NULL, "-", cmd, "UNKNOWN_COMMAND");
        }
        
        sprintf(framed_response, "LEN:%d\n%s", (int)strlen(response), response);
        send(client_fd, framed_response, strlen(framed_response), 0);
        
        if (consumed > 0 && consumed < total_recv) {
            memmove(buffer, buffer + consumed, total_recv - consumed);
            total_recv -= consumed;
        } else if (consumed >= total_recv) {
            total_recv = 0;
        }
    }
    
    write_log(client_ip, client_port, child_pid, NULL, "-", "DISCONNECT", "Client disconnected");
    sleep(10);
    close(client_fd);
    exit(0);
}


void sigchld_handler(int sig) {
    (void)sig;
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

void cleanup() {
    save_users_to_disk();
    
    User *u = users;
    while (u) {
        User *next = u->next;
        free(u);
        u = next;
    }
    
    Session *s = sessions;
    while (s) {
        Session *next = s->next;
        free(s);
        s = next;
    }
    
    RateLimit *r = rate_limits;
    while (r) {
        RateLimit *next = r->next;
        free(r);
        r = next;
    }
    
    if (log_file) {
        fclose(log_file);
    }
}

void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        cleanup();
        exit(0);
    }
}


int main() {
    srand(time(NULL));
    
    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGCHLD, &sa, NULL);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    

    mkdir("/srv/ie2102", 0755);
    mkdir("/srv/ie2102/IT24103599", 0755);
    
    log_file = fopen("server_IT24103599.log", "a");
    if (!log_file) {
        perror("Cannot open log file");
        exit(1);
    }
    

    load_users_from_disk();
    
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Socket failed");
        exit(1);
    }
    
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        exit(1);
    }
    
    if (listen(server_fd, 100) < 0) {
        perror("Listen failed");
        exit(1);
    }
    
    printf("========================================\n");
    printf("Server Running\n");
    printf("Port: %d\n", PORT);
    printf("SID: %s\n", SID);
    printf("Log: server_IT24103599.log\n");
    printf("Format: LEN:<n>\\n<payload>\n");
    printf("Hash: SHA-256 with Salt\n");
    printf("Max Payload: %d bytes\n", MAX_PAYLOAD);
    printf("Rate Limit: %d req/min\n", MAX_REQUESTS);
    printf("Login Lockout: %d attempts\n", MAX_LOGIN_ATTEMPTS);
    printf("Token Timeout: %d sec (%d min)\n", TOKEN_TIMEOUT, TOKEN_TIMEOUT/60);
    printf("User Directory: /srv/ie2102/IT24103599/<username>/\n");
    printf("========================================\n");
    
    write_log("SERVER", 0, getpid(), NULL, "-" , "START", "Server started");
    
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        
        if (client_fd < 0) {
            perror("Accept failed");
            continue;
        }
        
        pid_t pid = fork();
        
        if (pid == 0) {
            close(server_fd);
            handle_client(client_fd, client_addr);
            exit(0);
        } else if (pid > 0) {
            close(client_fd);
        } else {
            perror("Fork failed");
        }
    }
    
    cleanup();
    close(server_fd);
    return 0;
}
