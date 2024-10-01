#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <dlfcn.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>

// Global variables for debug and binding configurations
static int debug_enabled = 0;
static int reuse_addr = 0;
static int reuse_port = 0;
static int ip_transparent = 0;

// Function pointers to hold original bind and connect functions
static int (*real_bind)(int, const struct sockaddr *, socklen_t) = NULL;
static int (*real_connect)(int, const struct sockaddr *, socklen_t) = NULL;

// Structures to hold local binding addresses
static struct sockaddr_in local_sockaddr_in;
static struct sockaddr_in6 local_sockaddr_in6;

// Flags to indicate if binding addresses are set
static int bind_addr_set_ipv4 = 0;
static int bind_port_set_ipv4 = 0;
static int bind_addr_set_ipv6 = 0;
static int bind_port_set_ipv6 = 0;

// Initialization function to set up bindings and configurations
__attribute__((constructor))
static void init(void) {
    const char *err;

    // Enable debug if DEBUG environment variable is set
    if (getenv("DEBUG") != NULL) {
        debug_enabled = 1;
    }

    // Load the original bind and connect functions
    real_bind = dlsym(RTLD_NEXT, "bind");
    if ((err = dlerror()) != NULL) {
        fprintf(stderr, "dlsym(bind): %s\n", err);
    }

    real_connect = dlsym(RTLD_NEXT, "connect");
    if ((err = dlerror()) != NULL) {
        fprintf(stderr, "dlsym(connect): %s\n", err);
    }

    // Handle BIND_ADDR and BIND_PORT for IPv4 and IPv6
    char *bind_addr_env = getenv("BIND_ADDR");
    if (bind_addr_env) {
        // Attempt to parse as IPv4
        if (inet_pton(AF_INET, bind_addr_env, &local_sockaddr_in.sin_addr) == 1) {
            local_sockaddr_in.sin_family = AF_INET;
            local_sockaddr_in.sin_port = htons(0); // Default port
            bind_addr_set_ipv4 = 1;
            if (debug_enabled) {
                char addr_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &local_sockaddr_in.sin_addr, addr_str, sizeof(addr_str));
                printf("[DEBUG] Set BIND_ADDR for AF_INET to %s\n", addr_str);
            }
        }
        // Attempt to parse as IPv6
        else if (inet_pton(AF_INET6, bind_addr_env, &local_sockaddr_in6.sin6_addr) == 1) {
            local_sockaddr_in6.sin6_family = AF_INET6;
            local_sockaddr_in6.sin6_port = htons(0); // Default port
            bind_addr_set_ipv6 = 1;
            if (debug_enabled) {
                char addr_str[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &local_sockaddr_in6.sin6_addr, addr_str, sizeof(addr_str));
                printf("[DEBUG] Set BIND_ADDR for AF_INET6 to %s\n", addr_str);
            }
        }
        else {
            fprintf(stderr, "[ERROR] Invalid BIND_ADDR: %s\n", bind_addr_env);
        }
    }

    char *bind_port_env = getenv("BIND_PORT");
    if (bind_port_env) {
        int port = atoi(bind_port_env);
        if (bind_addr_set_ipv4) {
            local_sockaddr_in.sin_port = htons(port);
            bind_port_set_ipv4 = 1;
            if (debug_enabled) {
                printf("[DEBUG] Set BIND_PORT for AF_INET to %d\n", port);
            }
        }
        if (bind_addr_set_ipv6) {
            local_sockaddr_in6.sin6_port = htons(port);
            bind_port_set_ipv6 = 1;
            if (debug_enabled) {
                printf("[DEBUG] Set BIND_PORT for AF_INET6 to %d\n", port);
            }
        }
    }

    // Handle socket options
    char *reuse_addr_env = getenv("REUSE_ADDR");
    if (reuse_addr_env) {
        reuse_addr = atoi(reuse_addr_env);
        if (debug_enabled) {
            printf("[DEBUG] Set SO_REUSEADDR to %d\n", reuse_addr);
        }
    }

    char *reuse_port_env = getenv("REUSE_PORT");
    if (reuse_port_env) {
        reuse_port = atoi(reuse_port_env);
        if (debug_enabled) {
            printf("[DEBUG] Set SO_REUSEPORT to %d\n", reuse_port);
        }
    }

    char *ip_transparent_env = getenv("IP_TRANSPARENT");
    if (ip_transparent_env) {
        ip_transparent = atoi(ip_transparent_env);
        if (debug_enabled) {
            printf("[DEBUG] Set IP_TRANSPARENT to %d\n", ip_transparent);
        }
    }
}

// Helper function to get the address family from sockaddr
static unsigned short get_address_family(const struct sockaddr *sk) {
    return sk->sa_family;
}

// Override bind() function
int bind(int fd, const struct sockaddr *sk, socklen_t sl) {
    unsigned short family = get_address_family(sk);

    if (debug_enabled) {
        printf("[DEBUG] bind() called with family %d\n", family);
    }

    // Handle AF_INET
    if (family == AF_INET && bind_addr_set_ipv4) {
        struct sockaddr_in modified_sk = *(struct sockaddr_in *)sk;

        if (bind_addr_set_ipv4) {
            modified_sk.sin_addr.s_addr = local_sockaddr_in.sin_addr.s_addr;
            if (debug_enabled) {
                char addr_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &modified_sk.sin_addr, addr_str, sizeof(addr_str));
                printf("[DEBUG] Overriding AF_INET address to %s\n", addr_str);
            }
        }

        if (bind_port_set_ipv4) {
            modified_sk.sin_port = local_sockaddr_in.sin_port;
            if (debug_enabled) {
                printf("[DEBUG] Overriding AF_INET port to %d\n", ntohs(modified_sk.sin_port));
            }
        }

        // Apply socket options
        if (reuse_addr) {
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse_addr, sizeof(reuse_addr));
            if (debug_enabled) {
                printf("[DEBUG] Applied SO_REUSEADDR\n");
            }
        }

    #ifdef SO_REUSEPORT
        if (reuse_port) {
            setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &reuse_port, sizeof(reuse_port));
            if (debug_enabled) {
                printf("[DEBUG] Applied SO_REUSEPORT\n");
            }
        }
    #endif

        if (ip_transparent) {
            setsockopt(fd, SOL_IP, IP_TRANSPARENT, &ip_transparent, sizeof(ip_transparent));
            if (debug_enabled) {
                printf("[DEBUG] Applied IP_TRANSPARENT\n");
            }
        }

        return real_bind(fd, (struct sockaddr *)&modified_sk, sizeof(struct sockaddr_in));
    }

    // Handle AF_INET6
    else if (family == AF_INET6 && bind_addr_set_ipv6) {
        struct sockaddr_in6 modified_sk6 = *(struct sockaddr_in6 *)sk;

        if (bind_addr_set_ipv6) {
            memcpy(&modified_sk6.sin6_addr, &local_sockaddr_in6.sin6_addr, sizeof(struct in6_addr));
            if (debug_enabled) {
                char addr_str[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &modified_sk6.sin6_addr, addr_str, sizeof(addr_str));
                printf("[DEBUG] Overriding AF_INET6 address to %s\n", addr_str);
            }
        }

        if (bind_port_set_ipv6) {
            modified_sk6.sin6_port = local_sockaddr_in6.sin6_port;
            if (debug_enabled) {
                printf("[DEBUG] Overriding AF_INET6 port to %d\n", ntohs(modified_sk6.sin6_port));
            }
        }

        // Apply socket options
        if (reuse_addr) {
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse_addr, sizeof(reuse_addr));
            if (debug_enabled) {
                printf("[DEBUG] Applied SO_REUSEADDR\n");
            }
        }

    #ifdef SO_REUSEPORT
        if (reuse_port) {
            setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &reuse_port, sizeof(reuse_port));
            if (debug_enabled) {
                printf("[DEBUG] Applied SO_REUSEPORT\n");
            }
        }
    #endif

        if (ip_transparent) {
            setsockopt(fd, SOL_IPV6, IPV6_TRANSPARENT, &ip_transparent, sizeof(ip_transparent));
            if (debug_enabled) {
                printf("[DEBUG] Applied IPV6_TRANSPARENT\n");
            }
        }

        return real_bind(fd, (struct sockaddr *)&modified_sk6, sizeof(struct sockaddr_in6));
    }

    // For other families, proceed without modification
    return real_bind(fd, sk, sl);
}

// Override connect() function
int connect(int fd, const struct sockaddr *sk, socklen_t sl) {
    unsigned short family = get_address_family(sk);

    if (family == AF_INET) {
        if (debug_enabled) {
            printf("[DEBUG] connect(): AF_INET connect() call, binding to local address\n");
        }

        if (bind_addr_set_ipv4 || bind_port_set_ipv4) {
            struct sockaddr_in local_sk = local_sockaddr_in;

            int bind_result = real_bind(fd, (struct sockaddr *)&local_sk, sizeof(struct sockaddr_in));
            if (bind_result != 0 && debug_enabled) {
                perror("[ERROR] bind() failed");
            }
        }

        return real_connect(fd, sk, sl);
    }
    else if (family == AF_INET6) {
        if (debug_enabled) {
            printf("[DEBUG] connect(): AF_INET6 connect() call, binding to local address\n");
        }

        if (bind_addr_set_ipv6 || bind_port_set_ipv6) {
            struct sockaddr_in6 local_sk6 = local_sockaddr_in6;

            int bind_result = real_bind(fd, (struct sockaddr *)&local_sk6, sizeof(struct sockaddr_in6));
            if (bind_result != 0 && debug_enabled) {
                perror("[ERROR] bind() failed");
            }
        }

        return real_connect(fd, sk, sl);
    }
    else {
        // Suppress logging for unsupported families to reduce clutter
        return real_connect(fd, sk, sl);
    }
}

// Remove the main function as it's not needed for LD_PRELOAD libraries

