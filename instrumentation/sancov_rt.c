/*
 * Zero-Hunter-Engine v3.0 - SanitizerCoverage + CmpLog + Persistent UNIX Forkserver Runtime
 * Educational & Authorized Defensive Research Only
 *
 * Compile WITHOUT -fsanitize-coverage or -fsanitize=address:
 *   gcc -O3 -fPIC -c instrumentation/sancov_rt.c -o instrumentation/sancov_rt.o
 *
 * Features:
 *   1. ASLR-invariant 64KB AFL-style edge hit-count bitmap (ZERO_HUNTER_COV_FILE)
 *   2. 256-slot CmpLog operand ring buffer for integer & memcmp/strcmp comparisons
 *   3. High-speed UNIX Pipe Forkserver (ZERO_HUNTER_FORKSRV_CTL_FD / ST_FD) skipping
 *      dynamic linker & ASAN 16TB shadow setup per iteration (1,500-3,500+ exec/s)
 */

#define _GNU_SOURCE
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>

#define ZH_MAP_SIZE          (1u << 16)   /* 64 KB edge bitmap */
#define ZH_CMP_RING_SIZE     256u         /* Power of 2 */
#define ZH_CMP_TYPE_INT      1u
#define ZH_CMP_TYPE_MEM      2u
#define ZH_FORKSRV_HELLO     0x5A483330u  /* "ZH30" handshake magic */

typedef struct __attribute__((packed)) {
    uint8_t  type;        /* ZH_CMP_TYPE_INT or ZH_CMP_TYPE_MEM */
    uint8_t  size;        /* 1..14 bytes */
    uint16_t pc_low;      /* Low 16 bits of caller PC */
    uint8_t  op1[14];     /* First operand bytes */
    uint8_t  op2[14];     /* Second operand bytes */
} zh_cmp_entry_t;         /* Exactly 32 bytes */

typedef struct __attribute__((packed)) {
    uint8_t        edges[ZH_MAP_SIZE];
    uint32_t       cmp_write_idx;
    uint32_t       total_blocks;
    zh_cmp_entry_t cmp_ring[ZH_CMP_RING_SIZE];
} zh_cov_shm_t;

static uint8_t       local_dummy_edges[ZH_MAP_SIZE];
static zh_cov_shm_t *zh_shm = NULL;
static uint8_t      *zh_edges = local_dummy_edges;
static __thread uint32_t zh_prev_loc = 0;
static volatile int  zh_in_hook = 0;

static void zh_cov_init(void);

static inline uint32_t zh_hash_pc(uintptr_t pc) {
    /* Subtract function address inside same binary so PIE/ASLR slide cancels out! */
    uint64_t x = (uint64_t)(pc - (uintptr_t)&zh_cov_init);
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return (uint32_t)(x & (ZH_MAP_SIZE - 1u));
}

__attribute__((constructor(101)))
static void zh_cov_init(void) {
    const char *cov_path = getenv("ZERO_HUNTER_COV_FILE");
    if (!cov_path || !cov_path[0]) {
        return;
    }

    int fd = open(cov_path, O_RDWR);
    if (fd < 0) {
        return;
    }

    void *mem = mmap(NULL, sizeof(zh_cov_shm_t), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);

    if (mem == MAP_FAILED || !mem) {
        return;
    }

    zh_shm = (zh_cov_shm_t *)mem;
    zh_edges = zh_shm->edges;
}

/*
 * Persistent Forkserver Loop (runs at priority 65535 AFTER libasan, libubsan,
 * and zh_cov_init have completed one-time initialization, right before main()).
 */
__attribute__((constructor(65535)))
static void zh_forkserver_init(void) {
    const char *ctl_env = getenv("ZERO_HUNTER_FORKSRV_CTL_FD");
    const char *st_env  = getenv("ZERO_HUNTER_FORKSRV_ST_FD");
    if (!ctl_env || !st_env) {
        return; /* Normal standalone execution */
    }

    int ctl_fd = atoi(ctl_env);
    int st_fd  = atoi(st_env);
    if (ctl_fd <= 2 || st_fd <= 2) {
        return;
    }

    const char *stdin_file = getenv("ZERO_HUNTER_STDIN_FILE");
    const char *err_file   = getenv("ZERO_HUNTER_ERR_FILE");
    const char *out_file   = getenv("ZERO_HUNTER_OUT_FILE");

    /* Send 4-byte readiness handshake to Python controller */
    uint32_t hello = ZH_FORKSRV_HELLO;
    if (write(st_fd, &hello, 4) != 4) {
        _exit(1);
    }

    while (1) {
        uint32_t cmd = 0;
        ssize_t r = read(ctl_fd, &cmd, 4);
        if (r != 4) {
            _exit(0); /* Controller closed pipe -> clean shutdown */
        }

        pid_t child_pid = fork();
        if (child_pid < 0) {
            _exit(1);
        }

        if (child_pid == 0) {
            /* Forked child: rebind stdio if requested and enter main() immediately */
            close(ctl_fd);
            close(st_fd);
            zh_prev_loc = 0;

            if (stdin_file && stdin_file[0]) {
                int infd = open(stdin_file, O_RDONLY);
                if (infd >= 0) {
                    dup2(infd, STDIN_FILENO);
                    close(infd);
                }
            }

            if (out_file && out_file[0]) {
                int outfd = open(out_file, O_WRONLY | O_CREAT | O_TRUNC, 0600);
                if (outfd >= 0) {
                    dup2(outfd, STDOUT_FILENO);
                    close(outfd);
                }
            } else {
                int devnull = open("/dev/null", O_WRONLY);
                if (devnull >= 0) {
                    dup2(devnull, STDOUT_FILENO);
                    close(devnull);
                }
            }

            if (err_file && err_file[0]) {
                int errfd = open(err_file, O_WRONLY | O_CREAT | O_TRUNC, 0600);
                if (errfd >= 0) {
                    dup2(errfd, STDERR_FILENO);
                    close(errfd);
                }
            }
            return; /* Proceed directly into target main()! */
        }

        /* Forkserver parent: report child PID, wait for completion, report wait status */
        int32_t pid32 = (int32_t)child_pid;
        if (write(st_fd, &pid32, 4) != 4) {
            _exit(1);
        }

        int status = 0;
        if (waitpid(child_pid, &status, 0) < 0) {
            _exit(1);
        }

        int32_t st32 = (int32_t)status;
        if (write(st_fd, &st32, 4) != 4) {
            _exit(1);
        }
    }
}

/* --- Edge Coverage Callbacks (GCC & Clang) --- */

void __sanitizer_cov_trace_pc(void) {
    uintptr_t pc = (uintptr_t)__builtin_return_address(0);
    uint32_t cur_loc = zh_hash_pc(pc);
    uint32_t idx = (cur_loc ^ zh_prev_loc) & (ZH_MAP_SIZE - 1u);
    uint8_t val = zh_edges[idx];
    if (val < 255u) {
        zh_edges[idx] = (uint8_t)(val + 1u);
    }
    zh_prev_loc = cur_loc >> 1;
}

void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {
    static uint32_t guard_counter = 1;
    if (start == stop || *start) return;
    for (uint32_t *x = start; x < stop; x++) {
        *x = guard_counter++;
    }
    if (zh_shm) {
        zh_shm->total_blocks = guard_counter - 1;
    }
}

void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
    if (!*guard) return;
    uint32_t cur_loc = (*guard * 2654435761u) & (ZH_MAP_SIZE - 1u);
    uint32_t idx = (cur_loc ^ zh_prev_loc) & (ZH_MAP_SIZE - 1u);
    uint8_t val = zh_edges[idx];
    if (val < 255u) {
        zh_edges[idx] = (uint8_t)(val + 1u);
    }
    zh_prev_loc = cur_loc >> 1;
}

/* --- Integer & Memory Comparison Hooks (CmpLog / I2S) --- */

static inline void zh_record_int_cmp(uintptr_t pc, uint64_t a, uint64_t b, uint8_t size) {
    if (!zh_shm || a == b) return;
    if (size == 1 && (a == 0 || b == 0)) return;

    uint32_t slot = __atomic_fetch_add(&zh_shm->cmp_write_idx, 1u, __ATOMIC_RELAXED) & (ZH_CMP_RING_SIZE - 1u);
    zh_cmp_entry_t *e = &zh_shm->cmp_ring[slot];
    e->type = ZH_CMP_TYPE_INT;
    e->size = size;
    e->pc_low = (uint16_t)((pc - (uintptr_t)&zh_cov_init) & 0xFFFFu);
    memcpy(e->op1, &a, size);
    memcpy(e->op2, &b, size);
}

static inline void zh_record_mem_cmp(uintptr_t pc, const void *s1, const void *s2, size_t n) {
    if (!zh_shm || !s1 || !s2 || n < 2) return;
    if (zh_in_hook) return;
    zh_in_hook = 1;

    uint8_t copy_len = (n > 14u) ? 14u : (uint8_t)n;
    uint32_t slot = __atomic_fetch_add(&zh_shm->cmp_write_idx, 1u, __ATOMIC_RELAXED) & (ZH_CMP_RING_SIZE - 1u);
    zh_cmp_entry_t *e = &zh_shm->cmp_ring[slot];
    e->type = ZH_CMP_TYPE_MEM;
    e->size = copy_len;
    e->pc_low = (uint16_t)((pc - (uintptr_t)&zh_cov_init) & 0xFFFFu);
    memcpy(e->op1, s1, copy_len);
    memcpy(e->op2, s2, copy_len);

    zh_in_hook = 0;
}

void __sanitizer_cov_trace_cmp1(uint8_t a, uint8_t b) {
    zh_record_int_cmp((uintptr_t)__builtin_return_address(0), a, b, 1);
}
void __sanitizer_cov_trace_cmp2(uint16_t a, uint16_t b) {
    zh_record_int_cmp((uintptr_t)__builtin_return_address(0), a, b, 2);
}
void __sanitizer_cov_trace_cmp4(uint32_t a, uint32_t b) {
    zh_record_int_cmp((uintptr_t)__builtin_return_address(0), a, b, 4);
}
void __sanitizer_cov_trace_cmp8(uint64_t a, uint64_t b) {
    zh_record_int_cmp((uintptr_t)__builtin_return_address(0), a, b, 8);
}

void __sanitizer_cov_trace_const_cmp1(uint8_t a, uint8_t b) {
    zh_record_int_cmp((uintptr_t)__builtin_return_address(0), a, b, 1);
}
void __sanitizer_cov_trace_const_cmp2(uint16_t a, uint16_t b) {
    zh_record_int_cmp((uintptr_t)__builtin_return_address(0), a, b, 2);
}
void __sanitizer_cov_trace_const_cmp4(uint32_t a, uint32_t b) {
    zh_record_int_cmp((uintptr_t)__builtin_return_address(0), a, b, 4);
}
void __sanitizer_cov_trace_const_cmp8(uint64_t a, uint64_t b) {
    zh_record_int_cmp((uintptr_t)__builtin_return_address(0), a, b, 8);
}

void __sanitizer_cov_trace_switch(uint64_t val, uint64_t *cases) {
    if (!cases || !zh_shm) return;
    uint64_t count = cases[0];
    uint64_t bits  = cases[1];
    uint8_t  size  = (uint8_t)(bits / 8u);
    if (size < 1 || size > 8) size = 4;
    uintptr_t pc = (uintptr_t)__builtin_return_address(0);
    uint64_t limit = (count > 8u) ? 8u : count;
    for (uint64_t i = 0; i < limit; i++) {
        zh_record_int_cmp(pc, val, cases[2 + i], size);
    }
}

/* ASAN weak hooks for strcmp / strncmp / memcmp */
void __sanitizer_weak_hook_memcmp(void *called_pc, const void *s1, const void *s2, size_t n, int result) {
    if (result != 0) {
        zh_record_mem_cmp((uintptr_t)called_pc, s1, s2, n);
    }
}

void __sanitizer_weak_hook_strncmp(void *called_pc, const char *s1, const char *s2, size_t n, int result) {
    if (result != 0 && s1 && s2) {
        size_t l1 = strnlen(s1, 14);
        size_t l2 = strnlen(s2, 14);
        size_t len = (l1 > l2) ? l1 : l2;
        if (len > n) len = n;
        zh_record_mem_cmp((uintptr_t)called_pc, s1, s2, len);
    }
}

void __sanitizer_weak_hook_strcmp(void *called_pc, const char *s1, const char *s2, int result) {
    if (result != 0 && s1 && s2) {
        size_t l1 = strnlen(s1, 14);
        size_t l2 = strnlen(s2, 14);
        size_t len = (l1 > l2) ? l1 : l2;
        zh_record_mem_cmp((uintptr_t)called_pc, s1, s2, len);
    }
}
