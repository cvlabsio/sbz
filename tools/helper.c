#include <sys/mman.h>
#include <sys/stat.h>

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// ----------------------------------------------------------------------

__attribute__((noreturn)) void bail(const char* format, ...)
{
    va_list args;
    va_start(args, format);

    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");

    va_end(args);

    exit(1);
}

void unprotect(uintptr_t location, size_t len)
{
    long page_size = sysconf(_SC_PAGESIZE);

    if (location % page_size != 0) {
        location -= (location % page_size);
    }

    if (mprotect((void*)location, len, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
        bail("mprotect() at 0x%p failed: %s", location, strerror(errno));
    }
}

void hook_copy(uintptr_t location, char* buf, size_t len)
{
    unprotect(location, len);
    memcpy((void*)location, buf, len);
}

void hook_call(uintptr_t location, void* callback)
{
    unprotect(location, 4);

    int32_t displacement = (callback - (void*)location);

    *(uint32_t*)(location) = 0x40000000 | ((displacement / 4) & 0x3fffffff);
}

void hook_jump(uintptr_t location, void* callback)
{
    unprotect(location, 8);

    int32_t displacement = (callback - (void*)location);

    if (displacement < -16777216 || displacement > 16777215) {
        bail("hook_jump: displacement too large between 0x%p and 0x%p\n", callback,
            location);
    }

    *(uint32_t*)(location) = 0x10800000 | ((displacement / 4) & 0x3fffff);
    *(uint32_t*)(location + 4) = 0x01000000;
}

void hook_vtable_entry(uintptr_t location, size_t index, void* callback)
{
    location = location + (index * 4);

    unprotect(location, 4);

    *(void**)(location) = callback;
}

// ----------------------------------------------------------------------

typedef int (*vfs_read_f)(void* handle, void* buffer, size_t size);
typedef int (*vfs_write_f)(void* handle, void* buffer, size_t size);
typedef void* (*vfs_open_f)(int id_1, int id_2, int id_3);
typedef void (*vfs_close_f)(void* handle);
typedef size_t (*vfs_size_f)(void* handle);

typedef struct {
    vfs_read_f read;
    vfs_write_f write;
    vfs_open_f open;
    vfs_close_f close;
    vfs_size_f size;
} VfsApi;

typedef struct {
    int id_1;
    int id_2;
    int id_3;
    char __pad[144]; // rest isn't relevant for our usecase
} DiskVfsHandle;

static const vfs_write_f disk_vfs_write_original = (vfs_write_f)0x1e2c4;

int disk_vfs_write_stub(DiskVfsHandle* handle, void* buffer, size_t size)
{
    printf("=== dumping object %08x %08x %08x ===\n", handle->id_1, handle->id_2, handle->id_3);

    char fname[256];
    snprintf(fname, sizeof(fname), "vfs/%08x_%08x_%08x.bin", handle->id_1, handle->id_2, handle->id_3);

    FILE* f = fopen(fname, "wb+");
    fwrite(buffer, sizeof(char), size, f);
    fclose(f);

    return disk_vfs_write_original(handle, buffer, size);
}

// ----------------------------------------------------------------------

typedef int (*encrypt_formatted_message_f)(int key, char* buf, char* unk1,
    size_t len);

static const encrypt_formatted_message_f encrypt_formatted_message_original = (encrypt_formatted_message_f)0x2a1a8;

int encrypt_formatted_message_stub(int key, char* buf, char* unk1, size_t len)
{
    printf("%s\n", buf);

    return encrypt_formatted_message_original(key, buf, unk1, len);
}

// ----------------------------------------------------------------------

__attribute__((constructor)) void run()
{
    // disable annoying (and inconsequential) fork() call
    hook_copy(0x1a68c, "\x02\x80\x00\x05", 4);

    // redirect log messages to stdout
    hook_call(0x2b0f4, encrypt_formatted_message_stub);

    // dump bundled modules and data as they're initially written to disk VFS storage files
    mkdir("vfs", 0644);
    hook_call(0x39ab8, disk_vfs_write_stub);
}
