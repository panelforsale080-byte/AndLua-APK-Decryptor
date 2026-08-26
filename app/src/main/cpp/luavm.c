#include <android/log.h>
#include <dirent.h>
#include <dlfcn.h>
#include <jni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "AlpLuaVm", __VA_ARGS__)

typedef void *(*lua_newstate_t)(void);
typedef void (*lua_close_t)(void *);
typedef int (*lua_loadbuffer_t)(void *, const char *, size_t, const char *);
typedef int (*lua_loadbufferx_t)(void *, const char *, size_t, const char *, const char *);
typedef int (*lua_writer_t)(void *, const void *, size_t, void *);
typedef int (*lua_dump_t)(void *, lua_writer_t, void *);
typedef int (*lua_dump3_t)(void *, lua_writer_t, void *, int);

static char g_err[256];

static void set_err(const char *s) {
    size_t n = strlen(s);
    if (n > sizeof(g_err) - 1) {
        n = sizeof(g_err) - 1;
    }
    memcpy(g_err, s, n);
    g_err[n] = 0;
}

typedef struct {
    unsigned char *p;
    size_t n;
    size_t cap;
} Buf;

static int writer(void *L, const void *data, size_t sz, void *ud) {
    Buf *b = (Buf *) ud;
    (void) L;
    if (sz == 0) {
        return 0;
    }
    if (b->n + sz > b->cap) {
        size_t cap = b->cap == 0 ? 4096 : b->cap;
        while (cap < b->n + sz) {
            cap *= 2;
        }
        unsigned char *np = (unsigned char *) realloc(b->p, cap);
        if (!np) {
            return 1;
        }
        b->p = np;
        b->cap = cap;
    }
    memcpy(b->p + b->n, data, sz);
    b->n += sz;
    return 0;
}

static int is_so(const char *name) {
    size_t n = strlen(name);
    return n > 3 && strcmp(name + n - 3, ".so") == 0;
}

static void *open_lua(const char *dir) {
    DIR *d = opendir(dir);
    if (!d) {
        set_err("no lib dir");
        return NULL;
    }
    char path[512];
    struct dirent *ent;
    void *found = NULL;
    while ((ent = readdir(d)) != NULL) {
        if (!is_so(ent->d_name)) {
            continue;
        }
        if (strstr(ent->d_name, "luajava") != NULL) {
            continue;
        }
        snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);
        void *h = dlopen(path, RTLD_NOW | RTLD_GLOBAL);
        if (!h) {
            LOGI("dlopen fail %s %s", path, dlerror());
            continue;
        }
        if (dlsym(h, "luaL_newstate") != NULL) {
            LOGI("lua lib %s", path);
            found = h;
            break;
        }
        dlclose(h);
    }
    closedir(d);
    if (!found) {
        set_err("no lua runtime in apk libs");
    }
    return found;
}

static unsigned char *run_undump(void *h, const unsigned char *in, size_t in_n,
                                 size_t *out_n) {
    lua_newstate_t pnew = (lua_newstate_t) dlsym(h, "luaL_newstate");
    lua_close_t pclose = (lua_close_t) dlsym(h, "lua_close");
    lua_loadbufferx_t ploadx = (lua_loadbufferx_t) dlsym(h, "luaL_loadbufferx");
    lua_loadbuffer_t pload = (lua_loadbuffer_t) dlsym(h, "luaL_loadbuffer");
    lua_dump_t pdump = (lua_dump_t) dlsym(h, "lua_dump");
    if (!pnew || !pclose || (!ploadx && !pload) || !pdump) {
        set_err("lua symbols missing");
        return NULL;
    }
    void *L = pnew();
    if (!L) {
        set_err("luaL_newstate failed");
        return NULL;
    }
    int rc;
    if (ploadx) {
        rc = ploadx(L, (const char *) in, in_n, "=dump", NULL);
    } else {
        rc = pload(L, (const char *) in, in_n, "=dump");
    }
    if (rc != 0) {
        set_err("runtime load failed");
        pclose(L);
        return NULL;
    }
    Buf b;
    memset(&b, 0, sizeof(b));
    lua_dump3_t pdump3 = (lua_dump3_t) pdump;
    rc = pdump(L, writer, &b);
    if (rc != 0 && b.n == 0) {
        rc = pdump3(L, writer, &b, 1);
    }
    pclose(L);
    if (b.n == 0) {
        free(b.p);
        set_err("runtime dump empty");
        return NULL;
    }
    *out_n = b.n;
    return b.p;
}

JNIEXPORT jbyteArray JNICALL
Java_com_andlua_decryptor_LuaVm_undumpNative(JNIEnv *env, jclass cls, jstring jdir,
                                       jbyteArray jlua) {
    (void) cls;
    g_err[0] = 0;
    if (!jdir || !jlua) {
        set_err("bad args");
        return NULL;
    }
    const char *dir = (*env)->GetStringUTFChars(env, jdir, NULL);
    void *h = open_lua(dir);
    (*env)->ReleaseStringUTFChars(env, jdir, dir);
    if (!h) {
        return NULL;
    }
    jsize n = (*env)->GetArrayLength(env, jlua);
    jbyte *in = (*env)->GetByteArrayElements(env, jlua, NULL);
    size_t out_n = 0;
    unsigned char *out = run_undump(h, (const unsigned char *) in, (size_t) n, &out_n);
    (*env)->ReleaseByteArrayElements(env, jlua, in, JNI_ABORT);
    if (!out) {
        return NULL;
    }
    jbyteArray arr = (*env)->NewByteArray(env, (jsize) out_n);
    (*env)->SetByteArrayRegion(env, arr, 0, (jsize) out_n, (jbyte *) out);
    free(out);
    return arr;
}

JNIEXPORT jstring JNICALL
Java_com_andlua_decryptor_LuaVm_lastError(JNIEnv *env, jclass cls) {
    (void) cls;
    return (*env)->NewStringUTF(env, g_err);
}
