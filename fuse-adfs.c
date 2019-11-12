#define FUSE_USE_VERSION 32
#define _GNU_SOURCE

#include <fuse_lowlevel.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ADFS_SECT_SIZE  256
#define ADFS_DIR_SECTS    5
#define ADFS_DIR_SIZE  (ADFS_SECT_SIZE*ADFS_DIR_SECTS)

#define ADFS_MAX_NAME    10
#define DIR_HDR_SIZE   0x05
#define DIR_ENT_SIZE   0x1A
#define DIR_FTR_SIZE   0x35
#define DIR_MAX_ENT      47

#define ATTR_UREAD   0x0001
#define ATTR_UWRITE  0x0002
#define ATTR_UEXEC   0x0004
#define ATTR_LOCKED  0x0008
#define ATTR_OREAD   0x0010
#define ATTR_OWRITE  0x0020
#define ATTR_OEXEC   0x0040
#define ATTR_PRIV    0x0080
#define ATTR_DIR     0x0100
#define ATTR_SCANNED 0x1000

struct adfs_inode;
struct adfs_dirent;

struct adfs_inode {
    fuse_ino_t parent;
    unsigned   sector;
    unsigned   load_addr;
    unsigned   exec_addr;
    unsigned   length;
    unsigned   attr;
    struct adfs_dirent *children;
};

static struct adfs_inode *inode_tab;
unsigned itab_used, itab_alloc;

#define INODE_CHUNK_SIZE 256

struct adfs_dirent {
    fuse_ino_t inode;
    char name[ADFS_MAX_NAME+1];
};

static struct options {
    int foreground;
    int read_only;
    int show_help;
    int show_version;
} options;

#define OPTION(t, p) { t, offsetof(struct options, p), 1 }

static const struct fuse_opt option_spec[] = {
    OPTION("-f", foreground),
    OPTION("-h", show_help),
    OPTION("-r", read_only),
    OPTION("-V", show_version),
    FUSE_OPT_END
};

static int dev_fd;
static char *dev_name;
static const char usage[] = "Usage: %s [options] -d <device|img-file> <mountpoint>\n";
static int (*readsect)(off_t posn, unsigned char *buf, size_t size);
static int (*writesect)(off_t posn, const unsigned char *buf, size_t size);
static uid_t uid;
static gid_t gid;

static int rdsect_simple(off_t posn, unsigned char *buf, size_t size)
{
    if (!size)
        return 0;
    if (lseek(dev_fd, posn, SEEK_SET) < 0)
        return errno;
    if (read(dev_fd, buf, size) != size)
        return errno;
    return 0;
}

static int wrsect_simple(off_t posn, const unsigned char *buf, size_t size)
{
    if (!size)
        return 0;
    if (lseek(dev_fd, posn, SEEK_SET) < 0)
        return errno;
    if (write(dev_fd, buf, size) != size)
        return errno;
    return 0;
}

static int rdsect_ide(off_t posn, unsigned char *buf, size_t size)
{
    if (!size)
        return 0;
    if (lseek(dev_fd, posn * 2, SEEK_SET) < 0)
        return errno;
    do {
        unsigned char tbuf[16*ADFS_SECT_SIZE];
        size_t chunk = sizeof(tbuf)/2;
        if (chunk > size)
            chunk = size;
        if (read(dev_fd, tbuf, chunk*2) != chunk*2)
            return errno;
        unsigned char *ptr = tbuf;
        unsigned char *end = buf + chunk;
        while (buf < end) {
            *buf++ = *ptr;
            ptr += 2;
        }
        size -= chunk;
    } while (size);
    return 0;
}

static int wrsect_ide(off_t posn, const unsigned char *buf, size_t size)
{
    if (!size)
        return 0;
    if (lseek(dev_fd, posn * 2, SEEK_SET) < 0)
        return errno;
    do {
        unsigned char tbuf[16*ADFS_SECT_SIZE];
        size_t chunk = sizeof(tbuf)/2;
        if (chunk > size)
            chunk = size;
        unsigned char *ptr = tbuf;
        const unsigned char *end = buf + chunk;
        while (buf < end) {
            *ptr++ = *buf++;
            *ptr++ = 0;
        }
        if (write(dev_fd, tbuf, chunk*2) != chunk*2)
            return errno;
        size -= chunk;
    } while (size);
    return 0;
}

static void make_root(struct adfs_inode *root)
{
    root->parent = 0;
    root->sector = 2;
    root->load_addr = 0;
    root->exec_addr = 0;
    root->length = ADFS_DIR_SIZE;
    root->attr = ATTR_UREAD|ATTR_UWRITE|ATTR_DIR;
    root->children = NULL;
}

static inline uint32_t adfs_get32(const unsigned char *base)
{
    return base[0] | (base[1] << 8) | (base[2] << 16) | (base[3] << 24);
}

static inline uint32_t adfs_get24(const unsigned char *base)
{
    return base[0] | (base[1] << 8) | (base[2] << 16);
}

static const char hst_chars[] = "#$%&.?@^";
static const char bbc_chars[] = "?<;+/#=>";

static int scan_dir(struct adfs_inode *dir, unsigned char *data)
{
    struct adfs_dirent *child = malloc(DIR_MAX_ENT * sizeof(struct adfs_dirent));
    if (!child)
        return errno;
    dir->children = child;
    unsigned char *ptr = data + DIR_HDR_SIZE;
    unsigned char *ftr = data + ADFS_DIR_SIZE - DIR_ENT_SIZE;
    while (ptr < ftr) {
        int i;
        for (i = 0; i < ADFS_MAX_NAME; ++i) {
            int ch = ptr[i] & 0x7f;
            if (!ch || ch == 0x0d)
                break;
            char *ptr = strchr(bbc_chars, ch);
            if (ptr)
                ch = hst_chars[ptr-bbc_chars];
            child->name[i] = ch;
        }
        child->name[i] = 0;
        if (!i)
            return 0;
        if (itab_used >= itab_alloc) {
            size_t newsize = itab_alloc + INODE_CHUNK_SIZE;
            struct adfs_inode *newtab = realloc(inode_tab, newsize * sizeof(struct adfs_inode));
            if (!newtab)
                return errno;
            inode_tab = newtab;
            itab_alloc = newsize;
        }
        fuse_ino_t inum = itab_used++;
        struct adfs_inode *inode = inode_tab + inum;
        unsigned a = 0;
        if (ptr[0] & 0x80) a |= ATTR_UREAD;
        if (ptr[1] & 0x80) a |= ATTR_UWRITE;
        if (ptr[2] & 0x80) a |= ATTR_LOCKED;
        if (ptr[3] & 0x80) a |= ATTR_DIR;
        if (ptr[4] & 0x80) a |= ATTR_UEXEC;
        if (ptr[5] & 0x80) a |= ATTR_OREAD;
        if (ptr[6] & 0x80) a |= ATTR_OWRITE;
        if (ptr[7] & 0x80) a |= ATTR_OEXEC;
        if (ptr[8] & 0x80) a |= ATTR_PRIV;
        inode->attr      = a;
        inode->load_addr = adfs_get32(ptr + 0x0a);
        inode->exec_addr = adfs_get32(ptr + 0x0e);
        inode->length    = adfs_get32(ptr + 0x12);
        inode->sector    = adfs_get24(ptr + 0x16);
        inode->children = NULL;
        child->inode = inum;
        child++;
        ptr += DIR_ENT_SIZE;
    }
    return 0;
}

static int read_dir(struct adfs_inode *dir)
{
    if (dir->children)
        return 0;
    unsigned char buf[ADFS_DIR_SIZE];
    int err = readsect(dir->sector * ADFS_SECT_SIZE, buf, ADFS_DIR_SIZE);
    if (!err)
        err = scan_dir(dir, buf);
    return err;
}

static int adfs_ioselect(void)
{
    if (lseek(dev_fd, 0x200, SEEK_SET) > 0) {
        unsigned char buf[0x0c00];
        ssize_t bytes = read(dev_fd, buf, sizeof(buf));
        if (bytes > 0) {
            if (bytes >= 0x500 && !memcmp(buf+1, "Hugo", 4) && !memcmp(buf, buf+0x4fa, 5)) {
                readsect = rdsect_simple;
                writesect = wrsect_simple;
                return scan_dir(inode_tab, buf);
            }
            if (bytes >= 0xc00 && !memcmp(buf+0x201, "\0H\0u\0g\0o", 8) && !memcmp(buf+0x200, buf+0xbf4, 10)) {
                readsect = rdsect_ide;
                writesect = wrsect_ide;
                unsigned char *dptr = buf;
                unsigned char *sptr = buf+0x200;
                ssize_t size = ADFS_DIR_SIZE;
                do {
                    *dptr++ = *sptr;
                    sptr += 2;
                } while (--size);
                return scan_dir(inode_tab, buf);
            }
            fprintf(stderr, "%s: %s does not contain an ADFS filesystem\n", program_invocation_short_name, dev_name);
        }
        else
            fprintf(stderr, "%s: unable to read %s: %s\n", program_invocation_short_name, dev_name, strerror(errno));
    }
    else
        fprintf(stderr, "%s: unable to seek %s: %s\n", program_invocation_short_name, dev_name, strerror(errno));
    return 1;
}

static int adfs_stat(fuse_ino_t ino, struct stat *stp)
{
    if (ino >= itab_used)
        return -1;
    struct adfs_inode *ent = inode_tab + ino;
    unsigned attr = ent->attr;
    mode_t mode;
    memset(stp, 0, sizeof(struct stat));
    if (attr & ATTR_DIR) {
        mode = S_IFDIR;
        if (attr & ATTR_UREAD)
            mode |= 0500;
        if (attr & ATTR_OREAD)
            mode |= 0055;
        stp->st_nlink = 2;
    }
    else {
        mode = S_IFREG;
        if (attr & ATTR_UREAD)
            mode |= 0444;
        if (attr & ATTR_OREAD)
            mode |= 0044;
        stp->st_nlink = 1;
    }
    if (attr & ATTR_UWRITE)
        mode |= 0200;
    if (attr & ATTR_OWRITE)
        mode |= 0022;
    stp->st_mode = mode;
    stp->st_ino = ino + 1;
    stp->st_size = ent->length;
    stp->st_uid = uid;
    stp->st_gid = gid;
    return 0;
}

static int name_cmp(const char *pattern, const char *candidate)
{
    for (int c = ADFS_MAX_NAME; c; c--) {
        int pat_ch = *pattern++ & 0x7f;
        int can_ch = *candidate++ & 0x7f;
        if (!pat_ch)
            return (!can_ch || can_ch == 0x0d) ? 0 : 1;
        if (pat_ch > ' ')
            pat_ch |= 0x20;
        if (can_ch > ' ')
            can_ch |= 0x20;
        int d = pat_ch - can_ch;
        if (d)
            return d;
    }
    return 0;
}

static void adfs_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
    printf("lookup %ld:%s\n", parent, name);
    if (--parent < itab_used && strlen(name) <= ADFS_MAX_NAME) {
        struct adfs_inode *ent = inode_tab + parent;
        if (ent->attr & ATTR_DIR) {
            int err = read_dir(ent);
            if (!err) {
                ent = inode_tab + parent;
                struct adfs_dirent *ptr = ent->children;
                for (int i = 0; i < DIR_MAX_ENT; ++i) {
                    if (!ptr->name[0])
                        break;
                    int d = name_cmp(name, ptr->name);
                    printf("%s<>%s->%d\n", name, ptr->name, d);
                    if (!d) {
                        struct fuse_entry_param e;
                        if (!adfs_stat(ptr->inode, &e.attr)) {
                            printf("adfs_lookup: %s->%ld\n", name, e.attr.st_ino);
                            e.ino = e.attr.st_ino;
                            e.attr_timeout = 1.0;
                            e.entry_timeout = 1.0;
                            fuse_reply_entry(req, &e);
                        }
                        else
                            fuse_reply_err(req, ENOENT);
                        return;
                    }
                    else if (d < 0)
                        break;
                    ptr++;
                }
                fuse_reply_err(req, ENOENT);
            }
            else
                fuse_reply_err(req, err);
        }
        else
            fuse_reply_err(req, ENOTDIR);
    }
    else
        fuse_reply_err(req, ENOENT);
}

static void adfs_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    printf("getattr %ld\n", ino);
    struct stat stbuf;
    if (!adfs_stat(--ino, &stbuf)) {
        fputs("found\n", stdout);
        fuse_reply_attr(req, &stbuf, 1.0);
    }
    else
        fuse_reply_err(req, ENOENT);
}

static void adfs_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    printf("open %ld\n", ino);

    if (--ino < itab_used) {
        if ((fi->flags & O_ACCMODE) != O_RDONLY)
            fuse_reply_err(req, EACCES);
        else
            fuse_reply_open(req, fi);
    }
    else
        fuse_reply_err(req, ENOENT);
}

static void adfs_opendir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    printf("opendir %ld\n", ino);

    if (--ino < itab_used) {
        int err = read_dir(inode_tab + ino);
        if (!err) {
            struct fuse_file_info fi;
            memset(&fi, 0, sizeof(fi));
            fi.cache_readdir = 1;
            fuse_reply_open(req, &fi);
        }
        else
            fuse_reply_err(req, err);
    }
    else
        fuse_reply_err(req, ENOENT);
}

static void adfs_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi)
{
    printf("readdir %ld %ld %ld\n", ino, size, off);

    if (--ino < itab_used) {
        struct adfs_dirent *ent = inode_tab[ino].children + off;
        int err = 0;
        char buf[size];
        char *ptr = buf;
        size_t avail = size;
        for (int i = DIR_MAX_ENT - off; i; --i) {
            if (!ent->name[0])
                break;
            struct stat stb;
            if ((err = adfs_stat(ent->inode, &stb)))
                break;
            size_t bytes = fuse_add_direntry(req, ptr, avail, ent->name, &stb, ++off);
            if (bytes > avail)
                break;
            ptr += bytes;
            avail -= bytes;
            ent++;
        }
        if (err)
            fuse_reply_err(req, err);
        else
            fuse_reply_buf(req, buf, ptr - buf);
    }
    else
        fuse_reply_err(req, ENOENT);
}

static void adfs_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi)
{
    printf("read %ld: %ld,%ld\n", ino, size, off);

    if (--ino < itab_used) {
        struct adfs_inode *ent = inode_tab + ino;
        off_t left = ent->length - off;
        if (left < 0)
            fuse_reply_buf(req, 0, 0);
        else {
            if (size > left)
                size = left;
            unsigned char buf[size];
            int err = readsect(inode_tab[ino].sector * ADFS_SECT_SIZE + off, buf, size);
            if (!err)
                fuse_reply_buf(req, (char *)buf, size);
            else
                fuse_reply_err(req, err);
        }
    }
    else
        fuse_reply_err(req, ENOENT);
}

static const struct fuse_lowlevel_ops adfs_ops =
{
    .lookup  = adfs_lookup,
    .getattr = adfs_getattr,
    .open    = adfs_open,
    .opendir = adfs_opendir,
    .readdir = adfs_readdir,
    .read    = adfs_read
};

int main(int argc, char *argv[])
{
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    int ret = 1;

    if (!fuse_opt_parse(&args, &options, option_spec, NULL)) {
        if (options.show_help) {
            printf(usage, program_invocation_short_name);
            fuse_cmdline_help();
            fuse_lowlevel_help();
            ret = 0;
        }
        else if (options.show_version) {
            printf("FUSE library version %s\n", fuse_pkgversion());
            fuse_lowlevel_version();
            ret = 0;
        }
        else if (args.argc >= 3) {
            const char *mountpoint = args.argv[--args.argc];
            dev_name = args.argv[--args.argc];
            struct fuse_session *se = fuse_session_new(&args, &adfs_ops, sizeof(adfs_ops), NULL);
            if (se) {
                if ((dev_fd = open(dev_name, options.read_only ? O_RDONLY : O_RDWR)) >= 0) {
                    if ((inode_tab = malloc(INODE_CHUNK_SIZE * sizeof(struct adfs_inode)))) {
                        make_root(inode_tab);
                        itab_used = 1;
                        itab_alloc = INODE_CHUNK_SIZE;
                        struct flock fl;
                        fl.l_type = options.read_only ? F_RDLCK : F_WRLCK;
                        fl.l_whence = SEEK_SET;
                        fl.l_start = 0;
                        fl.l_len = 0;
                        fl.l_pid = 0;
                        if (!fcntl(dev_fd, F_SETLKW, &fl)) {
                            if (!(ret = adfs_ioselect())) {
                                uid = getuid();
                                gid = getgid();
                                if (!fuse_set_signal_handlers(se)) {
                                    if (!fuse_session_mount(se, mountpoint)) {
                                        fuse_daemonize(options.foreground);
                                        ret = fuse_session_loop(se);
                                        fuse_session_unmount(se);
                                    }
                                    fuse_remove_signal_handlers(se);
                                }
                            }
                        }
                        else
                            fprintf(stderr, "%s: unable to lock %s: %s\n", program_invocation_short_name, dev_name, strerror(errno));
                    }
                    else
                        fprintf(stderr, "%s: unable to allocate inode table: %s\n", program_invocation_short_name, strerror(errno));
                    close(dev_fd);
                }
                else
                    fprintf(stderr, "%s: unable to open %s: %s\n", program_invocation_short_name, dev_name, strerror(errno));
                fuse_session_destroy(se);
            }
        }
        else
            fprintf(stderr, usage, program_invocation_short_name);
        fuse_opt_free_args(&args);
    }
    return ret;
}
