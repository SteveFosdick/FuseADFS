#define FUSE_USE_VERSION 32
#define _GNU_SOURCE

#include <fuse_lowlevel.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
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
#define FSMAP_MAX_ENT    82
#define FSMAP_SIZE    0x200

#define ATTR_UREAD   0x0001
#define ATTR_UWRITE  0x0002
#define ATTR_UEXEC   0x0004
#define ATTR_LOCKED  0x0008
#define ATTR_OREAD   0x0010
#define ATTR_OWRITE  0x0020
#define ATTR_OEXEC   0x0040
#define ATTR_PRIV    0x0080
#define ATTR_DIR     0x0100
#define ATTR_DELETED 0x2000
#define ATTR_DELPEND 0x4000

struct adfs_directory;

struct adfs_inode {
    fuse_ino_t parent;
    unsigned   sector;
    unsigned   load_addr;
    unsigned   exec_addr;
    unsigned   length;
    unsigned   attr;
    struct adfs_directory *dir_contents;
    unsigned   use_count;
};

static struct adfs_inode *inode_tab;
unsigned itab_used, itab_alloc;

#define INODE_CHUNK_SIZE 256

struct adfs_dirent {
    fuse_ino_t inode;
    char name[ADFS_MAX_NAME+1];
};

struct adfs_directory {
    unsigned num_ent;
    struct adfs_dirent ents[DIR_MAX_ENT];
    unsigned char footer[DIR_FTR_SIZE];
    char dirty;
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
static unsigned char fsmap[FSMAP_SIZE];
static int fsmap_dirty;

static inline uint32_t adfs_get32(const unsigned char *base)
{
    return base[0] | (base[1] << 8) | (base[2] << 16) | (base[3] << 24);
}

static inline uint32_t adfs_get24(const unsigned char *base)
{
    return base[0] | (base[1] << 8) | (base[2] << 16);
}

static inline void adfs_put32(unsigned char *base, uint32_t value)
{
    base[0] = value & 0xff;
    base[1] = (value >> 8) & 0xff;
    base[2] = (value >> 16) & 0xff;
    base[3] = (value >> 24) & 0xff;
}

static inline void adfs_put24(unsigned char *base, uint32_t value)
{
    base[0] = value & 0xff;
    base[1] = (value >> 8) & 0xff;
    base[2] = (value >> 16) & 0xff;
}

#ifdef DEBUG
#define debug(...) fuse_log(FUSE_LOG_DEBUG, __VA_ARGS__)

static void print_dir(const char *when, struct adfs_directory *contents)
{
    unsigned num_ent = contents->num_ent;
    fuse_log(FUSE_LOG_DEBUG, "%s: entries=%d\n", when, num_ent);
    struct adfs_dirent *child = contents->ents;
    while (num_ent--) {
        fuse_log(FUSE_LOG_DEBUG, "%s: %ld %s %c\n", when, child->inode, child->name, inode_tab[child->inode].attr & ATTR_DIR ? 'd' : '-');
        child++;
    }
}

static void print_map(const char *when)
{
    int num_ent = fsmap[0x1fe];
    fuse_log(FUSE_LOG_DEBUG, "%s: entries=%d\n", when, num_ent);
    for (int ent = 0; ent < num_ent; ent += 3) {
        unsigned posn = adfs_get24(fsmap + ent);
        unsigned size = adfs_get24(fsmap + 0x100 + ent);
        fuse_log(FUSE_LOG_DEBUG, "%s: posn=%d, size=%d\n", when, posn, size);
    }
}

#else
#define debug(...)
#define print_dir(when, contents)
#define print_map(when)
#endif

static int rdsect_simple(off_t posn, unsigned char *buf, size_t size)
{
    debug("rdsect_simple posn=%ld, buf=%p, size=%ld\n", posn, buf, size);
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
    root->dir_contents = NULL;
}

static int new_inode(fuse_ino_t parent, unsigned sector, unsigned length, unsigned attr, unsigned load_addr, unsigned exec_addr)
{
    if (itab_used >= itab_alloc) {
        size_t newsize = itab_alloc + INODE_CHUNK_SIZE;
        struct adfs_inode *newtab = realloc(inode_tab, newsize * sizeof(struct adfs_inode));
        if (!newtab)
            return -errno;
        inode_tab = newtab;
        itab_alloc = newsize;
    }
    int inum = itab_used++;
    struct adfs_inode *inode = inode_tab + inum;
    inode->parent = parent;
    inode->sector = sector;
    inode->length = length;
    inode->attr = attr;
    inode->load_addr = load_addr;
    inode->exec_addr = exec_addr;
    inode->dir_contents = NULL;
    inode->use_count = 0;
    return inum;
}

static const char hst_chars[] = "#$%&.?@^";
static const char bbc_chars[] = "?<;+/#=>";

static int hst2bbc(char *bbc, const char *hst)
{
    char *end = bbc + ADFS_MAX_NAME;
    int ch;
    while ((ch = *hst++)) {
        if (bbc >= end)
            return ENAMETOOLONG;
        if (ch & 0x80)
            return EINVAL;
        const char *ptr = strchr(hst_chars, ch);
        if (ptr)
            ch = bbc_chars[ptr-hst_chars];
        *bbc++ = ch;
    }
    *bbc = 0;
    return 0;
}

static void bbc2hst(char *hst, const char *bbc)
{
    int ch;
    while ((ch = *bbc++)) {
        const char *ptr = strchr(bbc_chars, ch);
        if (ptr)
            ch = hst_chars[ptr-bbc_chars];
        *hst++ = ch;
    }
    *hst = 0;
}

static int scan_dir(struct adfs_inode *dir, unsigned char *data)
{
    struct adfs_directory *contents = malloc(sizeof(struct adfs_directory));
    if (!contents)
        return errno;
    fuse_ino_t dir_ino = dir - inode_tab;
    dir->dir_contents = contents;
    struct adfs_dirent *child = contents->ents;
    unsigned char *ptr = data + DIR_HDR_SIZE;
    unsigned char *ftr = data + ADFS_DIR_SIZE - DIR_FTR_SIZE;
    while (ptr < ftr) {
        int i;
        for (i = 0; i < ADFS_MAX_NAME; ++i) {
            int ch = ptr[i] & 0x7f;
            if (!ch || ch == 0x0d)
                break;
            child->name[i] = ch;
        }
        child->name[i] = 0;
        if (!i)
            break;
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
        int inum = new_inode(dir_ino, adfs_get24(ptr + 0x16), adfs_get32(ptr + 0x12), a, adfs_get32(ptr + 0x0a), adfs_get32(ptr + 0x0e));
        if (inum < 0)
            return -inum;
        child->inode = inum;
        child++;
        ptr += DIR_ENT_SIZE;
    }
    contents->num_ent = child - contents->ents;
    memcpy(contents->footer, ftr, DIR_FTR_SIZE);
    contents->dirty = 0;
    return 0;
}

static int read_dir(struct adfs_inode *dir)
{
    if (dir->dir_contents)
        return 0;
    unsigned char buf[ADFS_DIR_SIZE];
    int err = readsect(dir->sector * ADFS_SECT_SIZE, buf, ADFS_DIR_SIZE);
    if (!err)
        err = scan_dir(dir, buf);
    return err;
}

static int write_dir(struct adfs_inode *dir)
{
    struct adfs_directory *contents = dir->dir_contents;
    unsigned char buf[ADFS_DIR_SIZE];
    ++(contents->footer[0x2f]);
    memcpy(buf, contents->footer + 0x2f, 5);
    struct adfs_dirent *child = contents->ents;
    unsigned num_ent = contents->num_ent;
    unsigned char *ent = buf + DIR_HDR_SIZE;
    unsigned char *ftr = buf + ADFS_DIR_SIZE - DIR_FTR_SIZE;
    while (num_ent--) {
        int i = 0;
        while (i < ADFS_MAX_NAME) {
            int ch = child->name[i];
            if (!ch) {
                ent[i++] = 0x0d;
                break;
            }
            ent[i++] = ch;
        }
        while (i < ADFS_MAX_NAME)
            ent[i++] = 0;
        struct adfs_inode *inode = inode_tab + child->inode;
        unsigned a = inode->attr;
        if (a & ATTR_UREAD)  ent[0] |= 0x80;
        if (a & ATTR_UWRITE) ent[1] |= 0x80;
        if (a & ATTR_LOCKED) ent[2] |= 0x80;
        if (a & ATTR_DIR)    ent[3] |= 0x80;
        if (a & ATTR_UEXEC)  ent[4] |= 0x80;
        if (a & ATTR_OREAD)  ent[5] |= 0x80;
        if (a & ATTR_OWRITE) ent[6] |= 0x80;
        if (a & ATTR_OEXEC)  ent[7] |= 0x80;
        if (a & ATTR_PRIV)   ent[8] |= 0x80;
        adfs_put32(ent + 0x0a, inode->load_addr);
        adfs_put32(ent + 0x0e, inode->exec_addr);
        adfs_put32(ent + 0x12, inode->length);
        adfs_put24(ent + 0x16, inode->sector);
        child++;
        ent += DIR_ENT_SIZE;
    }
    if (ent < ftr)
        *ent = 0;
    memcpy(ftr, contents->footer, DIR_FTR_SIZE);
    return writesect(dir->sector * ADFS_SECT_SIZE, buf, ADFS_DIR_SIZE);
}

static int name_cmp(const char *pattern, const char *candidate)
{
    for (int c = ADFS_MAX_NAME; c; c--) {
        int pat_ch = *pattern++;
        int can_ch = *candidate++;
        if (!pat_ch)
            return (!can_ch || can_ch == 0x0d) ? 0 : 1;
        int d = (pat_ch & 0x5f) - (can_ch & 0x5f);
        if (d)
            return d;
    }
    return 0;
}

static int insert_name(struct adfs_inode *dir, const char *name, fuse_ino_t ino)
{
    struct adfs_directory *contents = dir->dir_contents;
    int num_ent = contents->num_ent;
    if (num_ent == DIR_MAX_ENT)
        return ENOSPC;
    struct adfs_dirent *child = contents->ents;
    while (num_ent--) {
        debug("insert_name: comparing %s <> %s\n", name, child->name);
        int d = name_cmp(name, child->name);
        if (!d)
            return EEXIST;
        if (d < 0)
            break;
        child++;
    }
    if (++num_ent > 0) {
        size_t bytes = num_ent * sizeof(struct adfs_dirent);
        debug("num_ent=%d, next=%s, moving %ld bytes\n", num_ent, child->name, bytes);
        memmove(child + 1, child, bytes);
    }
    strncpy(child->name, name, ADFS_MAX_NAME);
    child->inode = ino;
    contents->num_ent++;
    contents->dirty = 1;
    return 0;
}

static unsigned checksum(unsigned char *base)
{
    int i = 255, c = 0;
    unsigned sum = 255;
    while (--i >= 0) {
        sum += base[i] + c;
        c = 0;
        if (sum >= 256) {
            sum &= 0xff;
            c = 1;
        }
    }
    return sum;
}

static int read_fsmap(void)
{
    int err = readsect(0, fsmap, FSMAP_SIZE);
    if (!err) {
        if (checksum(fsmap) == fsmap[0xff] && checksum(fsmap + 0x100) == fsmap[0x1ff])
            return 0;
        fuse_log(FUSE_LOG_ERR, "%s: %s has a bad free space map\n", program_invocation_short_name, dev_name);
        return -1;
    }
    fuse_log(FUSE_LOG_ERR, "%s: unable to read free space map for %s: %s\n", program_invocation_short_name, dev_name, strerror(err));
    return err;
}

static int write_fsmap(void)
{
    fsmap[0x0ff] = checksum(fsmap);
    fsmap[0x1ff] = checksum(fsmap + 0x100);
    return writesect(0, fsmap, FSMAP_SIZE);
}

static int extend_inplace(unsigned ssect, unsigned avail, size_t end)
{
    unsigned end_sect = ssect + (avail / ADFS_SECT_SIZE);
    debug("extend_inplace: end_sect=%d\n", end_sect);
    int num_ent = fsmap[0x1fe];
    for (int ent = 0; ent < num_ent; ent += 3) {
        unsigned sector = adfs_get24(fsmap + ent);
        debug("extend_inplace: entry, sector=%d\n", sector);
        if (sector == end_sect) {
            debug("extend_inplace: found entry at %d\n", ent);
            unsigned reqd = end - avail;
            unsigned size = adfs_get24(fsmap + 0x100 + ent);
            if (size >= reqd) {
                if (size == reqd) {
                    debug("extend_inplace: exact match\n");
                    /* exact match so remove entry */
                    size_t bytes = (num_ent - ent) * 3;
                    memmove(fsmap + ent, fsmap + ent + 3, bytes);
                    memmove(fsmap + 0x100 + ent, fsmap + 0x100 + ent + 3, bytes);
                    fsmap[0x1fe]--;
                }
                else {
                    debug("extend_inplace: adjusting entry\n");
                    adfs_put24(fsmap + ent, sector + reqd);
                    adfs_put24(fsmap + 0x100 + ent, size - reqd);
                }
                fsmap_dirty = 1;
                return 0;
            }
            else
                return 1; /* space too small */
        }
    }
    return 1;
}

static int alloc_space(size_t bytes)
{
    size_t reqd = (bytes + 255) >> 8;
    int num_ent = fsmap[0x1fe];
    for (int ent = 0; ent < num_ent; ent += 3) {
        size_t size = adfs_get24(fsmap + 0x100 + ent);
        if (size >= reqd) {
            unsigned sector = adfs_get24(fsmap + ent);
            if (size == reqd) {
                /* exact match so remove entry */
                size_t bytes = (num_ent - ent) * 3;
                memmove(fsmap + ent, fsmap + ent + 3, bytes);
                memmove(fsmap + 0x100 + ent, fsmap + 0x100 + ent + 3, bytes);
                fsmap[0x1fe] -= 3;
            }
            else {
                adfs_put24(fsmap + ent, sector + reqd);
                adfs_put24(fsmap + 0x100 + ent, size - reqd);
            }
            fsmap_dirty = 1;
            return sector;
        }
    }
    return 0;
}

static int free_space(unsigned sector, size_t length)
{
    size_t sects = (length + 255) >> 8;
    int num_ent = fsmap[0x1fe];
    int ent;
    print_map("before");
    for (ent = 0; ent < num_ent; ent += 3) {
        unsigned posn = adfs_get24(fsmap + ent);
        unsigned size = adfs_get24(fsmap + 0x100 + ent);
        if ((posn + size) == sector) { // coallesce
            size += sects;
            debug("free_space: coalescing with previous, posn=%d, new_size=%d\n", posn, size);
            adfs_put24(fsmap + 0x100 + ent, size);
            fsmap_dirty = 1;
            return 0;
        }
        if (posn > sector) {
            if ((sector + sects) == posn) {
                posn = sector;
                size += sects;
                debug("free_space: coalescing with next, new_posn=%d, new_size=%d\n", posn, size);
                adfs_put24(fsmap + ent, posn);
                adfs_put24(fsmap + 0x100 + ent, size);
                fsmap_dirty = 1;
                return 0;
            }
            if (num_ent >= FSMAP_MAX_ENT)
                return ENOSPC;
            debug("free_space: inserting new entry\n");
            size_t bytes = (num_ent - ent) * 3;
            memmove(fsmap + ent + 3, fsmap + ent, bytes);
            memmove(fsmap + 0x100 + ent + 3, fsmap + 0x100 + ent, bytes);
            break;
        }
    }
    if (num_ent >= FSMAP_MAX_ENT)
        return ENOSPC;
    debug("free_space: new entry, posn=%d, size=%d\n", sector, sects);
    adfs_put24(fsmap + ent, sector);
    adfs_put24(fsmap + 0x100 + ent, sects);
    fsmap[0x1fe] += 3;
    fsmap_dirty = 1;
    print_map("after");
    return 0;
}

static int move_file(struct adfs_inode *inode, unsigned dsect, size_t bytes)
{
    unsigned src = inode->sector * ADFS_SECT_SIZE;
    unsigned dest = dsect  * ADFS_SECT_SIZE;
    unsigned char buf[4096];
    int err;

    debug("moving file from %d (sector %d) to %d (sector %d), size=%ld\n", src, inode->sector, dest, dsect, bytes);

    while (bytes >= sizeof(buf)) {
        if ((err = readsect(src, buf, sizeof(buf))))
            return err;
        src += sizeof(buf);
        if ((err = writesect(dest, buf, sizeof(buf))))
            return err;
        dest += sizeof(buf);
    }
    if (bytes) {
        if ((err = readsect(src, buf, bytes)))
            return err;
        if ((err = writesect(dest, buf, bytes)))
            return err;
    }
    err = free_space(inode->sector, bytes);
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
            fuse_log(FUSE_LOG_ERR, "%s: %s does not contain an ADFS filesystem\n", program_invocation_short_name, dev_name);
        }
        else
            fuse_log(FUSE_LOG_ERR, "%s: unable to read %s: %s\n", program_invocation_short_name, dev_name, strerror(errno));
    }
    else
        fuse_log(FUSE_LOG_ERR, "%s: unable to seek %s: %s\n", program_invocation_short_name, dev_name, strerror(errno));
    return 1;
}

static void write_dirty(void)
{
    struct adfs_inode *inode = inode_tab;
    struct adfs_inode *end = inode + itab_used;
    while (inode < end) {
        if (inode->attr & ATTR_DELPEND)
            debug("write_dirty: pending delete\n");
        if (!(inode->attr & ATTR_DELETED)) {
            struct adfs_directory *dir = inode->dir_contents;
            if (dir && dir->dirty) {
                debug("write_dirty: writing dir %s\n", dir->footer+1);
                int err = write_dir(inode);
                if (err)
                    fuse_log(FUSE_LOG_ERR, "%s: %s: unable to write directory back to filesystem: %s\n", program_invocation_short_name, dev_name, strerror(err));
            }
        }
        ++inode;
    }
    if (fsmap_dirty) {
        fuse_log(FUSE_LOG_DEBUG, "write_dirty: writing fsmap\n");
        int err = write_fsmap();
        if (err)
            fuse_log(FUSE_LOG_ERR, "%s: %s: unable to write free space map back to filesystem: %s\n", program_invocation_short_name, dev_name, strerror(err));
    }
    fuse_log(FUSE_LOG_DEBUG, "done\n");
}

static void fill_stat(fuse_ino_t ino, struct adfs_inode *inode, struct stat *stp)
{
    mode_t mode;
    unsigned attr = inode->attr;
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
    stp->st_ino = ino;
    stp->st_size = inode->length;
    stp->st_uid = uid;
    stp->st_gid = gid;
}

static void stat_reply(fuse_req_t req, fuse_ino_t ino, struct adfs_inode *inode)
{
    struct fuse_entry_param e;
    memset(&e, 0, sizeof(e));
    fill_stat(ino, inode, &e.attr);
    e.ino = ino;
    e.attr_timeout = ULONG_MAX;
    e.entry_timeout = ULONG_MAX;
    inode->use_count++;
    fuse_reply_entry(req, &e);
}

static void adfs_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
    debug("lookup %ld %s\n", parent, name);
    int err = ENOENT;
    if (--parent < itab_used) {
        char bbc_name[ADFS_MAX_NAME];
        if (!(err = hst2bbc(bbc_name, name))) {
            struct adfs_inode *inode = inode_tab + parent;
            unsigned attr = inode->attr;
            if (!(attr & ATTR_DELETED)) {
                if (attr & ATTR_DIR) {
                    err = read_dir(inode);
                    if (!err) {
                        struct adfs_directory *contents = inode_tab[parent].dir_contents;
                        unsigned num_ent = contents->num_ent;
                        struct adfs_dirent *ptr = contents->ents;
                        while (num_ent--) {
                            int d = name_cmp(bbc_name, ptr->name);
                            debug("comparing %s <> %s -> %d\n", bbc_name, ptr->name, d);
                            if (!d) {
                                stat_reply(req, ptr->inode + 1, inode_tab + ptr->inode);
                                    return;
                            }
                            else if (d < 0)
                                break;
                            ptr++;
                        }
                        err = ENOENT;
                    }
                }
            }
        }
    }
    fuse_reply_err(req, err);
}

static void adfs_forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup)
{
    debug("forget %ld\n", ino);
    if (--ino < itab_used) {
        struct adfs_inode *inode = inode_tab + ino;
        if (!(inode->use_count -= nlookup)) {
            if (inode->attr & ATTR_DELPEND) {
                debug("forget: processing pending delete\n");
                if (!free_space(inode->sector, inode->length))
                    inode->attr = (inode->attr & ~ATTR_DELPEND) | ATTR_DELETED;
            }
        }
    }
    fuse_reply_none(req);
}

static void adfs_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    debug("getattr %ld\n", ino);
    if (ino <= itab_used) {
        struct adfs_inode *inode = inode_tab + ino - 1;
        if (!(inode->attr & ATTR_DELETED)) {
            struct stat stbuf;
            memset(&stbuf, 0, sizeof(stbuf));
            fill_stat(ino, inode, &stbuf);
            fuse_reply_attr(req, &stbuf, ULONG_MAX);
            return;
        }
    }
        fuse_reply_err(req, ENOENT);
}

static unsigned mode2attr(mode_t mode)
{
    unsigned attr = 0;
    if (mode & S_IRUSR) attr |= ATTR_UREAD;
    if (mode & S_IWUSR) attr |= ATTR_UWRITE;
    if (mode & (S_IRGRP|S_IROTH)) attr |= ATTR_OREAD;
    if (mode & (S_IWGRP|S_IWOTH)) attr |= ATTR_OWRITE;
    return attr;
}

static void adfs_mknod(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode, dev_t rdev)
{
    debug("mknod %ld %s\n", parent, name);
    int err = EROFS;
    if (!options.read_only) {
        err = ENOENT;
        if (--parent < itab_used) {
            struct adfs_inode *pnode = inode_tab + parent;
            if (!(pnode->attr & ATTR_DELETED)) {
                if ((mode & S_IFMT) == S_IFREG) {
                    char bbc_name[ADFS_MAX_NAME];
                    if (!(err = hst2bbc(bbc_name, name))) {
                        int inum = new_inode(parent, 0, 0, mode2attr(mode), 0, 0);
                        if (inum >= 0) {
                            err = insert_name(pnode, bbc_name, inum);
                            if (!err) {
                                stat_reply(req, inum+1, inode_tab + inum);
                                return;
                            }
                        }
                        else
                            err = -inum;
                    }
                }
                else
                    err = ENOTSUP;
            }
        }
    }
    fuse_reply_err(req, err);
}

static void adfs_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode)
{
    debug("mknod %ld %s %o\n", parent, name, mode);
    int err = EROFS;
    if (!options.read_only) {
        err = ENOENT;
        if (--parent < itab_used) {
            struct adfs_inode *pnode = inode_tab + parent;
            if (!(pnode->attr & ATTR_DELETED)) {
                char bbc_name[ADFS_MAX_NAME];
                if (!(err = hst2bbc(bbc_name, name))) {
                    struct adfs_directory *contents = malloc(sizeof(struct adfs_directory));
                    if (contents) {
                        unsigned sector = alloc_space(ADFS_DIR_SIZE);
                        if (sector) {
                            int inum = new_inode(parent, sector, ADFS_DIR_SIZE, mode2attr(mode)|ATTR_DIR, 0, 0);
                            if (inum >= 0) {
                                err = insert_name(pnode, bbc_name, inum);
                                if (!err) {
                                    contents->num_ent = 0;
                                    contents->dirty = 1;
                                    memset(contents->footer, 0, DIR_FTR_SIZE);
                                    memcpy(contents->footer+1, bbc_name, sizeof(bbc_name));   // directory name.
                                    memcpy(contents->footer+0xe, bbc_name, sizeof(bbc_name)); // directory title.
                                    adfs_put24(contents->footer+0xb, pnode->sector);
                                    memcpy(contents->footer+0x30, "Hugo", 4);
                                    inode_tab[inum].dir_contents = contents;
                                    stat_reply(req, inum+1, inode_tab + inum);
                                    return;
                                }
                            }
                            else
                                err = -inum;
                        }
                        else
                            err = ENOSPC;
                    }
                    else
                        err = ENOMEM;
                }
            }
        }
    }
    fuse_reply_err(req, err);
}

static void delete_common(fuse_req_t req, fuse_ino_t parent, const char *name, int (*callback)(struct adfs_dirent *child))
{
    int err = EROFS;
    if (!options.read_only) {
        err = ENOENT;
        if (--parent < itab_used) {
            struct adfs_inode *pnode = inode_tab + parent;
            if (!(pnode->attr & ATTR_DELETED)) {
                char bbc_name[ADFS_MAX_NAME];
                if (!(err = hst2bbc(bbc_name, name))) {
                    err = ENOENT;
                    struct adfs_directory *contents = pnode->dir_contents;
                    int num_ent = contents->num_ent;
                    struct adfs_dirent *child = contents->ents;
                    while (num_ent--) {
                        debug("delete_common: comparing %s <> %s\n", name, child->name);
                        int d = name_cmp(bbc_name, child->name);
                        if (!d) {
                            print_dir("before", contents);
                            if (!(err = callback(child))) {
                                if (++num_ent > 0) {
                                    size_t bytes = num_ent * sizeof(struct adfs_dirent);
                                    debug("delete_common: num_ent=%d, next=%s, moving %ld bytes\n", num_ent, child->name, bytes);
                                    memmove(child, child+1, bytes);
                                }
                                contents->num_ent--;
                                contents->dirty = 1;
                                print_dir("after", contents);
                            }
                            break;
                        }
                        if (d < 0)
                            break;
                        child++;
                    }
                }
            }
        }
    }
    fuse_reply_err(req, err);
}

static int delete_file(struct adfs_dirent *child)
{
    struct adfs_inode *inode = inode_tab + child->inode;
    if (inode->attr & ATTR_DIR)
        return EISDIR;
    inode->attr |= ATTR_DELPEND;
    return 0;
}

static void adfs_unlink(fuse_req_t req, fuse_ino_t parent, const char *name)
{
    debug("unlink %ld %s\n", parent, name);
    delete_common(req, parent, name, delete_file);
}

static int delete_dir(struct adfs_dirent *child)
{
    struct adfs_inode *inode = inode_tab + child->inode;
    if (!(inode->attr & ATTR_DIR))
        return ENOTDIR;
    read_dir(inode);
    if (inode->dir_contents->num_ent)
        return ENOTEMPTY;
    inode->attr |= ATTR_DELPEND;
    return 0;
}

static void adfs_rmdir(fuse_req_t req, fuse_ino_t parent, const char *name)
{
    debug("rmdir %ld %s\n", parent, name);
    delete_common(req, parent, name, delete_dir);
}

static void adfs_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    debug("open: %ld\n", ino);
    int err = ENOENT;
    if (--ino < itab_used) {
        struct adfs_inode *inode = inode_tab + ino;
        if (!(inode->attr & ATTR_DELETED)) {
            mode_t accmode = fi->flags & O_ACCMODE;
            unsigned mask;
            if (accmode == O_RDONLY)
                mask = ATTR_UREAD;
            else if (options.read_only) {
                fuse_reply_err(req, EROFS);
                return;
            }
            else if (accmode == O_WRONLY)
                mask = ATTR_UWRITE;
            else
                mask = ATTR_UREAD|ATTR_UWRITE;
            if ((inode->attr & mask) == mask) {
                if (fi->flags & O_TRUNC) {
                    err = free_space(inode->sector, inode->length);
                    if (err) {
                        fuse_reply_err(req, err);
                        return;
                    }
                    inode->length = 0;
                    inode_tab[inode->parent].dir_contents->dirty = 1;
                }
                fuse_reply_open(req, fi);
                return;
            }
            else
                err = EACCES;
        }
    }
    fuse_reply_err(req, err);
}

static void adfs_opendir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    debug("opendir %ld\n", ino);
    int err = ENOENT;
    if (--ino < itab_used) {
        struct adfs_inode *inode = inode_tab + ino;
        unsigned attr = inode->attr;
        if (!(attr & ATTR_DELETED)) {
            if (attr & ATTR_UREAD) {
                err = read_dir(inode);
                if (!err) {
                    struct fuse_file_info fi;
                    fi.cache_readdir = 1;
                    fuse_reply_open(req, &fi);
                    return;
                }
            }
            else
                err = EACCES;
        }
    }
    fuse_reply_err(req, err);
}

static void adfs_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi)
{
    debug("readdir %ld size=%ld off=%ld\n", ino, size, off);
    int err = ENOENT;
    if (--ino < itab_used) {
        struct adfs_inode *inode = inode_tab + ino;
        if (!(inode->attr & ATTR_DELETED)) {
            struct adfs_directory *contents = inode->dir_contents;
            struct adfs_dirent *ent = contents->ents + off;
            unsigned num_ent = contents->num_ent - off;
            err = 0;
            char buf[size];
            char *ptr = buf;
            size_t avail = size;
            while (num_ent--) {
                struct stat stb;
                memset(&stb, 0, sizeof(stb));
                fill_stat(ent->inode + 1, inode_tab + ent->inode, &stb);
                char hst_name[ADFS_MAX_NAME];
                bbc2hst(hst_name, ent->name);
                size_t bytes = fuse_add_direntry(req, ptr, avail, hst_name, &stb, ++off);
                if (bytes > avail)
                    break;
                ptr += bytes;
                avail -= bytes;
                ent++;
            }
            if (!err) {
                fuse_reply_buf(req, buf, ptr - buf);
                return;
            }
        }
    }
    fuse_reply_err(req, err);
}

static void adfs_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi)
{
    debug("read %ld size=%ld off=%ld\n", ino, size, off);
    int err = ENOENT;
    if (--ino < itab_used) {
        struct adfs_inode *inode = inode_tab + ino;
        if (!(inode->attr & ATTR_DELETED)) {
            off_t left = inode->length - off;
            if (left < 0) {
                fuse_reply_buf(req, 0, 0);
                return;
            }
            else {
                if (size > left)
                    size = left;
                unsigned char buf[size];
                int err = readsect(inode->sector * ADFS_SECT_SIZE + off, buf, size);
                if (!err) {
                    fuse_reply_buf(req, (char *)buf, size);
                    return;
                }
            }
        }
    }
    fuse_reply_err(req, err);
}

static void adfs_write(fuse_req_t req, fuse_ino_t ino, const char *buf, size_t size, off_t off, struct fuse_file_info *fi)
{
    debug("write: %ld size=%ld off=%ld\n", ino, size, off);
    int err = ENOENT;
    if (--ino < itab_used) {
        struct adfs_inode *inode = inode_tab + ino;
        if (!(inode->attr & ATTR_DELETED)) {
            size_t end = off + size;
            size_t avail = (inode->length + 255) & ~0xff;
            debug("adfs_write: end=%ld, avail=%ld\n", end, avail);
            if (end > avail) {
                debug("adfs_write: need more space\n");
                if (avail == 0 || extend_inplace(inode->sector, avail, end)) {
                    debug("adfs_write: can't extend in place\n");
                    unsigned sector = alloc_space(end);
                    debug("adfs_write: new start sector %d\n", sector);
                    if (!sector) {
                        fuse_reply_err(req, ENOSPC);
                        return;
                    }
                    if (avail) {
                        int err = move_file(inode, sector, avail);
                        if (err) {
                            fuse_reply_err(req, err);
                            return;
                        }
                    }
                    inode->sector = sector;
                }
            }
            err = writesect(inode->sector * ADFS_SECT_SIZE + off, (unsigned char *)buf, size);
            if (!err) {
                if (end > inode->length) {
                    inode->length = end;
                    inode_tab[inode->parent].dir_contents->dirty = 1;
                }
                fuse_reply_write(req, size);
                return;
            }
        }
    }
    fuse_reply_err(req, err);
}

static void adfs_flush(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    debug("flush %ld\n", ino);
    if (--ino < itab_used) {
        struct adfs_inode *inode = inode_tab + ino;
        if (!(inode->attr & ATTR_DELETED)) {
            struct adfs_inode *parent = inode_tab + inode->parent;
            int err1 = 0, err2 = 0;
            if (parent->dir_contents->dirty)
                if (!(err1 = write_dir(parent)))
                    parent->dir_contents->dirty = 0;
            if (fsmap_dirty)
                if (!(err2 = write_fsmap()))
                    fsmap_dirty = 0;
            if (!err1)
                err1 = err2;
            fuse_reply_err(req, err1);
            return;
        }
    }
    fuse_reply_err(req, ENOENT);
}

static const struct fuse_lowlevel_ops adfs_ops =
{
    .lookup  = adfs_lookup,
    .forget  = adfs_forget,
    .getattr = adfs_getattr,
    .mknod   = adfs_mknod,
    .mkdir   = adfs_mkdir,
    .unlink  = adfs_unlink,
    .rmdir   = adfs_rmdir,
    .open    = adfs_open,
    .read    = adfs_read,
    .write   = adfs_write,
    .flush   = adfs_flush,
    .opendir = adfs_opendir,
    .readdir = adfs_readdir
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
                                if (options.read_only || !read_fsmap()) {
                                    uid = getuid();
                                    gid = getgid();
                                    if (!fuse_set_signal_handlers(se)) {
                                        if (!fuse_session_mount(se, mountpoint)) {
                                            fuse_daemonize(options.foreground);
                                            ret = fuse_session_loop(se);
                                            fuse_session_unmount(se);
                                            write_dirty();
                                        }
                                        fuse_remove_signal_handlers(se);
                                    }
                                }
                            }
                        }
                        else
                            fuse_log(FUSE_LOG_ERR, "%s: unable to lock %s: %s\n", program_invocation_short_name, dev_name, strerror(errno));
                    }
                    else
                        fuse_log(FUSE_LOG_ERR, "%s: unable to allocate inode table: %s\n", program_invocation_short_name, strerror(errno));
                    close(dev_fd);
                }
                else
                    fuse_log(FUSE_LOG_ERR, "%s: unable to open %s: %s\n", program_invocation_short_name, dev_name, strerror(errno));
                fuse_session_destroy(se);
            }
        }
        else
            fprintf(stderr, usage, program_invocation_short_name);
        fuse_opt_free_args(&args);
    }
    return ret;
}
