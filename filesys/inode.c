#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include <limits.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "../devices/block.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

/*Inode block sector status identifiers*/
#define INODE_SECTORS_UNALLOCATED UINT_MAX

/*MUST ADD UP TO THE DIFFERENCE BETWEEN (BLOCK_SECTOR_SIZE) AND inode_disk's METADATA*/
#define INODE_SECTOR_NUMBER_SIZE (sizeof(unsigned))
#define SECTOR_POINTERS_PER_BLOCK (BLOCK_SECTOR_SIZE / INODE_SECTOR_NUMBER_SIZE)

#define INODE_POINTERS 125
#define INODE_DIRECT 120
#define INODE_SINGLY_INDIRECT 4
#define INODE_DOUBLY_INDIRECT 1

#define DIRECT_SIZE BLOCK_SECTOR_SIZE
#define SINGLY_SIZE (BLOCK_SECTOR_SIZE * SECTOR_POINTERS_PER_BLOCK)
#define DOUBLY_SIZE (BLOCK_SECTOR_SIZE * SECTOR_POINTERS_PER_BLOCK * SECTOR_POINTERS_PER_BLOCK)

#define DIRECT_REGION_SIZE (DIRECT_SIZE * INODE_DIRECT)
#define SINGLY_REGION_SIZE (SINGLY_SIZE  * INODE_SINGLY_INDIRECT)
#define DOUBLY_REGION_SIZE (DOUBLY_SIZE * INODE_DOUBLY_INDIRECT)

#define INODE_DIRECT_OFF(off) off
#define INODE_SINGLY_OFF(off) (off - DIRECT_REGION_SIZE)
#define INODE_DOUBLY_OFF(off) (off - (DIRECT_REGION_SIZE + SINGLY_REGION_SIZE))

#define INODE_IS_DIRECT(off) (((off < DIRECT_REGION_SIZE) && (off >= 0)) ? true : false)
#define INODE_IS_SINGLY(off) (((off > DIRECT_REGION_SIZE) && (off < (SINGLY_REGION_SIZE + DIRECT_REGION_SIZE))) ? true : false)
#define INODE_IS_DOUBLY(off) (((off > (DIRECT_REGION_SIZE + SINGLY_REGION_SIZE)) \
                    && (off < (DOUBLY_REGION_SIZE + SINGLY_REGION_SIZE + DIRECT_REGION_SIZE))) ? true : false)

enum sector_t {
    eDIRECT, eSINGLY, eDOUBLY
};

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk {
    unsigned isDir;                     /*determines */
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
    block_sector_t direct[INODE_DIRECT];
    block_sector_t singly[INODE_SINGLY_INDIRECT];
    block_sector_t doubly[INODE_DOUBLY_INDIRECT];
};

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors(off_t size) {
    return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct inode_disk data;             /* Inode content. */
};

/*sets 3 off_t pointers  the indices of direct, singly indirect, and doubly indirect sectors
  for an offset into an inode. 
  returns the type of acccess the offset is*/
static enum sector_t
inode_getIndices(off_t *direct, off_t *singly, off_t *doubly, off_t off);

/*file extension routine - allocated enough blocks to make reads from and writes to
 blocks up to offset bytes from the start of an inode's data valid*/
static bool
inode_extend(struct inode *inode, off_t offset);

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector(struct inode *inode, off_t pos, bool write) {
    ASSERT(inode != NULL);

    enum sector_t type;

    off_t directI;
    off_t singlyI;
    off_t doublyI;

    block_sector_t singly_indirect_sec;
    block_sector_t doubly_indirect_sec;

    block_sector_t *direct_buff = (block_sector_t *) inode->data.direct;
    block_sector_t *singly_indirect_buff = (block_sector_t *) inode->data.singly;

    block_sector_t *direct_buff_tmp;
    block_sector_t *singly_indirect_buff_tmp;

    block_sector_t ret = INODE_SECTORS_UNALLOCATED;

    ASSERT((direct_buff_tmp = (block_sector_t *) malloc(BLOCK_SECTOR_SIZE)));
    ASSERT((singly_indirect_buff_tmp = (block_sector_t *) malloc(BLOCK_SECTOR_SIZE)));

    if (write)
        inode_extend(inode, pos);

    type = inode_getIndices(&directI, &singlyI, &doublyI, pos);

    switch (type) {
        case eDOUBLY:
            if ((doubly_indirect_sec = inode->data.doubly[doublyI]) == INODE_SECTORS_UNALLOCATED) {
                ret = INODE_SECTORS_UNALLOCATED;
                break;
            } else {
                singly_indirect_buff = singly_indirect_buff_tmp;
                block_read(fs_device, doubly_indirect_sec, singly_indirect_buff);
            }

        case eSINGLY:
            if ((singly_indirect_sec = singly_indirect_buff[singlyI]) == INODE_SECTORS_UNALLOCATED) {
                ret = INODE_SECTORS_UNALLOCATED;
                break;
            } else {
                direct_buff = direct_buff_tmp;
                block_read(fs_device, singly_indirect_sec, direct_buff);
            }

        case eDIRECT:
            ret = singly_indirect_buff[directI];

        default: /*should never be the case*/
            break;
    }

    free(direct_buff_tmp);
    free(singly_indirect_buff_tmp);

    return ret;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init(void) {
    list_init(&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create(block_sector_t sector, off_t length, bool isDir) {
    struct inode_disk *disk_inode = NULL;
    bool success = false;

    ASSERT(length >= 0);

    /* If this assertion fails, the inode structure is not exactly
       one sector in size, and you should fix that. */
    ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);

    if ((disk_inode = calloc(1, sizeof *disk_inode)) != NULL) {
        /*new type implementation. Initialize the inode to length 0*/
        disk_inode->isDir = isDir;
        disk_inode->length = 0;
        disk_inode->magic = INODE_MAGIC;

        //TODO Ask Nico what num sectors instead of bytes?
        memset(disk_inode->direct, INODE_SECTORS_UNALLOCATED, INODE_DIRECT);
        memset(disk_inode->singly, INODE_SECTORS_UNALLOCATED, INODE_SINGLY_INDIRECT);
        memset(disk_inode->doubly, INODE_SECTORS_UNALLOCATED, INODE_DOUBLY_INDIRECT);

        block_write(fs_device, sector, disk_inode);
        free(disk_inode);
        success = true;
    }

    return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open(block_sector_t sector) {
    struct list_elem *e;
    struct inode *inode;

    /* Check whether this inode is already open. */
    for (e = list_begin(&open_inodes); e != list_end(&open_inodes);
         e = list_next(e)) {
        inode = list_entry(e,
        struct inode, elem);
        if (inode->sector == sector) {
            inode_reopen(inode);
            return inode;
        }
    }

    /* Allocate memory. */
    inode = malloc(sizeof *inode);
    if (inode == NULL)
        return NULL;

    /* Initialize. */
    list_push_front(&open_inodes, &inode->elem);
    inode->sector = sector;
    inode->open_cnt = 1;
    inode->deny_write_cnt = 0;
    inode->removed = false;
    block_read(fs_device, inode->sector, &inode->data);
    return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen(struct inode *inode) {
    if (inode != NULL)
        inode->open_cnt++;
    return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber(const struct inode *inode) {
    return inode->sector;
}

bool inode_isdir(struct inode *inode) {
  return inode->data.isDir;
}

static enum sector_t
inode_getIndices(off_t *direct, off_t *singly, off_t *doubly, off_t off) {
    ASSERT((direct && singly && doubly) != (off_t)NULL);

    *direct = (off_t)NULL;
    *singly = (off_t)NULL;
    *doubly = (off_t)NULL;

    if (INODE_IS_DIRECT(off)) {
        *direct = INODE_DIRECT_OFF(off) / DIRECT_SIZE;
        return eDIRECT;
    } else if (INODE_IS_SINGLY(off)) {
        *singly = INODE_SINGLY_OFF(off) / SINGLY_SIZE;
        *direct = (INODE_SINGLY_OFF(off) % SINGLY_SIZE) / DIRECT_SIZE;
        return eSINGLY;
    } else if (INODE_IS_DOUBLY(off)) {
        *doubly = INODE_DOUBLY_OFF(off) / DOUBLY_SIZE;
        *singly = (INODE_DOUBLY_OFF(off) % DOUBLY_SIZE) / SINGLY_SIZE;
        *direct = (INODE_DOUBLY_OFF(off) % SINGLY_SIZE) / DIRECT_SIZE;
        return eDOUBLY;
    } else
        return (enum sector_t) NULL;
}

/* frees up the the block sectores based on type. */
void
inode_free_map_release(struct inode *inode) {

    off_t direct, singly, doubly;
    enum sector_t type = inode_getIndices(&direct, &singly, &doubly, inode->data.length);

    switch (type) {
        /** ----------------Direct--------------------------- */
        case eDIRECT:
            free_map_release(inode->data.direct[0], direct);
            break;

            /** ----------------Singly--------------------------- */
        case eSINGLY:

            //release all direct
            free_map_release(inode->data.direct[0], INODE_DIRECT);

            /** release singly sectors one by one */
            for (int sngly_indx = 0; sngly_indx <= singly; ++sngly_indx) {//TODO <= or < ?

                block_sector_t singly_block = (block_sector_t *) inode->data.singly[sngly_indx];
                off_t blk_size = (sngly_indx == singly) ? direct : (off_t) SECTOR_POINTERS_PER_BLOCK;
                free_map_release(singly_block[0], blk_size);
            }

            break;

            /** ----------------Doubly--------------------------- */
        case eDOUBLY:

            //release all direct
            free_map_release(inode->data.direct[0], INODE_DIRECT);

            //release all singly
            for (int sngly_blk = 0; sngly_blk <= INODE_SINGLY_INDIRECT; ++sngly_blk) {
                free_map_release(singly_block[0], SECTOR_POINTERS_PER_BLOCK);
            }

            /** release doubly sectors one by one */
            for (int dbly_index = 0; dbly_index <= doubly; ++dbly_index) {

                block_sector_t doubly_block = (block_sector_t*) inode->data.doubly[dbly_index];
                off_t dbly_blk_size = (dbly_index == doubly) ? singly : (off_t) SECTOR_POINTERS_PER_BLOCK;

                for (int sngly_index = 0;
                     sngly_index <= dbly_blk_size; ++sngly_index) {//TODO <= or < ?

                    block_sector_t  singly_block = (block_sector_t*) doubly_block[sngly_index];
                    off_t sngly_blk_size = (sngly_index == singly) ? direct : (off_t) SECTOR_POINTERS_PER_BLOCK;
                    free_map_release(singly_block[0], sngly_blk_size);
                }
            }
            break;
    }

}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close(struct inode *inode) {
    /* Ignore null pointer. */
    if (inode == NULL)
        return;

    /* Release resources if this was the last opener. */
    if (--inode->open_cnt == 0) {
        /* Remove from inode list and release lock. */
        list_remove(&inode->elem);

        /* Deallocate blocks if removed. */
        if (inode->removed) {
            free_map_release(inode->sector, 1);
            inode_free_map_release(inode);
        }

        free(inode);
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove(struct inode *inode) {
    ASSERT(inode != NULL);
    inode->removed = true;
}

static bool
inode_extend(struct inode *inode, off_t offset) {
    ASSERT(inode != NULL);

    bool ret = true;
    bool done = false;

    size_t newSize = inode->data.length;

    size_t offBlocks = offset / BLOCK_SECTOR_SIZE;
    size_t oldBlocks = newSize / BLOCK_SECTOR_SIZE;
    size_t newBlocks;

    off_t start = inode->data.length + BLOCK_SECTOR_SIZE;
    off_t directStart, singlyStart, doublyStart;
    off_t directEnd, singlyEnd, doublyEnd;
    enum sector_t typeStart;

    static char zeros[BLOCK_SECTOR_SIZE];
    static char unalloc[BLOCK_SECTOR_SIZE];

    block_sector_t *singly_indirect_buff;
    block_sector_t *direct_buff;

    block_sector_t *singly_indirect_buff_tmp;
    block_sector_t *direct_buff_tmp;

    block_sector_t direct_sec, singly_sec, doubly_sec;

    if (((oldBlocks = (newSize / BLOCK_SECTOR_SIZE)) == 0) && (newSize != 0))
        oldBlocks = 1;
    if (((offBlocks = (offset / BLOCK_SECTOR_SIZE)) == 0) && (offset != 0))
        offBlocks = 1;
    newBlocks = oldBlocks;

    if (offBlocks > oldBlocks)
        do
            newBlocks *= 2;
        while (newBlocks < offBlocks);
    else
        return true;

    ASSERT((singly_indirect_buff_tmp = (block_sector_t *) malloc(BLOCK_SECTOR_SIZE)));
    ASSERT((direct_buff_tmp = (block_sector_t *) malloc(BLOCK_SECTOR_SIZE)));

    memset(unalloc, INODE_SECTORS_UNALLOCATED, BLOCK_SECTOR_SIZE);

    typeStart = inode_getIndices(&directStart, &singlyStart, &doublyStart, (start += BLOCK_SECTOR_SIZE));
    inode_getIndices(&directEnd, &singlyEnd, &doublyEnd, newBlocks);

    if (doublyEnd == (off_t)NULL)
        doublyEnd = doublyStart + 1;
    if (singlyEnd == (off_t)NULL)
        singlyEnd = singlyStart + 1;

    while (true) {
        direct_buff = inode->data.direct;
        singly_indirect_buff = inode->data.singly;
        switch (typeStart) {
            case eDOUBLY:
                if ((doubly_sec = inode->data.doubly[doublyStart]) == INODE_SECTORS_UNALLOCATED) {
                    free_map_allocate(1, (block_sector_t *) &inode->data.doubly[doublyStart]);
                    doubly_sec = inode->data.doubly[doublyStart];
                    block_write(fs_device, doubly_sec, unalloc);
                }

                singly_indirect_buff = singly_indirect_buff_tmp;
                block_read(fs_device, doubly_sec, singly_indirect_buff);
            case eSINGLY:
                if ((singly_sec = singly_indirect_buff[singlyStart]) == INODE_SECTORS_UNALLOCATED) {
                    free_map_allocate(1, (block_sector_t *) &singly_indirect_buff[singlyStart]);
                    singly_sec = singly_indirect_buff[singlyStart];
                    block_write(fs_device, singly_sec, unalloc);
                }

                direct_buff = direct_buff_tmp;
                block_read(fs_device, doubly_sec, singly_indirect_buff);
            case eDIRECT:
                if ((direct_sec = singly_indirect_buff[directStart]) == INODE_SECTORS_UNALLOCATED) {
                    free_map_allocate(1, (block_sector_t *) &singly_indirect_buff[directStart]);
                    direct_sec = direct_buff[directStart];
                }

                block_write(fs_device, direct_sec, zeros);
        }

        if (done)
            break;

        typeStart = inode_getIndices(&directStart, &singlyStart, &doublyStart, (start += BLOCK_SECTOR_SIZE));
        if (directStart == directEnd && singlyStart == singlyEnd && doublyStart == doublyEnd)
            done = true;
    }

    free(direct_buff_tmp);
    free(singly_indirect_buff_tmp);

    return ret;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at(struct inode *inode, void *buffer_, off_t size, off_t offset) {
    uint8_t *buffer = buffer_;
    off_t bytes_read = 0;
    uint8_t *bounce = NULL;

    while (size > 0) {
        /* Disk sector to read, starting byte offset within sector. */
        block_sector_t sector_idx = byte_to_sector(inode, offset, false);
        if (sector_idx == INODE_SECTORS_UNALLOCATED)
            break;

        int sector_ofs = offset % BLOCK_SECTOR_SIZE;

        /* Bytes left in inode, bytes left in sector, lesser of the two. */
        off_t inode_left = inode_length(inode) - offset;
        int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
        int min_left = inode_left < sector_left ? inode_left : sector_left;

        /* Number of bytes to actually copy out of this sector. */
        int chunk_size = size < min_left ? size : min_left;
        if (chunk_size <= 0)
            break;

        if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
            /* Read full sector directly into caller's buffer. */
            block_read(fs_device, sector_idx, buffer + bytes_read);
        } else {
            /* Read sector into bounce buffer, then partially copy
               into caller's buffer. */
            if (bounce == NULL) {
                bounce = malloc(BLOCK_SECTOR_SIZE);
                if (bounce == NULL)
                    break;
            }
            //TODO change fs_device?
            block_read(fs_device, sector_idx, bounce);
            memcpy(buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }

        /* Advance. */
        size -= chunk_size;
        offset += chunk_size;
        bytes_read += chunk_size;
    }
    free(bounce);

    return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at(struct inode *inode, const void *buffer_, off_t size,
               off_t offset) {
    const uint8_t *buffer = buffer_;
    off_t bytes_written = 0;
    uint8_t *bounce = NULL;

    if (inode->deny_write_cnt)
        return 0;

    while (size > 0) {
        /* Sector to write, starting byte offset within sector. */
        block_sector_t sector_idx = byte_to_sector(inode, offset, true);
        if (sector_idx == INODE_SECTORS_UNALLOCATED)
            return bytes_written;

        int sector_ofs = offset % BLOCK_SECTOR_SIZE;

        /* Bytes left in inode, bytes left in sector, lesser of the two. */
        off_t inode_left = inode_length(inode) - offset;
        int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
        int min_left = inode_left < sector_left ? inode_left : sector_left;

        /* Number of bytes to actually write into this sector. */
        int chunk_size = size < min_left ? size : min_left;
        if (chunk_size <= 0)
            break;

        if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
            /* Write full sector directly to disk. */
            block_write(fs_device, sector_idx, buffer + bytes_written);
        } else {
            /* We need a bounce buffer. */
            if (bounce == NULL) {
                bounce = malloc(BLOCK_SECTOR_SIZE);
                if (bounce == NULL)
                    break;
            }

            /* If the sector contains data before or after the chunk
               we're writing, then we need to read in the sector
               first.  Otherwise we start with a sector of all zeros. */
            if (sector_ofs > 0 || chunk_size < sector_left)
                block_read(fs_device, sector_idx, bounce);
            else
                memset(bounce, 0, BLOCK_SECTOR_SIZE);
            memcpy(bounce + sector_ofs, buffer + bytes_written, chunk_size);
            block_write(fs_device, sector_idx, bounce);
        }

        /* Advance. */
        size -= chunk_size;
        offset += chunk_size;
        bytes_written += chunk_size;
    }
    free(bounce);

    return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write(struct inode *inode) {
    inode->deny_write_cnt++;
    ASSERT(inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write(struct inode *inode) {
    ASSERT(inode->deny_write_cnt > 0);
    ASSERT(inode->deny_write_cnt <= inode->open_cnt);
    inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length(const struct inode *inode) {
    return inode->data.length;
}
