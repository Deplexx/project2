#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include <limits.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

/*Inode block sector status identifiers*/
#define INODE_SECTORS_UNALLOCATED UINT_MAX

/*MUST ADD UP TO THE DIFFERENCE BETWEEN (BLOCK_SECTOR_SIZE) AND inode_disk's METADATA*/
#define INODE_SECTOR_NUMBER_SIZE (sizeof unsigned)
#define SECTOR_POINTERS_PER_BLOCK (BLOCK_SECTOR_SIZE >> INODE_SECTOR_NUMBER_SIZE)

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

enum sector_t {eDIRECT, eSINGLY, eDOUBLY};

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
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
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode 
  {
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
static enum sector_t inode_getIndices(off_t *direct, off_t *singly, off_t *doubly, off_t off);

/*file extension routine - allocated enough blocks to make reads from and writes to
 blocks up to offset bytes from the start of an inode's data valid*/
static bool inode_extend(struct inode *inode, off_t offset);

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (struct inode *inode, off_t pos, bool extend) 
{
  bool abort = false;

  enum sector_t type;

  off_t directI;
  off_t singlyI;
  off_t doublyI;

  block_sector_t singly_indirect_sec;
  block_sector_t doubly_indirect_sec;

  block_sector_t *direct_buff = (block_sector_t*) inode->data.direct;
  block_sector_t *singly_indirect_buff = (block_sector_t*) inode->data.singly;

  block_sector_t ret = INODE_SECTORS_UNALLOCATED;

  size_t oldLen = inode->data.length;

  if(extend && ((pos / BLOCK_SECTOR_SIZE) > (oldLen / BLOCK_SECTOR_SIZE)))
    inode_extend(inode, pos);

  ASSERT (inode != NULL);
  if (pos < inode->data.length) {
    if(INODE_IS_DIRECT(pos)) {
      type = eDIRECT;

      directI = INODE_DIRECT_OFF(pos) / DIRECT_SIZE;
    } else if(INODE_IS_SINGLY(pos)) {
      type = eSINGLY;

      singlyI = INODE_SINGLY_OFF(pos) / SINGLY_SIZE;
      directI = (INODE_SINGLY_OFF(pos) % SINGLY_SIZE) / DIRECT_SIZE;
    } else if(INODE_IS_DOUBLY(pos)) {
      type = eDOUBLY;

      doublyI = INODE_DOUBLY_OFF(pos) / DOUBLY_SIZE;
      singlyI = (INODE_DOUBLY_OFF(pos) % DOUBLY_SIZE) / SINGLY_SIZE;
      directI = (INODE_DOUBLY_OFF(pos) % SINGLY_SIZE) / DIRECT_SIZE;
    }

    while(true) {
      switch(type) {
	case eDOUBLY:
	  if((doubly_indirect_sec = inode->data.doubly[doublyI]) != (block_sector_t) INODE_SECTORS_UNALLOCATED) {
	    if(doubly_indirect_sec == BLOCK_SECTOR_ALL_ZEROS)
	      return BLOCK_SECTOR_ALL_ZEROS;

	    ASSERT((singly_indirect_buff = (block_sector_t*) malloc(BLOCK_SECTOR_SIZE)));
	    block_read(fs_device, doubly_indirect_sec, (void*) singly_indirect_buff);
	  } /*else if(extend) {
	    off_t i;

	    for(i = 0; i < doublyI; ++i)
	      if(i == (doublyI - 1)) {
	        if(free_map_allocate (1, (block_sector_t*) &inode->data.doubly[i]))
	          block_write (fs_device, inode->data.doubly[i], zeros);
		else {
		  ret =  INODE_SECTORS_UNALLOCATED;
		  abort = true;
		  break;
		}
	      } else
		inode->data.doubly[i] = BLOCK_SECTOR_ALL_ZEROS;

	    if(abort)
	      break;
	    else
	      continue;
	  } */else
	    return INODE_SECTORS_UNALLOCATED;

        case eSINGLY:
	  if((singly_indirect_sec = singly_indirect_buff[singlyI]) != (block_sector_t) INODE_SECTORS_UNALLOCATED) {
	    if(singly_indirect_sec == BLOCK_SECTOR_ALL_ZEROS)
	      return BLOCK_SECTOR_ALL_ZEROS;

	    ASSERT((direct_buff = (block_sector_t*) malloc(BLOCK_SECTOR_SIZE)));
	    block_read(fs_device, singly_indirect_sec, (void*) direct_buff);
	  } /*else if(extend) {
	    off_t i;

	    for(i = 0; i < singlyI; ++i) {
	      if(i == (singlyI - 1)) {
	        if(free_map_allocate (1, (block_sector_t*) &inode->data.doubly[i]))
	          block_write (fs_device, inode->data.doubly[i], zeros);
		else
		  return INODE_SECTORS_UNALLOCATED;
	      } else
		singly_indirect_buff[i] = BLOCK_SECTOR_ALL_ZEROS;
	    }
	  }*/

	  if(singly_indirect_buff != inode->data.singly)
	    free(singly_indirect_buff);

	case eDIRECT:
	  if(direct_buff[directI] != (block_sector_t) INODE_SECTORS_UNALLOCATED)
	    ret = directI;
	  /*else if(extend) {
	    off_t i;

	    for(i = 0; i < singlyI; ++i) {
	      if(i == (directI - 1)) {
		if(free_map_allocate (1, (block_sector_t*) &inode->data.doubly[i]))
		  block_write (fs_device, inode->data.doubly[i], zeros);
		else
		  return INODE_SECTORS_UNALLOCATED;
	      } else
		direct_buff[i] = BLOCK_SECTOR_ALL_ZEROS;
	    }
	  }*/

	  if(direct_buff != inode->data.direct)
	    free(direct_buff);

	default: /*should never be the case*/
	  break;
      }

      return ret;
    }
  }
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length, bool isDir)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if(disk_inode != NULL) {
    /*new type implementation. Initialize the inode to length 0*/
    disk_inode->isDir = isDir;
    disk_inode->length = 0;
    disk_inode->magic = INODE_MAGIC;
    size_t i;
    for(i = 0; i < INODE_DIRECT; ++i)
      disk_inode->direct[i] = (block_sector_t) INODE_SECTORS_UNALLOCATED;
    for(i = 0; i < INODE_SINGLY_INDIRECT; ++i)
      disk_inode->singly[i] = (block_sector_t) INODE_SECTORS_UNALLOCATED;
    for(i = 0; i < INODE_DOUBLY_INDIRECT; ++i)
      disk_inode->doubly[i] = (block_sector_t) INODE_SECTORS_UNALLOCATED;

    block_write (fs_device, sector, disk_inode);
    free(disk_inode);
    success = true;
  }
  /*old impementation*/
  /* disk_inode = calloc (1, sizeof *disk_inode); */
  /* if (disk_inode != NULL) */
  /*   { */
  /*     size_t sectors = bytes_to_sectors (length); */
  /*     disk_inode->length = length; */
  /*     disk_inode->magic = INODE_MAGIC; */
  /*     if (free_map_allocate (sectors, &disk_inode->start))  */
  /*       { */
  /*         block_write (fs_device, sector, disk_inode); */
  /*         if (sectors > 0)  */
  /*           { */
  /*             static char zeros[BLOCK_SECTOR_SIZE]; */
  /*             size_t i; */
              
  /*             for (i = 0; i < sectors; i++)  */
  /*               block_write (fs_device, disk_inode->start + i, zeros); */
  /*           } */
  /*         success = true;  */
  /*       }  */
  /*     free (disk_inode); */
  /*   } */
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  block_read (fs_device, inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

static enum sector_t inode_getIndices(off_t *direct, off_t *singly, off_t *doubly, off_t off) {
  ASSERT((direct && singly && doubly) != (off_t) NULL);

  *direct = (off_t) NULL;
  *singly = (off_t) NULL;
  *doubly = (off_t) NULL;

  if(INODE_IS_DIRECT(off)) {
    *direct = INODE_DIRECT_OFF(off) / DIRECT_SIZE;
    return eDIRECT;
  } else if(INODE_IS_SINGLY(off)) {
    *singly = INODE_SINGLY_OFF(off) / SINGLY_SIZE;
    *direct = (INODE_SINGLY_OFF(off) % SINGLY_SIZE) / DIRECT_SIZE;
    return eSINGLY;
  } else if(INODE_IS_DOUBLY(off)) {
    *doubly = INODE_DOUBLY_OFF(off) / DOUBLY_SIZE;
    *singly = (INODE_DOUBLY_OFF(off) % DOUBLY_SIZE) / SINGLY_SIZE;
    *direct = (INODE_DOUBLY_OFF(off) % SINGLY_SIZE) / DIRECT_SIZE;
    return eDOUBLY;
  } else
    return (enum sector_t) NULL;
}

/* frees up the the block sectores based on type. */
void
inode_free_map_release (struct inode *inode) {

	off_t direct, singly, doubly;
	enum sector_t type = inode_getIndices(&direct, &singly, &doubly, inode->data.length);


	switch (type) {
		case eDIRECT:/** ----------------Direct--------------------------- */

			/** release direct sectors one by one */
			for (int sctr = 0; sctr <= direct; ++sctr)
					free_map_release(inode->data.direct[sctr], 1);
			break;


		case eSINGLY:/** ----------------Singly--------------------------- */

			/** release direct sectors one by one */
			for (int sctr = 0; sctr <= INODE_DIRECT; ++sctr)
				free_map_release(inode->data.direct[sctr], 1);

			/** release singly sectors one by one */
			for (int sngly_blk = 0; sngly_blk <= singly; ++sngly_blk) {


				//sngly_blk<= 128 .. except for last singly block: sngly_blk<=direct
				for (int sctr = 0; sctr <= (sngly_blk == singly ? direct : SECTOR_POINTERS_PER_BLOCK); ++j){
					free_map_release(inode->data.singly[sngly_blk], 1); //TODO 12/07/2016: replace this with?
				}
			}
			break;



		case eDOUBLY:/** ----------------Doubly--------------------------- */

			/** release direct sectors one by one */
			for (int sctr = 0; sctr <= INODE_DIRECT; ++sctr)
				free_map_release(inode->data.direct[sctr], 1);

			/** release singly sectors one by one */
			for (int sngly_blk = 0; sngly_blk <= INODE_SINGLY_INDIRECT; ++sngly_blk) {


				//sngly_blk<= 128 .. except for last singly block: sngly_blk<=direct
				for (int sctr = 0; sctr <= SECTOR_POINTERS_PER_BLOCK; ++sctr){
					free_map_release(inode->data.singly[sngly_blk], 1); //TODO 12/07/2016: replace this with?
				}
			}

			/** release doubly sectors one by one */
			for (int dbly_blk = 0; dbly_blk <= doubly; ++dbly_blk) {


				//dbly_blk<= 128 .. except for last doubly block: dbly_blk <= sinly
				for (int sngly_blk = 0; sngly_blk <= (dbly_blk ==  doubly? singly : SECTOR_POINTERS_PER_BLOCK); ++sngly_blk){

					//sngly_blk<= 128 .. except for last singly block: sngly_blk<=direct
					for (int sctr = 0; sctr <= (sngly_blk == singly ? direct : SECTOR_POINTERS_PER_BLOCK); ++j){
						free_map_release(inode->data.doubly[dbly_blk], 1); //TODO 12/07/2016: replace this with?
					}
				}
			}
			break;
	}
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
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
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

static bool inode_extend(struct inode *inode, off_t offset) {
  ASSERT(inode != NULL);

  bool ret = false;

  size_t newSize = inode->data.length;

  size_t offBlocks = offset / BLOCK_SECTOR_SIZE;
  size_t oldBlocks = newSize / BLOCK_SECTOR_SIZE;
  size_t newBlocks = oldBlocks;
  size_t blocksWritten = 0;

  off_t direct, singly, doubly;
  enum sector_t type;

  static char zeros[BLOCK_SECTOR_SIZE];

  if(offBlocks > oldBlocks)
    do
      newBlocks *= 2;
    while(newBlocks < offBlocks);
  else
    return true;

  type = inode_getIndices(&direct, &singly, &doubly, offset);
  if(doubly == NULL)
    doubly = 1;
  if(singly == NULL)
    singly = 1;

  off_t i, j, k;
  for(i = 0; i < doubly; ++i)
    if(free_map_allocate (1, (block_sector_t*) &inode->data.doubly[i])) {
      block_write (fs_device, inode->data.doubly[i], zeros);
      ++blocksWritten;
    }

  inode->data.length = newSize;
  return true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset, false);
      if(sector_idx == INODE_SECTORS_UNALLOCATED)
	break;

      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Read full sector directly into caller's buffer. */
          block_read (fs_device, sector_idx, buffer + bytes_read);
        }
      else 
        {
          /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
          block_read (fs_device, sector_idx, bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;
  
  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset, true);
      if(sector_idx == INODE_SECTORS_UNALLOCATED)
	return bytes_written;

      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Write full sector directly to disk. */
          block_write (fs_device, sector_idx, buffer + bytes_written);
        }
      else 
        {
          /* We need a bounce buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left) 
            block_read (fs_device, sector_idx, bounce);
          else
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          block_write (fs_device, sector_idx, bounce);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  free (bounce);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->data.length;
}
