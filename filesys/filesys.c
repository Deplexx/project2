#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/thread.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

void get_info(struct file_info *info, char* str) {
  if (str == NULL) return;
  int32_t len = strlen(str);
  if (len <= 0) return;

  char temp[len+1];
  int32_t name_count = 0;

  struct dir *dir;
  struct inode* inode;
  struct inode** inode_p = malloc(sizeof(struct inode*));//TODO: free this mem

  if (thread_current()->current_dir == NULL) dir = dir_open_root();
  else if (str[0] == '/') dir = dir_open_root();
  else dir = dir_reopen(thread_current()->current_dir);

  for (int32_t i=0;i < len; i++){
    if ((str[i] == '/') || (i==len-1)){
      if (i == 0) continue;
      else {
	/* current or parent direcotry*/
	if ((temp[0] == '.') && (temp[1] == '.')) {
	  inode = inode_open(get_inode_parent(dir_get_inode(dir)));
	  dir_close(dir);
	  dir = dir_open(inode);
	} else {
	  /* subdirecotry*/
	  if (i==len-1){ 
	    temp[name_count] = str[i];
	    ++name_count;	    
	  }
          temp[name_count] = 0;
	  dir_lookup(dir, temp, inode_p);
	
	  /* regular file*/
	  /*if (inode_isdir(*inode_p)){
	    dir_close(dir);
	    dir = dir_open(*inode_p); 
	  } else {*/
	    //inode_close(inode_p);
	  //}
	}
	if (i != len-1)
          name_count = 0;
      } 
    } else {
      temp[name_count] = str[i];
      ++name_count;
    }
  }
    free(inode_p);
//  info->dir = dir;
//  info->name = malloc(name_count + 1);
//  memcpy(info->name, temp, name_count+1);
    info->name = str;
    info->dir = dir_open_root();
}

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  free_map_init ();

  if (format) 
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  free_map_close ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size, bool isdir) 
{
  block_sector_t inode_sector = 0;
  struct file_info file_info;
  file_info.name = NULL;
  file_info.dir = NULL;

  get_info(&file_info, name);
  if (!file_info.name || !file_info.dir) return false;
  struct dir *dir = file_info.dir;
  char * file_name = file_info.name;

  bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size,isdir)
                  && dir_add (dir, file_name, inode_sector));

//  free(file_name);
  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);
  dir_close (dir);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
  struct file_info file_info;
  file_info.name = NULL;
  file_info.dir = NULL;

  get_info(&file_info, name);
  if (!file_info.name || !file_info.dir) return false;
  struct dir *dir = file_info.dir;
  char * file_name = file_info.name;
  struct inode *inode = NULL;

  if (dir != NULL)
    dir_lookup (dir, file_name, &inode);
  dir_close (dir);
//  free(file_name);
  struct file* file = file_open(inode);
  return file;
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  struct file_info file_info;
  file_info.name = NULL;
  file_info.dir = NULL;

  get_info(&file_info, name);
  if (!file_info.name || !file_info.dir) return false;
  struct dir *dir = file_info.dir;
  char * file_name = file_info.name;

  bool success = dir != NULL && dir_remove (dir, file_name);
  dir_close (dir); 
//  free(file_name);
  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}
