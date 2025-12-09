#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "filesys/cache.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

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

  cache_init ();

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
  cache_flush ();
}

// Extrai o nome do arquivo e retorna o diretório pai
static struct dir *
parse_path (char *path, char *file_name) 
{
  struct dir *dir;
  struct inode *inode;
  
  if (path == NULL || file_name == NULL || strlen(path) == 0)
    return NULL;

  // Cópia do path para não alterar a string original
  char *path_copy = malloc(strlen(path) + 1);
  if (path_copy == NULL) return NULL;
  
  strlcpy(path_copy, path, strlen(path) + 1);

  // Define o diretório inicial
  if (path[0] == '/') 
    {
      dir = dir_open_root ();
    } 
  else 
    {
      struct thread *t = thread_current ();
      if (t->cwd == NULL) 
        dir = dir_open_root ();
      else 
        dir = dir_reopen (t->cwd);
    }

  char *token, *nextToken, *save_ptr;
  token = strtok_r (path_copy, "/", &save_ptr);
  nextToken = strtok_r (NULL, "/", &save_ptr);

  // Navega pelos diretórios intermediários
  while (token != NULL && nextToken != NULL) 
    {
      // Verifica se o nome do diretório intermediário é muito longo
      if (strlen(token) > NAME_MAX)
        {
          dir_close (dir);
          free(path_copy);
          return NULL;
        }

      if (!dir_lookup (dir, token, &inode)) 
        {
          dir_close (dir);
          free(path_copy);
          return NULL; 
        }
      
      if (!inode_is_dir(inode))
        {
          inode_close(inode);
          dir_close(dir);
          free(path_copy);
          return NULL;
        }

      dir_close (dir);
      dir = dir_open (inode);

      token = nextToken;
      nextToken = strtok_r (NULL, "/", &save_ptr);
    }

  // Define o nome do arquivo final
  if (token != NULL)
  {
      //Verifica se o nome do arquivo final é muito longo */
      if (strlen(token) > NAME_MAX)
        {
          dir_close (dir);
          free(path_copy);
          return NULL;
        }
    strlcpy (file_name, token, NAME_MAX + 1);
  }
  else
    strlcpy (file_name, ".", NAME_MAX + 1);
  free(path_copy);
  return dir;
}

//Cria um diretório novo
bool
filesys_mkdir (const char *name) 
{
  block_sector_t inode_sector = 0;
  char file_name[NAME_MAX + 1];

  struct dir *dir = parse_path ((char *) name, file_name);
  if (dir == NULL) return false;

  // Aloca setor, cria inode de diretório (true) e adiciona ao pai
  bool success = (free_map_allocate (1, &inode_sector)
                  && dir_create (inode_sector, 16)
                  && dir_add (dir, file_name, inode_sector));

  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);

  if (success) 
    {
      struct dir *new_dir = dir_open (inode_open (inode_sector));
      if (new_dir != NULL)
        {
          dir_add (new_dir, ".", inode_sector); 
          dir_add (new_dir, "..", inode_get_inumber(dir_get_inode(dir)));
          dir_close (new_dir);
        }
    }

  dir_close (dir);
  return success;
}

// Muda o diretório atual do processo
bool
filesys_chdir (const char *name)
{
  char file_name[NAME_MAX + 1];
  
  // Usa parse_path para achar o diretório pai
  struct dir *parent_dir = parse_path ((char *) name, file_name);
  struct inode *inode = NULL;

  if (parent_dir != NULL)
    {
      if (strcmp(file_name, ".") == 0)
        {
          inode = dir_get_inode(parent_dir);
          inode_reopen(inode);
        }
      else if (strcmp(file_name, "..") == 0)
        {
          dir_lookup (parent_dir, "..", &inode);
        }
      else
        {
          dir_lookup (parent_dir, file_name, &inode);
        }
    }
  
  dir_close(parent_dir);

  // Se achou o inode, verifica se é diretório e atualiza a thread
  if (inode != NULL)
    {
      if (inode_is_dir(inode))
        {
           struct thread *t = thread_current();
           if (t->cwd != NULL)
             dir_close(t->cwd);
           t->cwd = dir_open(inode);
           return true;
        }
      inode_close(inode);
    }
    
  return false;
}


/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size) 
{
  block_sector_t inode_sector = 0;
  char file_name[NAME_MAX + 1];

  struct dir *dir = parse_path ((char *) name, file_name);
  if (dir == NULL) return false;

  bool success = (free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size, false)
                  && dir_add (dir, file_name, inode_sector));
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
  if (strlen(name) == 0) return NULL;

  char file_name[NAME_MAX + 1];

  struct dir *dir = parse_path ((char *) name, file_name);
  struct inode *inode = NULL;

  if (dir != NULL)
    {
      if (strcmp(file_name, ".") == 0) {
         inode = dir_get_inode(dir);
         inode_reopen(inode); // Incrementa contador pois dir_close vai decrementar
      } else if (strcmp(file_name, "..") == 0) {
         if (!dir_lookup (dir, "..", &inode)) inode = NULL;
      } else {
         dir_lookup (dir, file_name, &inode);
      }
      dir_close (dir);
    }
  else
    {
      return NULL;
    }

  return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  char file_name[NAME_MAX + 1];

  struct dir *dir = parse_path ((char *) name, file_name);
  bool success = dir != NULL && dir_remove (dir, name);
  dir_close (dir); 

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
