#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "filesys/cache.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define DIRECT_BLOCKS 123
#define INDIRECT_BLOCKS 1
#define DBL_INDIRECT_BLOCKS 1

struct indirect_block
  {
    block_sector_t blocks[128];
  };

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
    uint32_t is_dir;

    block_sector_t direct[DIRECT_BLOCKS];
    block_sector_t indirect;
    block_sector_t double_indirect;

    //A soma dos tamanhos deve dar 512 bytes: off_t (4) + unsigned (4) + direct (124*4) + indirect (4) + dbl (4) = 512 bytes
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

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  ASSERT (inode != NULL);

  // Se a posição for maior que o tamanho do arquivo
  if (pos >= inode->data.length)
    return -1;

  off_t index = pos / BLOCK_SECTOR_SIZE;

  // Bloco Direto
  if (index < DIRECT_BLOCKS) {
      block_sector_t ret = inode->data.direct[index];
      return ret;
  }
  index -= DIRECT_BLOCKS;

  // Bloco Indireto
  if (index < 128)
    {
      if (inode->data.indirect == 0)
        return 0; // Bloco não alocado

      struct indirect_block *block = calloc (1, sizeof *block);
      if (block == NULL) return 0;

      cache_read (inode->data.indirect, block);
      // block_read (fs_device, inode->data.indirect, block);
      block_sector_t result = block->blocks[index];
      free (block);
      
      return result;
    }
  index -= 128;

  // Bloco Duplamente Indireto
  if (index < 128 * 128)
    {
      // Bloco não alocado
      if (inode->data.double_indirect == 0)
        return 0;

      struct indirect_block *block = calloc (1, sizeof *block);
      if (block == NULL) return 0;

      // block_read (fs_device, inode->data.double_indirect, block);
      cache_read (inode->data.double_indirect, block);
      
      block_sector_t indirect_sector = block->blocks[index / 128];
      
      if (indirect_sector == 0)
        {
          free (block);
          return 0;
        }

      // block_read (fs_device, indirect_sector, block);
      cache_read (indirect_sector, block);
      block_sector_t result = block->blocks[index % 128];
      
      free (block);
      return result;
    }

  return -1;
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
inode_create (block_sector_t sector, off_t length, bool is_dir)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;

      disk_inode->is_dir = is_dir ? 1 : 0; // Salva o tipo

      if (length > 0) 
        {
          size_t sectors = bytes_to_sectors (length);
          size_t i;
          static char zeros[BLOCK_SECTOR_SIZE]; // Zeros para limpar o setor

          for (i = 0; i < sectors; i++) 
            {
               if (i < DIRECT_BLOCKS)
                 {
                    if (free_map_allocate (1, &disk_inode->direct[i]))
                      {
                        // block_write (fs_device, disk_inode->direct[i], zeros);
                        cache_write (disk_inode->direct[i], zeros);
                      }
                    else
                      {
                        success = false; 
                        free (disk_inode);
                        return false;
                      }
                 }
            }
        }

      // block_write (fs_device, sector, disk_inode);
      cache_write (sector, disk_inode);
      success = true;

      free (disk_inode);
    }
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
  // block_read (fs_device, inode->sector, &inode->data);
  cache_read (inode->sector, &inode->data);
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

// Libera todos os setores alocados por um inode
static void
inode_deallocate (struct inode *inode)
{
  struct inode_disk *disk_inode = &inode->data;
  
  // 1. Liberar blocos diretos
  for (int i = 0; i < DIRECT_BLOCKS; i++)
    {
      if (disk_inode->direct[i] != 0)
        free_map_release (disk_inode->direct[i], 1);
    }

  // Liberar bloco indireto e seus dados
  if (disk_inode->indirect != 0)
    {
      struct indirect_block *block = malloc (BLOCK_SECTOR_SIZE);
      if (block) 
        {
          cache_read (disk_inode->indirect, block);
          for (int i = 0; i < 128; i++)
            {
              if (block->blocks[i] != 0)
                free_map_release (block->blocks[i], 1);
            }
          free (block);
        }
      free_map_release (disk_inode->indirect, 1);
    }

  // Liberar bloco duplamente indireto
  if (disk_inode->double_indirect != 0)
    {
      struct indirect_block *l1_block = malloc (BLOCK_SECTOR_SIZE);
      struct indirect_block *l2_block = malloc (BLOCK_SECTOR_SIZE);
      
      if (l1_block && l2_block)
        {
          cache_read (disk_inode->double_indirect, l1_block);
          for (int i = 0; i < 128; i++)
            {
              if (l1_block->blocks[i] != 0)
                {
                  // Ler o bloco de nível 2
                  cache_read (l1_block->blocks[i], l2_block);
                  for (int j = 0; j < 128; j++)
                    {
                      if (l2_block->blocks[j] != 0)
                        free_map_release (l2_block->blocks[j], 1);
                    }
                  free_map_release (l1_block->blocks[i], 1);
                }
            }
        }
      if (l1_block) free (l1_block);
      if (l2_block) free (l2_block);
      
      free_map_release (disk_inode->double_indirect, 1);
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
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          // Libera todos os dados do arquivo
          inode_deallocate (inode);

          free_map_release (inode->sector, 1);
        }

      free (inode); 
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
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      // Tratamento de Arquivos Esparsos
      if (sector_idx == 0) 
        {
          memset (buffer + bytes_read, 0, chunk_size);
        }
      else 
        {
          // Leitura normal do disco
          if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
            {
              /* Read full sector directly into caller's buffer. */
              // block_read (fs_device, sector_idx, buffer + bytes_read);
              cache_read (sector_idx, buffer + bytes_read);
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
              // block_read (fs_device, sector_idx, bounce);
              cache_read (sector_idx, bounce);
              memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
            }
        }
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);

  return bytes_read;
}

// Garante que o setor 'index' esteja alocado no inode_disk. Se não estiver, aloca novos blocos (diretos, indiretos, etc) e preenche com zeros. Retorna o número do setor físico ou 0 em caso de erro.
static block_sector_t
inode_allocate_sector (struct inode_disk *disk_inode, off_t index)
{
  block_sector_t new_sector;

  // Bloco Direto
  if (index < DIRECT_BLOCKS)
    {
      if (disk_inode->direct[index] == 0)
        {
          if (!free_map_allocate (1, &new_sector)) return 0;
          
          static char zeros[BLOCK_SECTOR_SIZE];
          // block_write (fs_device, new_sector, zeros);
          cache_write (new_sector, zeros);
          
          disk_inode->direct[index] = new_sector;
        }
      return disk_inode->direct[index];
    }
  index -= DIRECT_BLOCKS;

  // Bloco Indireto
  if (index < 128)
    {
      // Se o bloco de índices indiretos ainda não existe, cria ele
      if (disk_inode->indirect == 0)
        {
          if (!free_map_allocate (1, &new_sector)) return 0;
          
          static char zeros[BLOCK_SECTOR_SIZE];
          // block_write (fs_device, new_sector, zeros);
          cache_write (new_sector, zeros);
          
          disk_inode->indirect = new_sector;
        }

      // Lê o bloco de índices
      struct indirect_block *block = calloc (1, sizeof *block);
      if (block == NULL) return 0;
      // block_read (fs_device, disk_inode->indirect, block);
      cache_read (disk_inode->indirect, block);

      if (block->blocks[index] == 0)
        {
          if (!free_map_allocate (1, &new_sector)) 
            {
              free(block); 
              return 0;
            }
          
          static char zeros[BLOCK_SECTOR_SIZE];
          // block_write (fs_device, new_sector, zeros);
          cache_write (new_sector, zeros);
          
          block->blocks[index] = new_sector;
          // block_write (fs_device, disk_inode->indirect, block);
          cache_write (disk_inode->indirect, block);
        }
      
      block_sector_t result = block->blocks[index];
      free (block);
      return result;
    }
  index -= 128;

  // Bloco Duplamente Indireto
  if (index < 128 * 128)
    {
      // Aloca o bloco de índices de primeira camada se necessário
      if (disk_inode->double_indirect == 0)
        {
          if (!free_map_allocate (1, &new_sector)) return 0;
          static char zeros[BLOCK_SECTOR_SIZE];
          // block_write (fs_device, new_sector, zeros);
          cache_write (new_sector, zeros);
          disk_inode->double_indirect = new_sector;
        }

      struct indirect_block *block = calloc (1, sizeof *block);
      if (block == NULL) return 0;
      // block_read (fs_device, disk_inode->double_indirect, block);
      cache_read (disk_inode->double_indirect, block);

      // Aloca o bloco de índices de segunda camada se necessário
      off_t l1_index = index / 128;
      off_t l2_index = index % 128;

      if (block->blocks[l1_index] == 0)
        {
          if (!free_map_allocate (1, &new_sector)) 
            {
              free(block); 
              return 0;
            }
          static char zeros[BLOCK_SECTOR_SIZE];
          // block_write (fs_device, new_sector, zeros);
          cache_write (new_sector, zeros);
          
          block->blocks[l1_index] = new_sector;
          // block_write (fs_device, disk_inode->double_indirect, block);
          cache_write (disk_inode->double_indirect, block);
        }
      
      block_sector_t indirect_sector = block->blocks[l1_index];
      
      // block_read (fs_device, indirect_sector, block);
      cache_read (indirect_sector, block);

      if (block->blocks[l2_index] == 0)
        {
          if (!free_map_allocate (1, &new_sector)) 
            {
              free(block); 
              return 0;
            }
          static char zeros[BLOCK_SECTOR_SIZE];
          // block_write (fs_device, new_sector, zeros);
          cache_write (new_sector, zeros);
          
          block->blocks[l2_index] = new_sector;
          // block_write (fs_device, indirect_sector, block);
          cache_write (indirect_sector, block);
        }

      block_sector_t result = block->blocks[l2_index];
      free (block);
      return result;
    }

  return 0;
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

  bool inode_needs_save = false;

  if (offset + size > inode_length(inode)) 
    {
      // Se a escrita vai além do tamanho atual, expandimos o arquivo
      if (!inode->data.double_indirect && (offset + size) > (DIRECT_BLOCKS + 128 + 128*128) * BLOCK_SECTOR_SIZE)
        {
           return 0; 
        }
      
      inode->data.length = offset + size;
      // Tamanho mudou, precisa salvar
      inode_needs_save = true;
    }

  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int chunk_size = size < sector_left ? size : sector_left;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t sector_idx_logic = offset / BLOCK_SECTOR_SIZE;

      // Verificação: O setor já existia antes?
      block_sector_t old_sector_idx = byte_to_sector(inode, offset);

      block_sector_t sector_idx = inode_allocate_sector(&inode->data, sector_idx_logic);

      if (sector_idx == 0)
        break;

      //Se o setor era 0 (não existia) e agora existe, o Inode mudou
      if (old_sector_idx == 0 && sector_idx != 0) {
          inode_needs_save = true;
      }

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Write full sector directly to disk. */
          // block_write (fs_device, sector_idx, buffer + bytes_written);
          cache_write (sector_idx, buffer + bytes_written);
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
            // block_read (fs_device, sector_idx, bounce);
            cache_read (sector_idx, bounce);
          else
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          // block_write (fs_device, sector_idx, bounce);
          cache_write (sector_idx, bounce);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  free (bounce);

  //Salva o Inode se houve alocação ou mudança de tamanho
  if (inode_needs_save) {
      // block_write (fs_device, inode->sector, &inode->data);
      cache_write (inode->sector, &inode->data);
  }

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

bool
inode_is_dir (const struct inode *inode)
{
  if (inode == NULL) return false;
  return inode->data.is_dir == 1;
}

// Retorna o número de descritores abertos para este inode.
int
inode_get_open_cnt (const struct inode *inode)
{
  return inode->open_cnt;
}

// Retorna true se o inode foi marcado para remoção.
bool
inode_is_removed (const struct inode *inode)
{
  ASSERT (inode != NULL);
  return inode->removed;
}
