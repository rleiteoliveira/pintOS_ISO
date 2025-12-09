#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include <string.h>
#include <debug.h>

#define CACHE_SIZE 64

struct cache_entry 
  {
    block_sector_t sector;
    bool is_valid;
    bool is_dirty;
    bool accessed; 
    uint8_t data[BLOCK_SECTOR_SIZE];
    struct lock entry_lock;
  };

static struct cache_entry *cache;
static struct lock cache_global_lock;

void
cache_init (void)
{
  lock_init (&cache_global_lock);
  
  // Aloca o cache no heap para evitar estourar limites de segmentos estáticos
  cache = malloc (sizeof(struct cache_entry) * CACHE_SIZE);
  if (cache == NULL) PANIC("Failed to allocate buffer cache");

  for (int i = 0; i < CACHE_SIZE; i++)
    {
      cache[i].is_valid = false;
      lock_init (&cache[i].entry_lock); // Inicializa o lock individual
    }
}

static int
cache_evict (void)
{
  static int clock_hand = 0;
  
  while (true)
    {
      // Algoritmo Clock Simples
      lock_acquire(&cache[clock_hand].entry_lock);
      
      if (!cache[clock_hand].is_valid)
        {
          // Encontrou slot vazio
          lock_release(&cache[clock_hand].entry_lock);
          return clock_hand;
        }

      if (cache[clock_hand].accessed)
        {
          cache[clock_hand].accessed = false;
          lock_release(&cache[clock_hand].entry_lock);
        }
      else
        {
          if (cache[clock_hand].is_dirty)
            {
              block_write (fs_device, cache[clock_hand].sector, cache[clock_hand].data);
            }
          
          cache[clock_hand].is_valid = false;
          lock_release(&cache[clock_hand].entry_lock);
          return clock_hand;
        }
        
      clock_hand = (clock_hand + 1) % CACHE_SIZE;
    }
}

static int
cache_lookup (block_sector_t sector)
{
  for (int i = 0; i < CACHE_SIZE; i++)
    {
      // Leitura sem lock é arriscada, mas com lock global é seguro
      if (cache[i].is_valid && cache[i].sector == sector)
        return i;
    }
  return -1;
}

void
cache_read (block_sector_t sector, void *buffer)
{
  lock_acquire (&cache_global_lock);
  
  int idx = cache_lookup (sector);
  if (idx == -1)
    {
      // Cache miss: precisa evictar e carregar
      idx = cache_evict ();
      
      lock_acquire(&cache[idx].entry_lock);
      
      cache[idx].is_valid = true;
      cache[idx].sector = sector;
      cache[idx].is_dirty = false;
      block_read (fs_device, sector, cache[idx].data);
      
      lock_release(&cache[idx].entry_lock);
    }
  
  // Atualiza metadados e copia dados
  lock_acquire(&cache[idx].entry_lock);
  cache[idx].accessed = true;
  memcpy (buffer, cache[idx].data, BLOCK_SECTOR_SIZE);
  lock_release(&cache[idx].entry_lock);
  
  lock_release (&cache_global_lock);
}

void
cache_write (block_sector_t sector, const void *buffer)
{
  lock_acquire (&cache_global_lock);
  
  int idx = cache_lookup (sector);
  if (idx == -1)
    {
      idx = cache_evict ();
      
      lock_acquire(&cache[idx].entry_lock);
      
      cache[idx].is_valid = true;
      cache[idx].sector = sector;
      
      /* Em Write-Back, lemos o conteúdo antigo antes de sobrescrever.
         Isso é vital se a escrita não for alinhada, mas aqui
         estamos assumindo blocos inteiros. Lemos por segurança. */
      block_read (fs_device, sector, cache[idx].data);
      
      lock_release(&cache[idx].entry_lock);
    }
  
  lock_acquire(&cache[idx].entry_lock);
  cache[idx].accessed = true;
  
  /* Cópia dos dados para a RAM */
  memcpy (cache[idx].data, buffer, BLOCK_SECTOR_SIZE);
  
  /* --- MUDANÇA CRUCIAL: WRITE-BACK --- */
  /* Apenas marcamos como sujo. NÃO escrevemos no disco agora. */
  cache[idx].is_dirty = true; 
  /* ----------------------------------- */
  
  lock_release(&cache[idx].entry_lock);
  
  lock_release (&cache_global_lock);
}

void
cache_flush (void)
{
  lock_acquire (&cache_global_lock);
  for (int i = 0; i < CACHE_SIZE; i++)
    {
      lock_acquire(&cache[i].entry_lock); /* Adquirir lock da entrada */
      if (cache[i].is_valid && cache[i].is_dirty)
        {
          block_write (fs_device, cache[i].sector, cache[i].data);
          cache[i].is_dirty = false;
        }
      lock_release(&cache[i].entry_lock); /* Liberar lock da entrada */
    }
  lock_release (&cache_global_lock);
}