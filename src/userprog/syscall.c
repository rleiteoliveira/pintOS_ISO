#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "devices/input.h"
#include "userprog/pagedir.h"
#include "lib/kernel/console.h"
#include "userprog/pagedir.h"

static void syscall_handler (struct intr_frame *);
//Adicionado
static void validate_user_pointer(const void *uaddr);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f)
{
  // Valida o ponteiro da pilha para ler o número da syscall
  validate_user_pointer(f->esp + 3);
  int syscall_num = *(int *)f->esp;

  switch (syscall_num)
  {
  case SYS_HALT:
  {
    shutdown_power_off(); // Desliga o Pintos
    break;
  }
  case SYS_EXIT:
  {
    // Valida a leitura do argumento 'status' (bytes 4-7)
    validate_user_pointer(f->esp + 7);
    int status = *(int *)(f->esp + 4);
    thread_current()->exit_status = status;
    printf("%s: exit(%d)\n", thread_current()->name, status);
    thread_exit();
    break;
  }

  case SYS_WRITE:
    {
      // Valida a leitura de TODOS os 3 argumentos (bytes 4-15)
      validate_user_pointer(f->esp + 15);
      int fd = *(int *)(f->esp + 4);
      const void *buffer = *(void **)(f->esp + 8);
      unsigned size = *(unsigned *)(f->esp + 12);

      // Valida o buffer de usuário (ambas as pontas)
      validate_user_pointer(buffer);
      if (size > 0)
      {
        validate_user_pointer(buffer + size - 1);
      }
      if (fd == 1) // STDOUT_FILENO
      {
        const char *user_ptr = (const char *)buffer;
        unsigned bytes_written = 0;
        // Itera pelo buffer, lidando com fronteiras de página
        while (bytes_written < size)
        {
          // Calcula quantos bytes ler *nesta página*
          unsigned bytes_left_in_page = PGSIZE - pg_ofs(user_ptr);
          unsigned bytes_to_write = size - bytes_written;

          if (bytes_to_write > bytes_left_in_page)
          {
            bytes_to_write = bytes_left_in_page;
          }

          // Obtém o ponteiro do KERNEL para este pedaço do usuário
          // pagedir_get_page já retorna o ponteiro de kernel traduzido
          void *k_ptr = pagedir_get_page(thread_current()->pagedir, user_ptr);
          if (k_ptr == NULL)
          {
            thread_exit(); // Ponteiro inválido no meio do buffer
          }
          // Escreve o pedaço usando o ponteiro do KERNEL
          putbuf(k_ptr, bytes_to_write);

          // Avança os ponteiros
          bytes_written += bytes_to_write;
          user_ptr += bytes_to_write;
        }
        f->eax = size; // Retorna o total de bytes escritos
      }
      else
      {
        f->eax = -1; // Lógica para outros FDs (ainda não implementada)
      }
      break;
    }
  default:
  {
    thread_exit();
    break;
  }
  }
}

// Valida um ponteiro do espaço de usuário.
// Encerra o processo se o ponteiro for inválido.
static void
validate_user_pointer(const void *uaddr)
{
  struct thread *cur = thread_current();
  // Verifica se não é nulo e se está abaixo de PHYS_BASE, e se está mapeado na tabela de páginas.
  if (uaddr == NULL || !is_user_vaddr(uaddr) || pagedir_get_page(cur->pagedir, uaddr) == NULL)
  {
    thread_exit();
  }
}
