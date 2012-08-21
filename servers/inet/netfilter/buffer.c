/*
 *  MINIX-3 network filter - linked buffer handling
 *
 *  (C) 2007 Brian Schueler (brian.schueler@gmx.de)
 *  
 *      As part of the diploma thesis:
 *      Analysis and Porting of a network 
 *      filtering architecture on Minix-3
 *      under supervision of
 *      Prof. Dr. rer. nat. Ruediger Weis
 *      at the University of Applied Sciences Berlin
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <stdio.h>
#include <string.h>
#include <buffer.h>
#include <sys/types.h>
#include <stdlib.h>

void clearBuffers(struct buffer *buf)
{
  struct buffer *rbuf = buf;
  struct buffer *todelete;
#ifdef _DEBUG
  printf("clearBuffers(): in\n");
#endif
  while (rbuf != NULL)
  {
    if (rbuf->data)
    {
      free(rbuf->data);
      rbuf->data = NULL;
      rbuf->size = 0;
    }
    todelete = rbuf;
    rbuf = rbuf->next;
    if (buf != todelete) free(todelete);
  }
  buf->next = NULL;
#ifdef _DEBUG
  printf("clearBuffers(): in\n");
#endif
}

void *appendBuffer(struct buffer *buf, char *data, int size)
{
  struct buffer *rbuf = buf;
#ifdef _DEBUG
  printf("appendbuffer(): buffer->size: %08x \n",rbuf->size);
  printf("              : data: %08x \n",*data);
  printf("              : size: %d \n",size);
#endif
  while (rbuf->next != NULL)
  {
    rbuf = rbuf->next;
  }
  rbuf->data = (char *) malloc (size * sizeof(char));
  memcpy(rbuf->data, data,size);
  rbuf->size = size;
  rbuf->next = (void *) malloc (sizeof(struct buffer));
  ((struct buffer*)(rbuf->next))->next = NULL;
  ((struct buffer*)(rbuf->next))->data = NULL;
  ((struct buffer*)(rbuf->next))->size = 0;
  return (rbuf->next);
}

int getTotalBufSize(struct buffer *buf)
{
  struct buffer *rbuf = buf;
  int total = 0;

  while (rbuf != NULL)
  {
    total = total + rbuf->size;
    rbuf = rbuf->next;
  }
  return total;
}

void bondBuffers(char *singlebuf, struct buffer *buf)
{
  struct buffer *rbuf = buf;
  int index = 0;

  while (rbuf != NULL)
  {
    memcpy(singlebuf+index, rbuf->data, rbuf->size);
    index = index + rbuf->size;
    rbuf = rbuf->next;
  }
}
