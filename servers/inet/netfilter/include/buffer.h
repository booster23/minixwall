#ifndef BUFFER_H
#define BUFFER_H BUFFER_H

struct buffer {
  void *next;
  char *data;
  int size;
};

void clearBuffers(struct buffer *buf);
void* appendBuffer(struct buffer *buf, char *data, int size);
int getTotalBufSize(struct buffer *buf);
void bondBuffers(char *singlebuf, struct buffer *buf);

#endif
