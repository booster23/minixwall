#include "inet.h"
#include "buf.h"
#include "type.h"
#include <stdio.h>
#include "assert.h"
#include "sr.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include "nf.h"
#include <nfcore.h>
#include <nf_ioctl_cmd.h>

THIS_FILE 

PUBLIC nf_fd_t nf_fd_table[1];
int nf_opened;
int ioctl_pend;

PUBLIC void nf_prep( void )
{
}

PUBLIC int nf_open( port, srfd, get_userdata_func, put_userdata_func,
             put_pkt, select_res )
int port;
int srfd;
get_userdata_t get_userdata_func;
put_userdata_t put_userdata_func;
put_pkt_t put_pkt;
select_res_t select_res;
{
	nf_fd_t *nf_fd;

	nf_fd= &nf_fd_table[0];

	nf_fd->nf_srfd= srfd;
	nf_fd->nf_get_userdata= get_userdata_func;
	nf_fd->nf_put_userdata= put_userdata_func;
	nf_fd->nf_select_res= select_res;
	nf_opened=TRUE;

	return 0;
}

PUBLIC void nf_close( fd )
int fd;
{
	nf_opened=FALSE;
}

PUBLIC int nf_init( void )
{
	nfCoreInit();
	sr_add_minor(if2minor(0, NF_DEV_OFF),
		0, nf_open, nf_close, nf_read,
		nf_write, nf_ioctl, nf_cancel, NULL);
	nf_opened=FALSE;
}

PUBLIC int nf_ioctl( fd, request )
int fd;
ioreq_t request;
{
  nf_fd_t *nf_fd=&nf_fd_table[0];

  if (!nf_opened)
  {
    reply_thr_get (nf_fd, EBADMODE, TRUE);
    return NW_OK;
  }
  ioctl_pend=request;
  reply_thr_get (nf_fd, NW_OK, TRUE);

  return NW_OK;
}

PUBLIC int nf_read( fd, count )
int fd;
size_t count;
{
  nf_fd_t *nf_fd=&nf_fd_table[0];
  if (!nf_opened || !ioctl_pend)
  {
    reply_thr_put (nf_fd, EBADMODE, FALSE);
    return NW_OK;
  }
  ioctl_pend=0;                     /* reset ioctl number */
  reply_thr_put (nf_fd, NW_OK, FALSE);

  return NW_OK;
}

PUBLIC int nf_write( fd, count )
int fd;
size_t count;
{
  nf_fd_t *nf_fd=&nf_fd_table[0];
  acc_t *data=NULL;
  void *data_p;
  int i=0;

  if (!nf_opened)
  {
    reply_thr_get (nf_fd, EBADMODE, FALSE);
    return NW_OK;
  }
  if (ioctl_pend)
  {
    /* fetch data from iptables */
    printf("nf_write:nf_srfd>%x  count>%u\n", nf_fd->nf_srfd, count);
    data=(*nf_fd->nf_get_userdata)(nf_fd->nf_srfd,0,count,FALSE);
    assert(data);
    data_p=data->acc_buffer->buf_data_p;
/*
for (i=0;i<10;i++)
{
  printf("%02x, ",*(((char*)(data_p)+i)));
}
printf("\n");
*/
    i=nf_ioctl_cmd(ioctl_pend,data_p);
    bf_afree(data);
  }
  ioctl_pend=0;                     /* reset ioctl number */
  reply_thr_get (nf_fd, i, FALSE);

  return NW_OK;
}

void reply_thr_put(nf_fd, reply, for_ioctl)
nf_fd_t *nf_fd;
int reply;
int for_ioctl;
{
	int result;

	result= (*nf_fd->nf_put_userdata)(nf_fd->nf_srfd, reply,
		(acc_t *)0, for_ioctl);
	assert(result == NW_OK);
}

/*
reply_thr_get
*/

void reply_thr_get(nf_fd, reply, for_ioctl)
nf_fd_t *nf_fd;
int reply;
int for_ioctl;
{
	acc_t *result;
	result= (*nf_fd->nf_get_userdata)(nf_fd->nf_srfd, reply,
		(size_t)0, for_ioctl);
	assert (!result);
}

PUBLIC int nf_cancel(fd, which_operation)
int fd;
int which_operation;
{
	nf_fd_t *nf_fd;

	DBLOCK(0x10, printf("nf_cancel(%d, %d)\n", fd, which_operation));

	nf_fd= &nf_fd_table[fd];

	switch (which_operation)
	{
	case SR_CANCEL_READ:
	case SR_CANCEL_WRITE:
	case SR_CANCEL_IOCTL:
	default:
		ip_panic(( "got unknown cancel request" ));
	}
	return NW_OK;
}
