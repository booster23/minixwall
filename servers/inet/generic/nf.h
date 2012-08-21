#ifndef NF_H
#define NF_H NF_H

typedef struct nf_fd
{
	int nf_srfd;
	get_userdata_t nf_get_userdata;
	put_userdata_t nf_put_userdata;
	put_pkt_t nf_put_pkt;
	ioreq_t nf_ioctl;
	select_res_t nf_select_res;
} nf_fd_t;


void nf_prep( void );
int nf_open( int port, int srfd, get_userdata_t get_userdata_func,
             put_userdata_t put_userdata_func,
             put_pkt_t put_pkt, select_res_t select_res );
void nf_close( int fd );
int nf_init( void );
int nf_ioctl( int fd, ioreq_t request );
int nf_read( int fd, size_t count );
int nf_write( int fd, size_t count );
void reply_thr_put(nf_fd_t *nf_fd, int reply, int for_ioctl);
void reply_thr_get(nf_fd_t *nf_fd, int reply, int for_ioctl);
int nf_cancel(int fd, int which_operation);
#endif
