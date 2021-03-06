/*
 * Copyright (c) 2003-2007 Network Appliance, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the BSD-type
 * license below:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *      Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *
 *      Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 *      Neither the name of the Network Appliance, Inc. nor the names of
 *      its contributors may be used to endorse or promote products
 *      derived from this software without specific prior written
 *      permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/seq_file.h>

#include "xprt_rdma.h"

#ifdef RPC_DEBUG
# define RPCDBG_FACILITY	RPCDBG_TRANS
#endif

MODULE_LICENSE("Dual BSD/GPL");

MODULE_DESCRIPTION("RPC/RDMA Transport for Linux kernel NFS");
MODULE_AUTHOR("Network Appliance, Inc.");


static unsigned int xprt_rdma_slot_table_entries = RPCRDMA_DEF_SLOT_TABLE;
static unsigned int xprt_rdma_max_inline_read = RPCRDMA_DEF_INLINE;
static unsigned int xprt_rdma_max_inline_write = RPCRDMA_DEF_INLINE;
static unsigned int xprt_rdma_inline_write_padding;
static unsigned int xprt_rdma_memreg_strategy = RPCRDMA_FRMR;
                int xprt_rdma_pad_optimize = 0;

#ifdef RPC_DEBUG

static unsigned int min_slot_table_size = RPCRDMA_MIN_SLOT_TABLE;
static unsigned int max_slot_table_size = RPCRDMA_MAX_SLOT_TABLE;
static unsigned int zero;
static unsigned int max_padding = PAGE_SIZE;
static unsigned int min_memreg = RPCRDMA_BOUNCEBUFFERS;
static unsigned int max_memreg = RPCRDMA_LAST - 1;

static struct ctl_table_header *sunrpc_table_header;

static ctl_table xr_tunables_table[] = {
	{
		.procname	= "rdma_slot_table_entries",
		.data		= &xprt_rdma_slot_table_entries,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &min_slot_table_size,
		.extra2		= &max_slot_table_size
	},
	{
		.procname	= "rdma_max_inline_read",
		.data		= &xprt_rdma_max_inline_read,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "rdma_max_inline_write",
		.data		= &xprt_rdma_max_inline_write,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "rdma_inline_write_padding",
		.data		= &xprt_rdma_inline_write_padding,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &max_padding,
	},
	{
		.procname	= "rdma_memreg_strategy",
		.data		= &xprt_rdma_memreg_strategy,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &min_memreg,
		.extra2		= &max_memreg,
	},
	{
		.procname	= "rdma_pad_optimize",
		.data		= &xprt_rdma_pad_optimize,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{ },
};

static ctl_table sunrpc_table[] = {
	{
		.procname	= "sunrpc",
		.mode		= 0555,
		.child		= xr_tunables_table
	},
	{ },
};

#endif

static struct rpc_xprt_ops xprt_rdma_procs;	

static void
xprt_rdma_format_addresses(struct rpc_xprt *xprt)
{
	struct sockaddr *sap = (struct sockaddr *)
					&rpcx_to_rdmad(xprt).addr;
	struct sockaddr_in *sin = (struct sockaddr_in *)sap;
	char buf[64];

	(void)rpc_ntop(sap, buf, sizeof(buf));
	xprt->address_strings[RPC_DISPLAY_ADDR] = kstrdup(buf, GFP_KERNEL);

	snprintf(buf, sizeof(buf), "%u", rpc_get_port(sap));
	xprt->address_strings[RPC_DISPLAY_PORT] = kstrdup(buf, GFP_KERNEL);

	xprt->address_strings[RPC_DISPLAY_PROTO] = "rdma";

	snprintf(buf, sizeof(buf), "%08x", ntohl(sin->sin_addr.s_addr));
	xprt->address_strings[RPC_DISPLAY_HEX_ADDR] = kstrdup(buf, GFP_KERNEL);

	snprintf(buf, sizeof(buf), "%4hx", rpc_get_port(sap));
	xprt->address_strings[RPC_DISPLAY_HEX_PORT] = kstrdup(buf, GFP_KERNEL);

	
	xprt->address_strings[RPC_DISPLAY_NETID] = "rdma";
}

static void
xprt_rdma_free_addresses(struct rpc_xprt *xprt)
{
	unsigned int i;

	for (i = 0; i < RPC_DISPLAY_MAX; i++)
		switch (i) {
		case RPC_DISPLAY_PROTO:
		case RPC_DISPLAY_NETID:
			continue;
		default:
			kfree(xprt->address_strings[i]);
		}
}

static void
xprt_rdma_connect_worker(struct work_struct *work)
{
	struct rpcrdma_xprt *r_xprt =
		container_of(work, struct rpcrdma_xprt, rdma_connect.work);
	struct rpc_xprt *xprt = &r_xprt->xprt;
	int rc = 0;

	if (!xprt->shutdown) {
		current->flags |= PF_FSTRANS;
		xprt_clear_connected(xprt);

		dprintk("RPC:       %s: %sconnect\n", __func__,
				r_xprt->rx_ep.rep_connected != 0 ? "re" : "");
		rc = rpcrdma_ep_connect(&r_xprt->rx_ep, &r_xprt->rx_ia);
		if (rc)
			goto out;
	}
	goto out_clear;

out:
	xprt_wake_pending_tasks(xprt, rc);
out_clear:
	dprintk("RPC:       %s: exit\n", __func__);
	xprt_clear_connecting(xprt);
	current->flags &= ~PF_FSTRANS;
}

static void
xprt_rdma_destroy(struct rpc_xprt *xprt)
{
	struct rpcrdma_xprt *r_xprt = rpcx_to_rdmax(xprt);
	int rc;

	dprintk("RPC:       %s: called\n", __func__);

	cancel_delayed_work_sync(&r_xprt->rdma_connect);

	xprt_clear_connected(xprt);

	rpcrdma_buffer_destroy(&r_xprt->rx_buf);
	rc = rpcrdma_ep_destroy(&r_xprt->rx_ep, &r_xprt->rx_ia);
	if (rc)
		dprintk("RPC:       %s: rpcrdma_ep_destroy returned %i\n",
			__func__, rc);
	rpcrdma_ia_close(&r_xprt->rx_ia);

	xprt_rdma_free_addresses(xprt);

	xprt_free(xprt);

	dprintk("RPC:       %s: returning\n", __func__);

	module_put(THIS_MODULE);
}

static const struct rpc_timeout xprt_rdma_default_timeout = {
	.to_initval = 60 * HZ,
	.to_maxval = 60 * HZ,
};

static struct rpc_xprt *
xprt_setup_rdma(struct xprt_create *args)
{
	struct rpcrdma_create_data_internal cdata;
	struct rpc_xprt *xprt;
	struct rpcrdma_xprt *new_xprt;
	struct rpcrdma_ep *new_ep;
	struct sockaddr_in *sin;
	int rc;

	if (args->addrlen > sizeof(xprt->addr)) {
		dprintk("RPC:       %s: address too large\n", __func__);
		return ERR_PTR(-EBADF);
	}

	xprt = xprt_alloc(args->net, sizeof(struct rpcrdma_xprt),
			xprt_rdma_slot_table_entries,
			xprt_rdma_slot_table_entries);
	if (xprt == NULL) {
		dprintk("RPC:       %s: couldn't allocate rpcrdma_xprt\n",
			__func__);
		return ERR_PTR(-ENOMEM);
	}

	
	xprt->timeout = &xprt_rdma_default_timeout;
	xprt->bind_timeout = (60U * HZ);
	xprt->reestablish_timeout = (5U * HZ);
	xprt->idle_timeout = (5U * 60 * HZ);

	xprt->resvport = 0;		
	xprt->tsh_size = 0;		
	xprt->max_payload = RPCRDMA_MAX_DATA_SEGS * PAGE_SIZE;
	xprt->ops = &xprt_rdma_procs;


	
	memcpy(&cdata.addr, args->dstaddr, args->addrlen);

	xprt->prot = IPPROTO_TCP;
	xprt->addrlen = args->addrlen;
	memcpy(&xprt->addr, &cdata.addr, xprt->addrlen);

	sin = (struct sockaddr_in *)&cdata.addr;
	if (ntohs(sin->sin_port) != 0)
		xprt_set_bound(xprt);

	dprintk("RPC:       %s: %pI4:%u\n",
		__func__, &sin->sin_addr.s_addr, ntohs(sin->sin_port));

	
	cdata.max_requests = xprt->max_reqs;

	
	cdata.rsize = RPCRDMA_MAX_SEGS * PAGE_SIZE; 
	cdata.wsize = RPCRDMA_MAX_SEGS * PAGE_SIZE; 

	cdata.inline_wsize = xprt_rdma_max_inline_write;
	if (cdata.inline_wsize > cdata.wsize)
		cdata.inline_wsize = cdata.wsize;

	cdata.inline_rsize = xprt_rdma_max_inline_read;
	if (cdata.inline_rsize > cdata.rsize)
		cdata.inline_rsize = cdata.rsize;

	cdata.padding = xprt_rdma_inline_write_padding;


	new_xprt = rpcx_to_rdmax(xprt);

	rc = rpcrdma_ia_open(new_xprt, (struct sockaddr *) &cdata.addr,
				xprt_rdma_memreg_strategy);
	if (rc)
		goto out1;

	new_xprt->rx_data = cdata;
	new_ep = &new_xprt->rx_ep;
	new_ep->rep_remote_addr = cdata.addr;

	rc = rpcrdma_ep_create(&new_xprt->rx_ep,
				&new_xprt->rx_ia, &new_xprt->rx_data);
	if (rc)
		goto out2;

	rc = rpcrdma_buffer_create(&new_xprt->rx_buf, new_ep, &new_xprt->rx_ia,
				&new_xprt->rx_data);
	if (rc)
		goto out3;

	INIT_DELAYED_WORK(&new_xprt->rdma_connect, xprt_rdma_connect_worker);
	new_ep->rep_func = rpcrdma_conn_func;
	new_ep->rep_xprt = xprt;

	xprt_rdma_format_addresses(xprt);

	if (!try_module_get(THIS_MODULE))
		goto out4;

	return xprt;

out4:
	xprt_rdma_free_addresses(xprt);
	rc = -EINVAL;
out3:
	(void) rpcrdma_ep_destroy(new_ep, &new_xprt->rx_ia);
out2:
	rpcrdma_ia_close(&new_xprt->rx_ia);
out1:
	xprt_free(xprt);
	return ERR_PTR(rc);
}

static void
xprt_rdma_close(struct rpc_xprt *xprt)
{
	struct rpcrdma_xprt *r_xprt = rpcx_to_rdmax(xprt);

	dprintk("RPC:       %s: closing\n", __func__);
	if (r_xprt->rx_ep.rep_connected > 0)
		xprt->reestablish_timeout = 0;
	xprt_disconnect_done(xprt);
	(void) rpcrdma_ep_disconnect(&r_xprt->rx_ep, &r_xprt->rx_ia);
}

static void
xprt_rdma_set_port(struct rpc_xprt *xprt, u16 port)
{
	struct sockaddr_in *sap;

	sap = (struct sockaddr_in *)&xprt->addr;
	sap->sin_port = htons(port);
	sap = (struct sockaddr_in *)&rpcx_to_rdmad(xprt).addr;
	sap->sin_port = htons(port);
	dprintk("RPC:       %s: %u\n", __func__, port);
}

static void
xprt_rdma_connect(struct rpc_task *task)
{
	struct rpc_xprt *xprt = (struct rpc_xprt *)task->tk_xprt;
	struct rpcrdma_xprt *r_xprt = rpcx_to_rdmax(xprt);

	if (r_xprt->rx_ep.rep_connected != 0) {
		
		schedule_delayed_work(&r_xprt->rdma_connect,
			xprt->reestablish_timeout);
		xprt->reestablish_timeout <<= 1;
		if (xprt->reestablish_timeout > (30 * HZ))
			xprt->reestablish_timeout = (30 * HZ);
		else if (xprt->reestablish_timeout < (5 * HZ))
			xprt->reestablish_timeout = (5 * HZ);
	} else {
		schedule_delayed_work(&r_xprt->rdma_connect, 0);
		if (!RPC_IS_ASYNC(task))
			flush_delayed_work(&r_xprt->rdma_connect);
	}
}

static int
xprt_rdma_reserve_xprt(struct rpc_xprt *xprt, struct rpc_task *task)
{
	struct rpcrdma_xprt *r_xprt = rpcx_to_rdmax(xprt);
	int credits = atomic_read(&r_xprt->rx_buf.rb_credits);

	
	if (r_xprt->rx_buf.rb_cwndscale == 0UL) {
		r_xprt->rx_buf.rb_cwndscale = xprt->cwnd;
		dprintk("RPC:       %s: cwndscale %lu\n", __func__,
			r_xprt->rx_buf.rb_cwndscale);
		BUG_ON(r_xprt->rx_buf.rb_cwndscale <= 0);
	}
	xprt->cwnd = credits * r_xprt->rx_buf.rb_cwndscale;
	return xprt_reserve_xprt_cong(xprt, task);
}

static void *
xprt_rdma_allocate(struct rpc_task *task, size_t size)
{
	struct rpc_xprt *xprt = task->tk_xprt;
	struct rpcrdma_req *req, *nreq;

	req = rpcrdma_buffer_get(&rpcx_to_rdmax(xprt)->rx_buf);
	BUG_ON(NULL == req);

	if (size > req->rl_size) {
		dprintk("RPC:       %s: size %zd too large for buffer[%zd]: "
			"prog %d vers %d proc %d\n",
			__func__, size, req->rl_size,
			task->tk_client->cl_prog, task->tk_client->cl_vers,
			task->tk_msg.rpc_proc->p_proc);
		if (rpcx_to_rdmax(xprt)->rx_ia.ri_memreg_strategy ==
				RPCRDMA_BOUNCEBUFFERS) {
			
			dprintk("RPC:       %s: too much data (%zd) for inline "
					"(r/w max %d/%d)\n", __func__, size,
					rpcx_to_rdmad(xprt).inline_rsize,
					rpcx_to_rdmad(xprt).inline_wsize);
			size = req->rl_size;
			rpc_exit(task, -EIO);		
			rpcx_to_rdmax(xprt)->rx_stats.failed_marshal_count++;
			goto out;
		}
		if (task->tk_flags & RPC_TASK_SWAPPER)
			nreq = kmalloc(sizeof *req + size, GFP_ATOMIC);
		else
			nreq = kmalloc(sizeof *req + size, GFP_NOFS);
		if (nreq == NULL)
			goto outfail;

		if (rpcrdma_register_internal(&rpcx_to_rdmax(xprt)->rx_ia,
				nreq->rl_base, size + sizeof(struct rpcrdma_req)
				- offsetof(struct rpcrdma_req, rl_base),
				&nreq->rl_handle, &nreq->rl_iov)) {
			kfree(nreq);
			goto outfail;
		}
		rpcx_to_rdmax(xprt)->rx_stats.hardway_register_count += size;
		nreq->rl_size = size;
		nreq->rl_niovs = 0;
		nreq->rl_nchunks = 0;
		nreq->rl_buffer = (struct rpcrdma_buffer *)req;
		nreq->rl_reply = req->rl_reply;
		memcpy(nreq->rl_segments,
			req->rl_segments, sizeof nreq->rl_segments);
		
		nreq->rl_iov.length = 0;
		req->rl_reply = NULL;
		req = nreq;
	}
	dprintk("RPC:       %s: size %zd, request 0x%p\n", __func__, size, req);
out:
	req->rl_connect_cookie = 0;	
	return req->rl_xdr_buf;

outfail:
	rpcrdma_buffer_put(req);
	rpcx_to_rdmax(xprt)->rx_stats.failed_marshal_count++;
	return NULL;
}

static void
xprt_rdma_free(void *buffer)
{
	struct rpcrdma_req *req;
	struct rpcrdma_xprt *r_xprt;
	struct rpcrdma_rep *rep;
	int i;

	if (buffer == NULL)
		return;

	req = container_of(buffer, struct rpcrdma_req, rl_xdr_buf[0]);
	if (req->rl_iov.length == 0) {	
		r_xprt = container_of(((struct rpcrdma_req *) req->rl_buffer)->rl_buffer,
				      struct rpcrdma_xprt, rx_buf);
	} else
		r_xprt = container_of(req->rl_buffer, struct rpcrdma_xprt, rx_buf);
	rep = req->rl_reply;

	dprintk("RPC:       %s: called on 0x%p%s\n",
		__func__, rep, (rep && rep->rr_func) ? " (with waiter)" : "");

	for (i = 0; req->rl_nchunks;) {
		--req->rl_nchunks;
		i += rpcrdma_deregister_external(
			&req->rl_segments[i], r_xprt, NULL);
	}

	if (rep && wait_event_interruptible(rep->rr_unbind, !rep->rr_func)) {
		rep->rr_func = NULL;	
		req->rl_reply = NULL;
	}

	if (req->rl_iov.length == 0) {	
		struct rpcrdma_req *oreq = (struct rpcrdma_req *)req->rl_buffer;
		oreq->rl_reply = req->rl_reply;
		(void) rpcrdma_deregister_internal(&r_xprt->rx_ia,
						   req->rl_handle,
						   &req->rl_iov);
		kfree(req);
		req = oreq;
	}

	
	rpcrdma_buffer_put(req);
}


static int
xprt_rdma_send_request(struct rpc_task *task)
{
	struct rpc_rqst *rqst = task->tk_rqstp;
	struct rpc_xprt *xprt = task->tk_xprt;
	struct rpcrdma_req *req = rpcr_to_rdmar(rqst);
	struct rpcrdma_xprt *r_xprt = rpcx_to_rdmax(xprt);

	
	if (req->rl_niovs == 0 && rpcrdma_marshal_req(rqst) != 0) {
		r_xprt->rx_stats.failed_marshal_count++;
		dprintk("RPC:       %s: rpcrdma_marshal_req failed\n",
			__func__);
		return -EIO;
	}

	if (req->rl_reply == NULL) 		
		rpcrdma_recv_buffer_get(req);

	if (req->rl_reply) {
		req->rl_reply->rr_func = rpcrdma_reply_handler;
		
		req->rl_reply->rr_xprt = xprt;
	}

	
	if (req->rl_connect_cookie == xprt->connect_cookie)
		goto drop_connection;
	req->rl_connect_cookie = xprt->connect_cookie;

	if (rpcrdma_ep_post(&r_xprt->rx_ia, &r_xprt->rx_ep, req))
		goto drop_connection;

	rqst->rq_xmit_bytes_sent += rqst->rq_snd_buf.len;
	rqst->rq_bytes_sent = 0;
	return 0;

drop_connection:
	xprt_disconnect_done(xprt);
	return -ENOTCONN;	
}

static void xprt_rdma_print_stats(struct rpc_xprt *xprt, struct seq_file *seq)
{
	struct rpcrdma_xprt *r_xprt = rpcx_to_rdmax(xprt);
	long idle_time = 0;

	if (xprt_connected(xprt))
		idle_time = (long)(jiffies - xprt->last_used) / HZ;

	seq_printf(seq,
	  "\txprt:\trdma %u %lu %lu %lu %ld %lu %lu %lu %Lu %Lu "
	  "%lu %lu %lu %Lu %Lu %Lu %Lu %lu %lu %lu\n",

	   0,	
	   xprt->stat.bind_count,
	   xprt->stat.connect_count,
	   xprt->stat.connect_time,
	   idle_time,
	   xprt->stat.sends,
	   xprt->stat.recvs,
	   xprt->stat.bad_xids,
	   xprt->stat.req_u,
	   xprt->stat.bklog_u,

	   r_xprt->rx_stats.read_chunk_count,
	   r_xprt->rx_stats.write_chunk_count,
	   r_xprt->rx_stats.reply_chunk_count,
	   r_xprt->rx_stats.total_rdma_request,
	   r_xprt->rx_stats.total_rdma_reply,
	   r_xprt->rx_stats.pullup_copy_count,
	   r_xprt->rx_stats.fixup_copy_count,
	   r_xprt->rx_stats.hardway_register_count,
	   r_xprt->rx_stats.failed_marshal_count,
	   r_xprt->rx_stats.bad_reply_count);
}


static struct rpc_xprt_ops xprt_rdma_procs = {
	.reserve_xprt		= xprt_rdma_reserve_xprt,
	.release_xprt		= xprt_release_xprt_cong, /* sunrpc/xprt.c */
	.alloc_slot		= xprt_alloc_slot,
	.release_request	= xprt_release_rqst_cong,       /* ditto */
	.set_retrans_timeout	= xprt_set_retrans_timeout_def,  /* ditto */
	.rpcbind		= rpcb_getport_async,	
	.set_port		= xprt_rdma_set_port,
	.connect		= xprt_rdma_connect,
	.buf_alloc		= xprt_rdma_allocate,
	.buf_free		= xprt_rdma_free,
	.send_request		= xprt_rdma_send_request,
	.close			= xprt_rdma_close,
	.destroy		= xprt_rdma_destroy,
	.print_stats		= xprt_rdma_print_stats
};

static struct xprt_class xprt_rdma = {
	.list			= LIST_HEAD_INIT(xprt_rdma.list),
	.name			= "rdma",
	.owner			= THIS_MODULE,
	.ident			= XPRT_TRANSPORT_RDMA,
	.setup			= xprt_setup_rdma,
};

static void __exit xprt_rdma_cleanup(void)
{
	int rc;

	dprintk(KERN_INFO "RPCRDMA Module Removed, deregister RPC RDMA transport\n");
#ifdef RPC_DEBUG
	if (sunrpc_table_header) {
		unregister_sysctl_table(sunrpc_table_header);
		sunrpc_table_header = NULL;
	}
#endif
	rc = xprt_unregister_transport(&xprt_rdma);
	if (rc)
		dprintk("RPC:       %s: xprt_unregister returned %i\n",
			__func__, rc);
}

static int __init xprt_rdma_init(void)
{
	int rc;

	rc = xprt_register_transport(&xprt_rdma);

	if (rc)
		return rc;

	dprintk(KERN_INFO "RPCRDMA Module Init, register RPC RDMA transport\n");

	dprintk(KERN_INFO "Defaults:\n");
	dprintk(KERN_INFO "\tSlots %d\n"
		"\tMaxInlineRead %d\n\tMaxInlineWrite %d\n",
		xprt_rdma_slot_table_entries,
		xprt_rdma_max_inline_read, xprt_rdma_max_inline_write);
	dprintk(KERN_INFO "\tPadding %d\n\tMemreg %d\n",
		xprt_rdma_inline_write_padding, xprt_rdma_memreg_strategy);

#ifdef RPC_DEBUG
	if (!sunrpc_table_header)
		sunrpc_table_header = register_sysctl_table(sunrpc_table);
#endif
	return 0;
}

module_init(xprt_rdma_init);
module_exit(xprt_rdma_cleanup);
