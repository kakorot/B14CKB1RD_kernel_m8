/*
 *   This program is free software; you can redistribute it and/or modify it
 *   under the terms of the GNU General Public License version 2 as published
 *   by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
 *
 *   Copyright (C) 2011 John Crispin <blogic@openwrt.org>
 */

#ifndef LTQ_DMA_H__
#define LTQ_DMA_H__

#define LTQ_DESC_SIZE		0x08	
#define LTQ_DESC_NUM		0x40	

#define LTQ_DMA_OWN		BIT(31)	
#define LTQ_DMA_C		BIT(30) 
#define LTQ_DMA_SOP		BIT(29) 
#define LTQ_DMA_EOP		BIT(28) 
#define LTQ_DMA_TX_OFFSET(x)	((x & 0x1f) << 23) 
#define LTQ_DMA_RX_OFFSET(x)	((x & 0x7) << 23) 
#define LTQ_DMA_SIZE_MASK	(0xffff) 

struct ltq_dma_desc {
	u32 ctl;
	u32 addr;
};

struct ltq_dma_channel {
	int nr;				
	int irq;			
	int desc;			
	struct ltq_dma_desc *desc_base;	
	int phys;			
};

enum {
	DMA_PORT_ETOP = 0,
	DMA_PORT_DEU,
};

extern void ltq_dma_enable_irq(struct ltq_dma_channel *ch);
extern void ltq_dma_disable_irq(struct ltq_dma_channel *ch);
extern void ltq_dma_ack_irq(struct ltq_dma_channel *ch);
extern void ltq_dma_open(struct ltq_dma_channel *ch);
extern void ltq_dma_close(struct ltq_dma_channel *ch);
extern void ltq_dma_alloc_tx(struct ltq_dma_channel *ch);
extern void ltq_dma_alloc_rx(struct ltq_dma_channel *ch);
extern void ltq_dma_free(struct ltq_dma_channel *ch);
extern void ltq_dma_init_port(int p);

#endif
