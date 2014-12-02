/*
 * vGT command parser
 *
 * Copyright(c) 2011-2013 Intel Corporation. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/slab.h>
#include "vgt.h"
#include "trace.h"
#include "fb_decoder.h"

#define CMDLEN			4

/* vgt uses below bits in NOOP_ID:
 *	    bit 21 - 16 is command type.
 *	    bit 15 - 0  holds command specific information.
 *
 * Assumption: Linux/Windows guest will not use bits 21 - bits 16 with
 * non-zero value.
 */
#define VGT_NOOP_ID_CMD_SHIFT	16
#define VGT_NOOP_ID_CMD_MASK	(0x3f << VGT_NOOP_ID_CMD_SHIFT)
#define CMD_LENGTH_MASK		0xff

/*
 * new cmd parser
 */

DEFINE_HASHTABLE(vgt_cmd_table, VGT_CMD_HASH_BITS);

static void vgt_add_cmd_entry(struct vgt_cmd_entry *e)
{
	hash_add(vgt_cmd_table, &e->hlist, e->info->opcode);
}

static struct cmd_info* vgt_find_cmd_entry(unsigned int opcode, int ring_id)
{
	struct vgt_cmd_entry *e;

	hash_for_each_possible(vgt_cmd_table, e, hlist, opcode) {
		if ( (opcode == e->info->opcode) && (e->info->rings & (1<<ring_id)) )
			return e->info;
	}
	return NULL;
}

static struct cmd_info* vgt_find_cmd_entry_any_ring(unsigned int opcode, int rings)
{
	struct cmd_info* info = NULL;
	unsigned int ring;
	for_each_set_bit(ring, (unsigned long*)&rings, MAX_ENGINES){
		info = vgt_find_cmd_entry(opcode, ring);
		if(info)
			break;
	}
	return info;
}

void vgt_clear_cmd_table(void)
{
	int i;
	struct hlist_node *tmp;
	struct vgt_cmd_entry *e;

	hash_for_each_safe(vgt_cmd_table, i, tmp, e, hlist)
		kfree(e);

	hash_init(vgt_cmd_table);
}
#ifdef VGT_ENABLE_ADDRESS_FIX
static int address_fixup(struct parser_exec_state *s, int index){
	/*TODO: add address fix up implementation */
	return 0;
}
#else

#define address_fixup(s,index)	do{}while(0)

#endif

void vgt_init_cmd_info(vgt_state_ring_t *rs)
{
	memset(&rs->patch_list, 0, sizeof(struct cmd_general_info));
	rs->patch_list.head = 0;
	rs->patch_list.tail = 0;
	rs->patch_list.count = CMD_PATCH_NUM;
	memset(&rs->handler_list, 0, sizeof(struct cmd_general_info));
	rs->handler_list.head = 0;
	rs->handler_list.tail = 0;
	rs->handler_list.count = CMD_HANDLER_NUM;
	memset(&rs->tail_list, 0, sizeof(struct cmd_general_info));
	rs->tail_list.head = 0;
	rs->tail_list.tail = 0;
	rs->tail_list.count = CMD_TAIL_NUM;
}

static int get_next_entry(struct cmd_general_info *list)
{
	int next;

	next = list->tail + 1;
	if (next == list->count)
		next = 0;

	if (next == list->head)
		next = list->count;

	return next;
}

/* TODO: support incremental patching */
static int add_patch_entry(struct parser_exec_state *s,
	void *addr, uint32_t val)
{
	vgt_state_ring_t* rs = &s->vgt->rb[s->ring_id];
	struct cmd_general_info *list = &rs->patch_list;
	struct cmd_patch_info *patch;
	int next;

	ASSERT(addr != NULL);

	next = get_next_entry(list);
	if (next == list->count) {
		vgt_err("CMD_SCAN: no free patch entry\n");
		return -ENOSPC;
	}

	vgt_dbg(VGT_DBG_CMD, "VM(%d): Add patch entry-%d (addr: %llx, val: %x, id: %lld\n",
		s->vgt->vm_id, next, (uint64_t)addr, val, s->request_id);
	patch = &list->patch[next];
	patch->addr = addr;
	patch->new_val = val;
	patch->request_id = s->request_id;
	if (s->vgt->vm_id == 0 || vgt_in_xen)
		patch->old_val = *(uint32_t *)addr;
	else
		patch->old_val = kvmgt_read_hva(s->vgt, addr, CMDLEN, 1);

	list->tail = next;
	return 0;
}

static int add_post_handle_entry(struct parser_exec_state *s,
	parser_cmd_handler handler)
{
	vgt_state_ring_t* rs = &s->vgt->rb[s->ring_id];
	struct cmd_general_info *list = &rs->handler_list;
	struct cmd_handler_info *entry;
	int next;

	next = get_next_entry(list);
	if (next == list->count) {
		vgt_err("CMD_SCAN: no free post-handle entry\n");
		return -ENOSPC;
	}

	entry = &list->handler[next];
	/* two pages mapping are always valid */
	memcpy(&entry->exec_state, s, sizeof(struct parser_exec_state));
	entry->handler = handler;
	entry->request_id = s->request_id;

	list->tail = next;
	return 0;

}

static int add_tail_entry(struct parser_exec_state *s,
	uint32_t tail, uint32_t cmd_nr, uint32_t flags)
{
	vgt_state_ring_t* rs = &s->vgt->rb[s->ring_id];
	struct cmd_general_info *list = &rs->tail_list;
	struct cmd_tail_info *entry;
	int next;

	next = get_next_entry(list);
	if (next == list->count) {
		vgt_err("CMD_SCAN: no free tail entry\n");
		return -ENOSPC;
	}

	entry = &list->cmd[next];
	entry->request_id = s->request_id;
	entry->tail = tail;
	entry->cmd_nr = cmd_nr;
	entry->flags = flags;

	list->tail = next;
	return 0;

}

static void apply_patch_entry(struct vgt_device *vgt, struct cmd_patch_info *patch)
{
	ASSERT(patch->addr);

	if (vgt->vm_id == 0 || vgt_in_xen) {
		*(uint32_t *)patch->addr = patch->new_val;
		clflush(patch->addr);
	} else {
		kvmgt_write_hva(vgt, patch->addr, &patch->new_val, CMDLEN, 1);
	}
}

#if 0
static void revert_batch_entry(struct batch_info *info)
{
	ASSERT(info->addr);

	*(uint32_t *)info->addr = info->old_val;
}
#endif

/*
 * Apply all patch entries with request ID before or
 * equal to the submission ID
 */
static void apply_patch_list(struct vgt_device *vgt, vgt_state_ring_t *rs, uint64_t submission_id)
{
	int next;
	struct cmd_general_info *list = &rs->patch_list;
	struct cmd_patch_info *patch;

	next = list->head;
	while (next != list->tail) {
		next++;
		if (next == list->count)
			next = 0;
		patch = &list->patch[next];
		/* TODO: handle id wrap */
		if (patch->request_id > submission_id)
			break;

		vgt_dbg(VGT_DBG_CMD, "submission-%lld: apply patch entry-%d (addr: %llx, val: %x->%x, id: %lld\n",
			submission_id, next, (uint64_t)patch->addr,
			patch->old_val, patch->new_val, patch->request_id);
		apply_patch_entry(vgt, patch);
		list->head = next;
	}
}

/*
 * Invoke all post-handle entries with request ID before or
 * equal to the submission ID
 */
static void apply_post_handle_list(vgt_state_ring_t *rs, uint64_t submission_id)
{
	int next;
	struct cmd_general_info *list = &rs->handler_list;
	struct cmd_handler_info *entry;

	next = list->head;
	while (next != list->tail) {
		next++;
		if (next == list->count)
			next = 0;
		entry = &list->handler[next];
		/* TODO: handle id wrap */
		if (entry->request_id > submission_id)
			break;

		entry->handler(&entry->exec_state);
		list->head = next;
	}
}

/* submit tails according to submission id */
void apply_tail_list(struct vgt_device *vgt, int ring_id,
	uint64_t submission_id)
{
	int next;
	struct pgt_device *pdev = vgt->pdev;
	vgt_state_ring_t *rs = &vgt->rb[ring_id];
	struct cmd_general_info *list = &rs->tail_list;
	struct cmd_tail_info *entry;

	next = list->head;
	while (next != list->tail) {
		next++;
		if (next == list->count)
			next = 0;
		entry = &list->cmd[next];
		/* TODO: handle id wrap */
		if (entry->request_id > submission_id)
			break;

		apply_post_handle_list(rs, entry->request_id);
		apply_patch_list(vgt, rs, entry->request_id);

		if ((rs->uhptr & _REGBIT_UHPTR_VALID) &&
		    (rs->uhptr_id < entry->request_id)) {
			rs->uhptr &= ~_REGBIT_UHPTR_VALID;
			VGT_MMIO_WRITE(pdev, VGT_UHPTR(ring_id), rs->uhptr);
		}

		VGT_WRITE_TAIL(pdev, ring_id, entry->tail);
		list->head = next;
	}
}

/* find allowable tail info based on cmd budget */
int get_submission_id(vgt_state_ring_t *rs, int budget,
	uint64_t *submission_id)
{
	int next, cmd_nr = 0;
	struct cmd_general_info *list = &rs->tail_list;
	struct cmd_tail_info *entry, *target = NULL;

	next = list->head;
	while (next != list->tail) {
		next++;
		if (next == list->count)
			next = 0;
		entry = &list->cmd[next];
		budget -= entry->cmd_nr;
		if (budget < 0)
			break;
		target = entry;
		cmd_nr += entry->cmd_nr;
	}

	if (target) {
		*submission_id = target->request_id;
		return cmd_nr;
	} else
		return MAX_CMD_BUDGET;
}

/* ring ALL, type = 0 */
static struct sub_op_bits sub_op_mi[]={
	{31, 29},
	{28, 23},
};

static struct decode_info decode_info_mi = {
	"MI",
	OP_LEN_MI,
	ARRAY_SIZE(sub_op_mi),
	sub_op_mi,
};


/* ring RCS, command type 2 */
static struct sub_op_bits sub_op_2d[]={
	{31, 29},
	{28, 22},
};

static struct decode_info decode_info_2d = {
	"2D",
	OP_LEN_2D,
	ARRAY_SIZE(sub_op_2d),
	sub_op_2d,
};

/* ring RCS, command type 3 */
static struct sub_op_bits sub_op_3d_media[]={
	{31, 29},
	{28, 27},
	{26, 24},
	{23, 16},
};

static struct decode_info decode_info_3d_media = {
	"3D_Media",
	OP_LEN_3D_MEDIA,
	ARRAY_SIZE(sub_op_3d_media),
	sub_op_3d_media,
};

/* ring VCS, command type 3 */
static struct sub_op_bits sub_op_mfx_vc[]={
	{31, 29},
	{28, 27},
	{26, 24},
	{23, 21},
	{20, 16},
};

static struct decode_info decode_info_mfx_vc = {
	"MFX_VC",
	OP_LEN_MFX_VC,
	ARRAY_SIZE(sub_op_mfx_vc),
	sub_op_mfx_vc,
};

/* ring VECS, command type 3 */
static struct sub_op_bits sub_op_vebox[] = {
	{31, 29},
	{28, 27},
	{26, 24},
	{23, 21},
	{20, 16},
};

static struct decode_info decode_info_vebox = {
	"VEBOX",
	OP_LEN_VEBOX,
	ARRAY_SIZE(sub_op_vebox),
	sub_op_vebox,
};

static struct decode_info* ring_decode_info[MAX_ENGINES][8]=
{
	[RING_BUFFER_RCS] = {
		&decode_info_mi,
		NULL,
		NULL,
		&decode_info_3d_media,
		NULL,
		NULL,
		NULL,
		NULL,
	},

	[RING_BUFFER_VCS] = {
		&decode_info_mi,
		NULL,
		NULL,
		&decode_info_mfx_vc,
		NULL,
		NULL,
		NULL,
		NULL,
	},

	[RING_BUFFER_BCS] = {
		&decode_info_mi,
		NULL,
		&decode_info_2d,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
	},

	[RING_BUFFER_VECS] = {
		&decode_info_mi,
		NULL,
		NULL,
		&decode_info_vebox,
		NULL,
		NULL,
		NULL,
		NULL,
	},
};

uint32_t vgt_get_opcode(uint32_t cmd, int ring_id)
{
	struct decode_info * d_info;

	if (ring_id >= MAX_ENGINES)
		return INVALID_OP;

	d_info = ring_decode_info[ring_id][CMD_TYPE(cmd)];
	if (d_info == NULL)
		return INVALID_OP;

	return cmd >> (32 - d_info->op_len);
}

static inline uint32_t sub_op_val(uint32_t cmd, uint32_t hi, uint32_t low)
{
	return (cmd >> low) & ((1U << (hi-low+1)) - 1);
}

static void vgt_print_opcode(uint32_t cmd, int ring_id)
{
	struct decode_info * d_info;
	int i;

	if (ring_id >= MAX_ENGINES)
		return;

	d_info = ring_decode_info[ring_id][CMD_TYPE(cmd)];
	if (d_info == NULL)
		return;

	vgt_err("opcode=0x%x %s sub_ops:", cmd >> (32 - d_info->op_len), d_info->name);
	for (i=0; i< d_info->nr_sub_op; i++){
		vgt_err("0x%x ", sub_op_val(cmd, d_info->sub_op[i].hi,  d_info->sub_op[i].low));
	}
	vgt_err("\n");
}

static inline struct cmd_info* vgt_get_cmd_info(uint32_t cmd, int ring_id)
{
	uint32_t opcode;

	opcode = vgt_get_opcode(cmd, ring_id);
	if (opcode == INVALID_OP){
		return NULL;
	}

	return vgt_find_cmd_entry(opcode, ring_id);
}

static inline uint32_t *cmd_ptr(struct parser_exec_state *s, int index)
{
	if (index < s->ip_buf_len)
		return s->ip_va + index;
	else
		return s->ip_va_next_page + (index - s->ip_buf_len);
}

static inline uint32_t cmd_val(struct parser_exec_state *s, int index)
{
	if (vgt_in_xen) {
		return *cmd_ptr(s, index);
	} else if (s->vgt->vm_id == 0) {
		return *cmd_ptr(s, index);
	} else {
		return kvmgt_read_hva(s->vgt, cmd_ptr(s, index), CMDLEN, 1);
	}
}

static void parser_exec_state_dump(struct parser_exec_state *s)
{
	vgt_err("  vgt%d RING%d: ring_start(%08lx) ring_end(%08lx)"
			" ring_head(%08lx) ring_tail(%08lx)\n", s->vgt->vgt_id,
			s->ring_id, s->ring_start, s->ring_start + s->ring_size, s->ring_head, s->ring_tail);

	vgt_err("  %s %s ip_gma(%08lx) ",
			s->buf_type == RING_BUFFER_INSTRUCTION ? "RING_BUFFER": "BATCH_BUFFER",
			s->buf_addr_type == GTT_BUFFER ? "GTT" : "PPGTT", s->ip_gma);

	if (s->ip_va == NULL){
		vgt_err(" ip_va(NULL)\n");
	}else{
		vgt_err("  ip_va=%p: %08x %08x %08x %08x \n",
				s->ip_va, cmd_val(s, 0), cmd_val(s,1), cmd_val(s, 2), cmd_val(s, 3));
		vgt_print_opcode(cmd_val(s, 0), s->ring_id);
	}
}
#define RING_BUF_WRAP(s, ip_gma)	(((s)->buf_type == RING_BUFFER_INSTRUCTION) && \
		((ip_gma) >= (s)->ring_start + (s)->ring_size))

static int ip_gma_set(struct parser_exec_state *s, unsigned long ip_gma)
{
	unsigned long gma_next_page;

	ASSERT(VGT_REG_IS_ALIGNED(ip_gma, 4));

	/* set ip_gma */

	if (RING_BUF_WRAP(s, ip_gma)){
		ip_gma = ip_gma - s->ring_size;
	}

	s->ip_gma = ip_gma;
	s->ip_va = vgt_gma_to_va(s->vgt, ip_gma,
			s->buf_addr_type == PPGTT_BUFFER);

	if (s->ip_va == NULL){
		vgt_err("ERROR: gma %lx is invalid, fail to set\n",s->ip_gma);
		dump_stack();
		parser_exec_state_dump(s);
		return -EFAULT;
	}

	s->ip_buf_len = (PAGE_SIZE - (ip_gma & (PAGE_SIZE-1)))
		/ sizeof(uint32_t);

	/* set ip of next page */

	if (RING_BUF_WRAP(s, ip_gma + PAGE_SIZE)){
		gma_next_page = s->ring_start;
	}else{
		gma_next_page = ((ip_gma >> PAGE_SHIFT) + 1) << PAGE_SHIFT;
	}
	s->ip_va_next_page = vgt_gma_to_va(s->vgt, gma_next_page,
			s->buf_addr_type == PPGTT_BUFFER);

	if (s->ip_va_next_page == NULL){
		vgt_err("ERROR: next page gma %lx is invalid, fail to set\n",gma_next_page);
		dump_stack();
		parser_exec_state_dump(s);
		return -EFAULT;
	}

	return 0;
}

static inline int ip_gma_advance(struct parser_exec_state *s, unsigned int len)
{
	int rc = 0;

	if (s->ip_buf_len > len) {
		/* not cross page, advance ip inside page */
		s->ip_gma += len * sizeof(uint32_t);
		s->ip_va += len;
		s->ip_buf_len -= len;
	} else {
		/* cross page, reset ip_va */
		rc = ip_gma_set(s, s->ip_gma + len * sizeof(uint32_t));
	}
	return rc;
}

static inline int cmd_length(struct parser_exec_state *s)
{
	struct cmd_info *info = s->info;

	/*
	 * MI_NOOP is special as the replacement elements. It's fixed
	 * length in definition, but variable length when using for
	 * replacement purpose. Instead of having the same handler
	 * invoke twice (may be postponed), special case length
	 * handling for MI_NOOP.
	 */
	if (info->opcode == OP_MI_NOOP) {
		unsigned int cmd, length = info->len;
		cmd = (cmd_val(s,0) & VGT_NOOP_ID_CMD_MASK) >>
			VGT_NOOP_ID_CMD_SHIFT;
		if (cmd)
			length = cmd_val(s,0) & CMD_LENGTH_MASK;

		return length;
	} else if ((info->flag & F_LEN_MASK) == F_LEN_CONST) {
		return info->len;
	}
	else /* F_LEN_VAR */{
		return (cmd_val(s,0) & ( (1U << s->info->len) - 1)) + 2;
	}
}

static int vgt_cmd_handler_mi_set_context(struct parser_exec_state* s)
{
	struct vgt_device *vgt = s->vgt;

	if (!vgt->has_context) {
		printk("VM %d activate context\n", vgt->vm_id);
		vgt->has_context = 1;
	}

	return 0;
}

#define BIT_RANGE_MASK(a,b)	\
	((1UL << ((a) + 1)) - (1UL << (b)))
static int vgt_cmd_handler_lri(struct parser_exec_state *s)
{
	unsigned int offset;
	struct pgt_device *pdev = s->vgt->pdev;

	offset = cmd_val(s, 1) & BIT_RANGE_MASK(22, 2);
	reg_set_cmd_access(pdev, offset);

	return 0;
}

static int vgt_cmd_handler_lrr(struct parser_exec_state *s)
{
	unsigned int offset;
	struct pgt_device *pdev = s->vgt->pdev;

	offset = cmd_val(s, 1) & BIT_RANGE_MASK(22, 2);
	reg_set_cmd_access(pdev, offset);

	offset = cmd_val(s, 2) & BIT_RANGE_MASK(22, 2);
	reg_set_cmd_access(pdev, offset);
	return 0;
}

static int vgt_cmd_handler_lrm(struct parser_exec_state *s)
{
	unsigned int offset;
	struct pgt_device *pdev = s->vgt->pdev;

	offset = cmd_val(s, 1) & BIT_RANGE_MASK(22, 2);
	reg_set_cmd_access(pdev, offset);

	return 0;
}

static int vgt_cmd_handler_srm(struct parser_exec_state *s)
{
	unsigned int offset;
	struct pgt_device *pdev = s->vgt->pdev;

	offset = cmd_val(s, 1) & BIT_RANGE_MASK(22, 2);
	reg_set_cmd_access(pdev, offset);

	return 0;
}

static int vgt_cmd_handler_pipe_control(struct parser_exec_state *s)
{
	unsigned int offset;
	struct pgt_device *pdev = s->vgt->pdev;
	if (cmd_val(s, 1) & PIPE_CONTROL_POST_SYNC) {
		offset = cmd_val(s, 2) & BIT_RANGE_MASK(22, 2);
		reg_set_cmd_access(pdev, offset);
	} else if (cmd_val(s, 1) & (2 << 14))
		reg_set_cmd_access(pdev, 0x2350);
	else if (cmd_val(s, 1) & (3 << 14))
		reg_set_cmd_access(pdev, _REG_RCS_TIMESTAMP);

	return 0;
}

static int vgt_cmd_advance_default(struct parser_exec_state *s)
{
	return ip_gma_advance(s, cmd_length(s));
}


static int vgt_cmd_handler_mi_batch_buffer_end(struct parser_exec_state *s)
{
	int rc;

	if (s->buf_type == BATCH_BUFFER_2ND_LEVEL){
		s->buf_type = BATCH_BUFFER_INSTRUCTION;
		rc = ip_gma_set(s, s->ret_ip_gma_bb);
		s->buf_addr_type = s->saved_buf_addr_type;
	}else{
		s->buf_type = RING_BUFFER_INSTRUCTION;
		s->buf_addr_type = GTT_BUFFER;
		rc = ip_gma_set(s, s->ret_ip_gma_ring);
	}

	return rc;
}

/* TODO
 *
 * The mi_display_flip handler below is just a workaround. The completed
 * handling is under discussion. The current approach is to NOOP the
 * MI_DISPLAY_FLIP command and then do pre-emulation. The pre-emulation
 * cannot exactly emulate command's behavior since it happens before
 * the command is issued. Consider the following two cases: one is that
 * right after the command-scan, display switch happens. Another case
 * is that commands inside ring buffer has some dependences.
 *
 * The interrupt is another consideration. mi_display_flip can trigger
 * interrupt for completion. VM's gfx driver may rely on that. Whether
 * we should inject virtual interrupt and when is the right time.
 *
 * The user space could resubmit ring/batch buffer with partially updated
 * MI_DISPLAY_FLIP. So special handling is needed in command parser for
 * such scenario.
 *
 * And we did not update HW state for the display flip.
 *
 */
#define PLANE_SELECT_SHIFT	19
#define PLANE_SELECT_MASK	(0x7 << PLANE_SELECT_SHIFT)
#define SURF_MASK		0xFFFFF000
#define PITCH_MASK		0x0000FFC0
#define TILE_PARA_SHIFT		0x0
#define TILE_PARA_MASK		0x1
/* Primary plane and sprite plane has the same tile shift in control reg */
#define PLANE_TILE_SHIFT	_PRI_PLANE_TILE_SHIFT
#define PLANE_TILE_MASK		(0x1 << PLANE_TILE_SHIFT)
#define FLIP_TYPE_MASK		0x3

#define DISPLAY_FLIP_PLANE_A  0x0
#define DISPLAY_FLIP_PLANE_B  0x1
#define DISPLAY_FLIP_SPRITE_A  0x2
#define DISPLAY_FLIP_SPRITE_B  0x3
#define DISPLAY_FLIP_PLANE_C  0x4
#define DISPLAY_FLIP_SPRITE_C  0x5


/* The NOOP for MI_DISPLAY_FLIP has below information stored in NOOP_ID:
 *
 *	bit 21 - bit 16 is 0x14, opcode of MI_DISPLAY_FLIP;
 *	bit 10 - bit 8  is plane select;
 *	bit 7  - bit 0  is the cmd length
 */
#define PLANE_INFO_SHIFT	8
#define PLANE_INFO_MASK		(0x7 << PLANE_INFO_SHIFT)

static bool display_flip_decode_plane_info(uint32_t  plane_code, enum vgt_pipe *pipe, enum vgt_plane_type *plane )
{
	switch (plane_code) {
		case DISPLAY_FLIP_PLANE_A:
			*pipe = PIPE_A;
			*plane = PRIMARY_PLANE;
			break;
		case DISPLAY_FLIP_PLANE_B:
			*pipe = PIPE_B;
			*plane = PRIMARY_PLANE;
			break;
		case DISPLAY_FLIP_SPRITE_A:
			*pipe = PIPE_A;
			*plane = SPRITE_PLANE;
			break;
		case DISPLAY_FLIP_SPRITE_B:
			*pipe = PIPE_B;
			*plane = SPRITE_PLANE;
			break;
		case DISPLAY_FLIP_PLANE_C:
			*pipe = PIPE_C;
			*plane = PRIMARY_PLANE;
			break;
		case DISPLAY_FLIP_SPRITE_C:
			*pipe = PIPE_C;
			*plane = SPRITE_PLANE;
			break;
		default:
			return false;
	}

	return true;

}

static bool display_flip_encode_plane_info(enum vgt_pipe pipe, enum vgt_plane_type plane, uint32_t * plane_code)
{

	if(pipe == PIPE_A && plane == PRIMARY_PLANE)
	{
		*plane_code = DISPLAY_FLIP_PLANE_A;
	}
	else if (pipe == PIPE_B && plane == PRIMARY_PLANE)
	{
		*plane_code = DISPLAY_FLIP_PLANE_B;
	}
	else if (pipe == PIPE_A && plane == SPRITE_PLANE)
	{
		*plane_code = DISPLAY_FLIP_SPRITE_A;
	}
	else if (pipe == PIPE_B && plane == SPRITE_PLANE)
	{
		*plane_code = DISPLAY_FLIP_SPRITE_B;
	}
	else if (pipe == PIPE_C && plane == PRIMARY_PLANE)
	{
		*plane_code = DISPLAY_FLIP_PLANE_C;
	}
	else if (pipe == PIPE_C && plane == SPRITE_PLANE)
	{
		*plane_code = DISPLAY_FLIP_SPRITE_C;
	}
	else
	{
		return false;
	}

	return true;

}

#define GET_INFO_FOR_FLIP(pipe, plane, 					\
			ctrl_reg, surf_reg, stride_reg, stride_mask)	\
do{									\
	if (plane == PRIMARY_PLANE) {					\
		ctrl_reg = VGT_DSPCNTR(pipe);				\
		surf_reg = VGT_DSPSURF(pipe);				\
		stride_reg = VGT_DSPSTRIDE(pipe);			\
		stride_mask = _PRI_PLANE_STRIDE_MASK;			\
	} else {							\
		ASSERT (plane == SPRITE_PLANE);				\
		ctrl_reg = VGT_SPRCTL(pipe);				\
		surf_reg = VGT_SPRSURF(pipe);				\
		stride_reg = VGT_SPRSTRIDE(pipe);			\
		stride_mask = _SPRITE_STRIDE_MASK;			\
	}								\
}while(0);

static bool vgt_flip_parameter_check(struct parser_exec_state *s,
				uint32_t plane_code,
				uint32_t stride_val,
				uint32_t surf_val)
{
	struct pgt_device *pdev = s->vgt->pdev;
	enum vgt_pipe pipe = I915_MAX_PIPES;
	enum vgt_plane_type plane = MAX_PLANE;
	uint32_t surf_reg, ctrl_reg;
	uint32_t stride_reg, stride_mask, phys_stride;
	uint32_t tile_para, tile_in_ctrl;
	bool async_flip;

	if (!display_flip_decode_plane_info(plane_code, &pipe, &plane))
		return false;

	GET_INFO_FOR_FLIP(pipe, plane,
			ctrl_reg, surf_reg, stride_reg, stride_mask);

	async_flip = ((surf_val & FLIP_TYPE_MASK) == 0x1);
	tile_para = ((stride_val & TILE_PARA_MASK) >> TILE_PARA_SHIFT);
	tile_in_ctrl = (__vreg(s->vgt, ctrl_reg) & PLANE_TILE_MASK)
				>> PLANE_TILE_SHIFT;

	phys_stride = __vreg(current_display_owner(pdev), stride_reg);
	if ((s->vgt != current_display_owner(pdev)) && !enable_panel_fitting &&
		(plane == PRIMARY_PLANE) &&
		((stride_val & PITCH_MASK) !=
			(phys_stride & stride_mask))) {
		vgt_dbg(VGT_DBG_CMD, "Stride value may not match display timing! "
			"MI_DISPLAY_FLIP will be ignored!\n");
		return false;
	}

	if ((__vreg(s->vgt, stride_reg) & stride_mask)
		!= (stride_val & PITCH_MASK)) {

		if (async_flip) {
			vgt_warn("Cannot change stride in async flip!\n");
			return false;
		}
	}

	if (tile_para != tile_in_ctrl) {

		if (async_flip) {
			vgt_warn("Cannot change tiling in async flip!\n");
			return false;
		}
	}

	return true;
}

static int vgt_handle_mi_display_flip(struct parser_exec_state *s, bool resubmitted)
{
	uint32_t surf_reg, surf_val, ctrl_reg;
	uint32_t stride_reg, stride_val, stride_mask;
	uint32_t tile_para;
	uint32_t opcode, plane_code, real_plane_code;
	enum vgt_pipe pipe;
	enum vgt_pipe real_pipe;
	enum vgt_plane_type plane;
	int i, length, rc = 0;
	struct fb_notify_msg msg;
	uint32_t value;

	opcode = cmd_val(s, 0);
	stride_val = cmd_val(s, 1);
	surf_val = cmd_val(s, 2);

	if (resubmitted) {
		plane_code = (opcode & PLANE_INFO_MASK) >> PLANE_INFO_SHIFT;
		length = opcode & CMD_LENGTH_MASK;
	} else {
		plane_code = (opcode & PLANE_SELECT_MASK) >> PLANE_SELECT_SHIFT;
		length = cmd_length(s);
	}


	if(!display_flip_decode_plane_info(plane_code, &pipe, &plane)){
		goto wrong_command;
	}

	real_pipe = s->vgt->pipe_mapping[pipe];

	if (length == 4) {
		vgt_warn("Page flip of Stereo 3D is not supported!\n");
		goto wrong_command;
	} else if (length != 3) {
		vgt_warn("Flip length not equal to 3, ignore handling flipping");
		goto wrong_command;
	}

	if ((pipe == I915_MAX_PIPES) || (plane == MAX_PLANE)) {
		vgt_warn("Invalid pipe/plane in MI_DISPLAY_FLIP!\n");
		goto wrong_command;
	}

	if (!resubmitted) {
		if (!vgt_flip_parameter_check(s, plane_code, stride_val, surf_val)) {
			goto wrong_command;
		}

		GET_INFO_FOR_FLIP(pipe, plane,
			ctrl_reg, surf_reg, stride_reg, stride_mask);
		tile_para = ((stride_val & TILE_PARA_MASK) >> TILE_PARA_SHIFT);

		__vreg(s->vgt, stride_reg) = (stride_val & stride_mask) |
				(__vreg(s->vgt, stride_reg) & (~stride_mask));
		__vreg(s->vgt, ctrl_reg) = (tile_para << PLANE_TILE_SHIFT) |
				(__vreg(s->vgt, ctrl_reg) & (~PLANE_TILE_MASK));
		__vreg(s->vgt, surf_reg) = (surf_val & SURF_MASK) |
				(__vreg(s->vgt, surf_reg) & (~SURF_MASK));
		__sreg(s->vgt, stride_reg) = __vreg(s->vgt, stride_reg);
		__sreg(s->vgt, ctrl_reg) = __vreg(s->vgt, ctrl_reg);
		__sreg(s->vgt, surf_reg) = __vreg(s->vgt, surf_reg);
	}

	msg.vm_id = s->vgt->vm_id;
	msg.pipe_id = pipe;
	msg.plane_id = plane;
	vgt_fb_notifier_call_chain(FB_DISPLAY_FLIP, &msg);

	if ((s->vgt == current_foreground_vm(s->vgt->pdev)) && !resubmitted) {
		if(!display_flip_encode_plane_info(real_pipe, plane, &real_plane_code))
		{
			goto wrong_command;
		}

		value = cmd_val(s, 0);
		add_patch_entry(s, cmd_ptr(s, 0), (value & ~PLANE_SELECT_MASK) |  (real_plane_code << PLANE_SELECT_SHIFT));
		return 0;
	}

	vgt_dbg(VGT_DBG_CMD, "VM %d: mi_display_flip to be ignored\n",
		s->vgt->vm_id);

	for (i = 1; i < length; i ++) {
		rc |= add_patch_entry(s, cmd_ptr(s, i), MI_NOOP |
			(OP_MI_DISPLAY_FLIP << VGT_NOOP_ID_CMD_SHIFT));
	}

	rc |= add_patch_entry(s, cmd_ptr(s,0), MI_NOOP |
			(OP_MI_DISPLAY_FLIP << VGT_NOOP_ID_CMD_SHIFT) |
			(plane_code << PLANE_INFO_SHIFT) |
			(length & CMD_LENGTH_MASK));

	vgt_inject_flip_done(s->vgt, pipe);

	return rc;

wrong_command:
	for (i = 0; i < length; i ++)
		rc |= add_patch_entry(s, cmd_ptr(s, i), MI_NOOP);
	return rc;
}

static int vgt_cmd_handler_mi_display_flip(struct parser_exec_state *s)
{
	return vgt_handle_mi_display_flip(s, false);
}

static bool is_wait_for_flip_pending(uint32_t cmd)
{
	return cmd & (MI_WAIT_FOR_PLANE_A_FLIP_PENDING |
		MI_WAIT_FOR_PLANE_B_FLIP_PENDING |
		MI_WAIT_FOR_PLANE_C_FLIP_PENDING |
		MI_WAIT_FOR_SPRITE_A_FLIP_PENDING |
		MI_WAIT_FOR_SPRITE_B_FLIP_PENDING |
		MI_WAIT_FOR_SPRITE_C_FLIP_PENDING);
}

static int vgt_handle_mi_wait_for_event(struct parser_exec_state *s)
{
	int rc = 0;
	enum vgt_pipe virtual_pipe = I915_MAX_PIPES;
	enum vgt_pipe real_pipe = I915_MAX_PIPES;
	uint32_t cmd = cmd_val(s, 0);
	uint32_t new_cmd = cmd;
	enum vgt_plane_type plane_type = MAX_PLANE;

	if (!is_wait_for_flip_pending(cmd)) {
		return rc;
	}

	if (s->vgt != current_foreground_vm(s->vgt->pdev)) {
		rc |= add_patch_entry(s, cmd_ptr(s, 0), MI_NOOP);
		vgt_dbg(VGT_DBG_CMD, "VM %d: mi_wait_for_event to be ignored\n", s->vgt->vm_id);
		return rc;
	}

	if (cmd & MI_WAIT_FOR_PLANE_A_FLIP_PENDING) {
		virtual_pipe = PIPE_A;
		plane_type = PRIMARY_PLANE;
		new_cmd &= ~MI_WAIT_FOR_PLANE_A_FLIP_PENDING;
	} else if (cmd & MI_WAIT_FOR_PLANE_B_FLIP_PENDING) {
		virtual_pipe = PIPE_B;
		plane_type = PRIMARY_PLANE;
		new_cmd &= ~MI_WAIT_FOR_PLANE_B_FLIP_PENDING;
	} else if (cmd & MI_WAIT_FOR_PLANE_C_FLIP_PENDING){
		virtual_pipe = PIPE_C;
		plane_type = PRIMARY_PLANE;
		new_cmd &= ~MI_WAIT_FOR_PLANE_C_FLIP_PENDING;
	} else if (cmd & MI_WAIT_FOR_SPRITE_A_FLIP_PENDING) {
		virtual_pipe = PIPE_A;
		plane_type = SPRITE_PLANE;
		new_cmd &= ~MI_WAIT_FOR_SPRITE_A_FLIP_PENDING;
	} else if (cmd & MI_WAIT_FOR_SPRITE_B_FLIP_PENDING) {
		virtual_pipe = PIPE_B;
		plane_type = SPRITE_PLANE;
		new_cmd &= ~MI_WAIT_FOR_SPRITE_B_FLIP_PENDING;
	} else  if(cmd & MI_WAIT_FOR_SPRITE_C_FLIP_PENDING){
		virtual_pipe = PIPE_C;
		plane_type = SPRITE_PLANE;
		new_cmd &= ~MI_WAIT_FOR_SPRITE_C_FLIP_PENDING;
	} else {
		ASSERT(0);
	}

	real_pipe = s->vgt->pipe_mapping[virtual_pipe];

	if (real_pipe == PIPE_A && plane_type == PRIMARY_PLANE) {
		new_cmd |= MI_WAIT_FOR_PLANE_A_FLIP_PENDING;
	} else if (real_pipe == PIPE_B && plane_type == PRIMARY_PLANE) {
		new_cmd |= MI_WAIT_FOR_PLANE_B_FLIP_PENDING;
	} else if (real_pipe == PIPE_C && plane_type == PRIMARY_PLANE) {
		new_cmd |= MI_WAIT_FOR_PLANE_C_FLIP_PENDING;
	} else if (real_pipe == PIPE_A && plane_type == SPRITE_PLANE) {
		new_cmd |= MI_WAIT_FOR_SPRITE_A_FLIP_PENDING;
	} else if (real_pipe == PIPE_B && plane_type == SPRITE_PLANE) {
		new_cmd |= MI_WAIT_FOR_SPRITE_B_FLIP_PENDING;
	} else if (real_pipe == PIPE_C && plane_type == SPRITE_PLANE) {
		new_cmd |= MI_WAIT_FOR_SPRITE_C_FLIP_PENDING;
	} else {
		rc = add_patch_entry(s, cmd_ptr(s, 0), MI_NOOP);
		return rc;
	}
	rc = add_patch_entry(s, cmd_ptr(s, 0), new_cmd);
	return rc;
}


#define USE_GLOBAL_GTT_MASK (1U << 22)
static int vgt_cmd_handler_mi_update_gtt(struct parser_exec_state *s)
{
	uint32_t entry_num, *entry;
	int rc, i;

	/*TODO: remove this assert when PPGTT support is added */
	ASSERT(cmd_val(s,0) & USE_GLOBAL_GTT_MASK);

	address_fixup(s, 1);

	entry_num = cmd_length(s) - 2; /* GTT items begin from the 3rd dword */
	//entry = v_aperture(s->vgt->pdev, cmd_val(s,1));
	entry = cmd_ptr(s, 2);
	for (i=0; i<entry_num; i++){
		vgt_dbg(VGT_DBG_CMD, "vgt: update GTT entry %d\n", i);
		/*TODO: optimize by batch g2m translation*/
		rc = gtt_p2m(s->vgt, entry[i], &entry[i] );
		if (rc < 0){
			/* TODO: how to handle the invalide guest value */
		}
	}

	return 0;
}

static int vgt_cmd_handler_mi_flush_dw(struct parser_exec_state* s)
{
	int i, len;

	/* Check post-sync bit */
	if ( (cmd_val(s,0) >> 14) & 0x3)
		address_fixup(s, 1);

	len = cmd_length(s);
	for (i=2; i<len; i++)
		address_fixup(s, i);

	return 0;
}

static void addr_type_update_snb(struct parser_exec_state* s)
{
	if ( (s->buf_type == RING_BUFFER_INSTRUCTION) &&
			(s->vgt->rb[s->ring_id].has_ppgtt_mode_enabled) &&
			(BATCH_BUFFER_ADR_SPACE_BIT(cmd_val(s,0)) == 1)
	   )
	{
		s->buf_addr_type = PPGTT_BUFFER;
	}
}

static int vgt_cmd_handler_mi_batch_buffer_start(struct parser_exec_state *s)
{
	int rc=0;
	bool second_level;

	if (s->buf_type == BATCH_BUFFER_2ND_LEVEL){
		vgt_err("MI_BATCH_BUFFER_START not allowd in 2nd level batch buffer\n");
		return -EINVAL;
	}

	second_level = BATCH_BUFFER_2ND_LEVEL_BIT(cmd_val(s,0)) == 1;
	if (second_level && (s->buf_type != BATCH_BUFFER_INSTRUCTION)){
		vgt_err("Jumping to 2nd level batch buffer from ring buffer is not allowd\n");
		return -EINVAL;
	}

	s->saved_buf_addr_type = s->buf_addr_type;

	/* FIXME: add IVB/HSW code */
	addr_type_update_snb(s);

	if (s->buf_type == RING_BUFFER_INSTRUCTION){
		s->ret_ip_gma_ring = s->ip_gma + 2*sizeof(uint32_t);
		s->buf_type = BATCH_BUFFER_INSTRUCTION;
	} else if (second_level){
		s->buf_type = BATCH_BUFFER_2ND_LEVEL;
		s->ret_ip_gma_bb = s->ip_gma + 2*sizeof(uint32_t);
	 }

	klog_printk("MI_BATCH_BUFFER_START: Addr=%x ClearCommandBufferEnable=%d\n",
			cmd_val(s,1),  (cmd_val(s,0)>>11) & 1);

	address_fixup(s, 1);

	rc = ip_gma_set(s, cmd_val(s,1) & BATCH_BUFFER_ADDR_MASK);

	if (rc < 0){
		vgt_warn("invalid batch buffer addr, so skip scanning it\n");
	}

	return rc;
}

static int vgt_cmd_handler_3dstate_vertex_buffers(struct parser_exec_state *s)
{
	int length, i;

	length = cmd_length(s);

	for (i=1; i < length; i = i+4){
		address_fixup(s,i + 1);
		address_fixup(s,i + 2);
	}

	return 0;
}

static int vgt_cmd_handler_3dstate_index_buffer(struct parser_exec_state *s)
{
	address_fixup(s,1);

	if (cmd_val(s,2) != 0)
		address_fixup(s,2);

	return 0;
}

static unsigned int constant_buffer_address_offset_disable(struct parser_exec_state *s)
{
	/* return the "CONSTANT_BUFFER Address Offset Disable" bit
	  in "INSTPM—Instruction Parser Mode Register"
	  0 - use as offset
	  1 - use as graphics address
	 */

	return __vreg(s->vgt,_REG_RCS_INSTPM) & INSTPM_CONS_BUF_ADDR_OFFSET_DIS;
}

static int vgt_cmd_handler_3dstate_constant_gs(struct parser_exec_state *s)
{
	if (constant_buffer_address_offset_disable(s) == 1){
		address_fixup(s,1);
	}
	address_fixup(s,2);
	address_fixup(s,3);
	address_fixup(s,4);

	return 0;
}

static int vgt_cmd_handler_3dstate_constant_ps(struct parser_exec_state *s)
{
	if (constant_buffer_address_offset_disable(s) == 1){
		address_fixup(s,1);
	}
	address_fixup(s,2);
	address_fixup(s,3);
	address_fixup(s,4);

	return 0;
}

static int vgt_cmd_handler_3dstate_constant_vs(struct parser_exec_state *s)
{
	if (constant_buffer_address_offset_disable(s) == 1){
		address_fixup(s,1);
	}
	address_fixup(s,2);
	address_fixup(s,3);
	address_fixup(s,4);

	return 0;
}

static int vgt_cmd_handler_state_base_address(struct parser_exec_state *s)
{
	address_fixup(s,1);
	address_fixup(s,2);
	address_fixup(s,3);
	address_fixup(s,4);
	address_fixup(s,5);
	/* Zero Bound is ignore */
	if (cmd_val(s,6) >> 12)
		address_fixup(s,6);
	if (cmd_val(s,7) >> 12)
		address_fixup(s,7);
	if (cmd_val(s,8) >> 12)
		address_fixup(s,8);
	if (cmd_val(s,9) >> 12)
		address_fixup(s,9);
	return 0;
}

static inline int base_and_upper_addr_fix(struct parser_exec_state *s)
{
	address_fixup(s,1);
	/* Zero Bound is ignore */
	if (cmd_val(s,2) >> 12)
		address_fixup(s,2);
	return 0;
}

static int vgt_cmd_handler_3dstate_binding_table_pool_alloc(struct parser_exec_state *s)
{
	return base_and_upper_addr_fix(s);
}

static int vgt_cmd_handler_3dstate_gather_pool_alloc(struct parser_exec_state *s)
{
	return base_and_upper_addr_fix(s);
}

static int vgt_cmd_handler_3dstate_dx9_constant_buffer_pool_alloc(struct parser_exec_state *s)
{
	return base_and_upper_addr_fix(s);
}

static int vgt_cmd_handler_op_3dstate_constant_hs(struct parser_exec_state *s)
{
	address_fixup(s, 3); /* TODO: check INSTPM<CONSTANT_BUFFER Address Offset Disable */
	address_fixup(s, 4);
	address_fixup(s, 5);
	address_fixup(s, 6);
	return 0;
}

static int vgt_cmd_handler_op_3dstate_constant_ds(struct parser_exec_state *s)
{
	address_fixup(s, 3); /* TODO: check INSTPM<CONSTANT_BUFFER Address Offset Disable */
	address_fixup(s, 4);
	address_fixup(s, 5);
	address_fixup(s, 6);
	return 0;
}

static int vgt_cmd_handler_mfx_pipe_buf_addr_state(struct parser_exec_state *s)
{
	int i;
	for (i=1; i<=23; i++){
		address_fixup(s, i);
	}
	return 0;
}

static int vgt_cmd_handler_mfx_ind_obj_base_addr_state(struct parser_exec_state *s)
{
	int i;
	for (i=1; i<=10; i++){
		address_fixup(s, i);
	}
	return 0;
}

static int vgt_cmd_handler_mfx_2_6_0_0(struct parser_exec_state *s)
{
	base_and_upper_addr_fix(s);
	address_fixup(s,2);
	return 0;
}

static int vgt_cmd_handler_mi_noop(struct parser_exec_state* s)
{
	unsigned int cmd;
	cmd = (cmd_val(s,0) & VGT_NOOP_ID_CMD_MASK) >> VGT_NOOP_ID_CMD_SHIFT;

	if (cmd) {
		if (cmd == OP_MI_DISPLAY_FLIP) {
			vgt_handle_mi_display_flip(s, true);
		} else {
			vgt_err("VM %d: Guest reuse cmd buffer that is not handled!\n",
					s->vgt->vm_id);
			parser_exec_state_dump(s);
		}
	}

	return 0;
}

static struct cmd_info cmd_info[] = {
	{"MI_NOOP", OP_MI_NOOP, F_LEN_CONST|F_POST_HANDLE, R_ALL, D_ALL, 0, 1, vgt_cmd_handler_mi_noop},

	{"MI_SET_PREDICATE", OP_MI_SET_PREDICATE, F_LEN_CONST, R_ALL, D_HSW_PLUS,
		0, 1, NULL},

	{"MI_USER_INTERRUPT", OP_MI_USER_INTERRUPT, F_LEN_CONST, R_ALL, D_ALL, 0, 1, NULL},

	{"MI_WAIT_FOR_EVENT", OP_MI_WAIT_FOR_EVENT, F_LEN_CONST | F_POST_HANDLE, R_RCS | R_BCS,
		D_ALL, 0, 1, vgt_handle_mi_wait_for_event},

	{"MI_FLUSH", OP_MI_FLUSH, F_LEN_CONST, R_ALL, D_ALL, 0, 1, NULL},

	{"MI_ARB_CHECK", OP_MI_ARB_CHECK, F_LEN_CONST, R_ALL, D_ALL, 0, 1, NULL},

	{"MI_RS_CONTROL", OP_MI_RS_CONTROL, F_LEN_CONST, R_RCS, D_HSW_PLUS, 0, 1, NULL},

	{"MI_REPORT_HEAD", OP_MI_REPORT_HEAD, F_LEN_CONST, R_ALL, D_ALL, 0, 1, NULL},

	{"MI_ARB_ON_OFF", OP_MI_ARB_ON_OFF, F_LEN_CONST, R_ALL, D_ALL, 0, 1, NULL},

	{"MI_URB_ATOMIC_ALLOC", OP_MI_URB_ATOMIC_ALLOC, F_LEN_CONST, R_RCS,
		D_HSW_PLUS, 0, 1, NULL},

	{"MI_BATCH_BUFFER_END", OP_MI_BATCH_BUFFER_END, F_IP_ADVANCE_CUSTOM|F_LEN_CONST,
		R_ALL, D_ALL, 0, 1, vgt_cmd_handler_mi_batch_buffer_end},

	{"MI_SUSPEND_FLUSH", OP_MI_SUSPEND_FLUSH, F_LEN_CONST, R_ALL, D_ALL, 0, 1, NULL},

	{"MI_PREDICATE", OP_MI_PREDICATE, F_LEN_CONST, R_RCS, D_IVB_PLUS, 0, 1, NULL},

	{"MI_TOPOLOGY_FILTER", OP_MI_TOPOLOGY_FILTER, F_LEN_CONST, R_ALL,
		D_IVB_PLUS, 0, 1, NULL},

	{"MI_SET_APPID", OP_MI_SET_APPID, F_LEN_CONST, R_ALL, D_IVB_PLUS, 0, 1, NULL},

	{"MI_RS_CONTEXT", OP_MI_RS_CONTEXT, F_LEN_CONST, R_RCS, D_HSW_PLUS, 0, 1, NULL},

	{"MI_DISPLAY_FLIP", OP_MI_DISPLAY_FLIP, F_LEN_VAR|F_POST_HANDLE, R_RCS | R_BCS,
		D_ALL, ADDR_FIX_1(2), 8, vgt_cmd_handler_mi_display_flip},

	{"MI_SEMAPHORE_MBOX", OP_MI_SEMAPHORE_MBOX, F_LEN_VAR, R_ALL, D_ALL, 0, 8, NULL },

	{"MI_SET_CONTEXT", OP_MI_SET_CONTEXT, F_LEN_VAR, R_ALL, D_ALL,
		ADDR_FIX_1(1), 8, vgt_cmd_handler_mi_set_context},

	{"MI_MATH", OP_MI_MATH, F_LEN_VAR, R_ALL, D_ALL, 0, 8, NULL},

	{"MI_URB_CLEAR", OP_MI_URB_CLEAR, F_LEN_VAR, R_RCS, D_ALL, 0, 8, NULL},

	{"MI_STORE_DATA_IMM", OP_MI_STORE_DATA_IMM, F_LEN_VAR, R_ALL, D_ALL,
		ADDR_FIX_1(2), 8, NULL},

	{"MI_STORE_DATA_INDEX", OP_MI_STORE_DATA_INDEX, F_LEN_VAR, R_ALL, D_ALL,
		0, 8, NULL},

	{"MI_LOAD_REGISTER_IMM", OP_MI_LOAD_REGISTER_IMM, F_LEN_VAR, R_ALL, D_ALL, 0, 8, vgt_cmd_handler_lri},

	{"MI_UPDATE_GTT", OP_MI_UPDATE_GTT, F_LEN_VAR, R_RCS, D_ALL,
		0, 8, vgt_cmd_handler_mi_update_gtt},

	{"MI_UPDATE_GTT", OP_MI_UPDATE_GTT, F_LEN_VAR, (R_VCS | R_BCS | R_VECS), D_ALL,
		0, 6, vgt_cmd_handler_mi_update_gtt},

	{"MI_STORE_REGISTER_MEM", OP_MI_STORE_REGISTER_MEM, F_LEN_VAR, R_ALL, D_ALL,
		ADDR_FIX_1(2), 8, vgt_cmd_handler_srm},

	{"MI_FLUSH_DW", OP_MI_FLUSH_DW, F_LEN_VAR, R_ALL, D_ALL,
		0, 6, vgt_cmd_handler_mi_flush_dw},

	{"MI_CLFLUSH", OP_MI_CLFLUSH, F_LEN_VAR, R_ALL, D_ALL,
		ADDR_FIX_1(1), 8, NULL},

	{"MI_REPORT_PERF_COUNT", OP_MI_REPORT_PERF_COUNT, F_LEN_VAR, R_ALL, D_ALL,
		ADDR_FIX_1(1), 6, NULL},

	{"MI_LOAD_REGISTER_MEM", OP_MI_LOAD_REGISTER_MEM, F_LEN_VAR, R_ALL, D_GEN7PLUS,
		ADDR_FIX_1(2), 8, vgt_cmd_handler_lrm},

	{"MI_LOAD_REGISTER_REG", OP_MI_LOAD_REGISTER_REG, F_LEN_VAR, R_ALL, D_HSW_PLUS,
		0, 8, vgt_cmd_handler_lrr},

	{"MI_RS_STORE_DATA_IMM", OP_MI_RS_STORE_DATA_IMM, F_LEN_VAR, R_RCS, D_HSW_PLUS,
		0, 8, NULL},

	{"MI_LOAD_URB_MEM", OP_MI_LOAD_URB_MEM, F_LEN_VAR, R_RCS, D_HSW_PLUS,
		ADDR_FIX_1(2), 8, NULL},

	{"MI_STORE_URM_MEM", OP_MI_STORE_URM_MEM, F_LEN_VAR, R_RCS, D_HSW_PLUS,
		ADDR_FIX_1(2), 8, NULL},

	{"MI_BATCH_BUFFER_START", OP_MI_BATCH_BUFFER_START, F_IP_ADVANCE_CUSTOM|F_LEN_CONST,
		R_ALL, D_ALL, 0, 2, vgt_cmd_handler_mi_batch_buffer_start},

	{"MI_CONDITIONAL_BATCH_BUFFER_END", OP_MI_CONDITIONAL_BATCH_BUFFER_END,
		F_LEN_VAR, R_ALL, D_ALL, ADDR_FIX_1(2), 8, NULL},

	{"MI_LOAD_SCAN_LINES_INCL", OP_MI_LOAD_SCAN_LINES_INCL, F_LEN_CONST, R_RCS | R_BCS, D_HSW_PLUS,
		0, 2, NULL},

	{"XY_SETUP_BLT", OP_XY_SETUP_BLT, F_LEN_VAR, R_BCS, D_ALL,
		ADDR_FIX_2(4,7), 8, NULL},

	{"XY_SETUP_CLIP_BLT", OP_XY_SETUP_CLIP_BLT, F_LEN_VAR, R_BCS, D_ALL,
		0, 8, NULL},

	{"XY_SETUP_MONO_PATTERN_SL_BLT", OP_XY_SETUP_MONO_PATTERN_SL_BLT, F_LEN_VAR,
		R_BCS, D_ALL, ADDR_FIX_1(4), 8, NULL},

	{"XY_PIXEL_BLT", OP_XY_PIXEL_BLT, F_LEN_VAR, R_BCS, D_ALL, 0, 8, NULL},

	{"XY_SCANLINES_BLT", OP_XY_SCANLINES_BLT, F_LEN_VAR, R_BCS, D_ALL,
		0, 8, NULL},

	{"XY_TEXT_BLT", OP_XY_TEXT_BLT, F_LEN_VAR, R_BCS, D_ALL,
		ADDR_FIX_1(3), 8, NULL},

	{"XY_TEXT_IMMEDIATE_BLT", OP_XY_TEXT_IMMEDIATE_BLT, F_LEN_VAR, R_BCS,
		D_ALL, 0, 8, NULL},

	{"COLOR_BLT", OP_COLOR_BLT, F_LEN_VAR, R_BCS, D_ALL, ADDR_FIX_1(3), 5, NULL},

	{"SRC_COPY_BLT", OP_SRC_COPY_BLT, F_LEN_VAR, R_BCS, D_ALL,
		ADDR_FIX_1(3), 5, NULL},

	{"XY_COLOR_BLT", OP_XY_COLOR_BLT, F_LEN_VAR, R_BCS, D_ALL,
		ADDR_FIX_1(4), 8, NULL},

	{"XY_PAT_BLT", OP_XY_PAT_BLT, F_LEN_VAR, R_BCS, D_ALL,
		ADDR_FIX_2(4,5), 8, NULL},

	{"XY_MONO_PAT_BLT", OP_XY_MONO_PAT_BLT, F_LEN_VAR, R_BCS, D_ALL,
		ADDR_FIX_2(4,5), 8, NULL},

	{"XY_SRC_COPY_BLT", OP_XY_SRC_COPY_BLT, F_LEN_VAR, R_BCS, D_ALL,
		ADDR_FIX_2(4,7), 8, NULL},

	{"XY_MONO_SRC_COPY_BLT", OP_XY_MONO_SRC_COPY_BLT, F_LEN_VAR, R_BCS,
		D_ALL, ADDR_FIX_2(4,5), 8, NULL},

	{"XY_FULL_BLT", OP_XY_FULL_BLT, F_LEN_VAR, R_BCS, D_ALL, 0, 8, NULL},

	{"XY_FULL_MONO_SRC_BLT", OP_XY_FULL_MONO_SRC_BLT, F_LEN_VAR, R_BCS, D_ALL,
		ADDR_FIX_3(4,5,8), 8, NULL},

	{"XY_FULL_MONO_PATTERN_BLT", OP_XY_FULL_MONO_PATTERN_BLT, F_LEN_VAR,
		R_BCS, D_ALL, ADDR_FIX_2(4,7), 8, NULL},

	{"XY_FULL_MONO_PATTERN_MONO_SRC_BLT", OP_XY_FULL_MONO_PATTERN_MONO_SRC_BLT,
		F_LEN_VAR, R_BCS, D_ALL, ADDR_FIX_2(4,5), 8, NULL},

	{"XY_MONO_PAT_FIXED_BLT", OP_XY_MONO_PAT_FIXED_BLT, F_LEN_VAR, R_BCS, D_ALL,
		ADDR_FIX_1(4), 8, NULL},

	{"XY_MONO_SRC_COPY_IMMEDIATE_BLT", OP_XY_MONO_SRC_COPY_IMMEDIATE_BLT,
		F_LEN_VAR, R_BCS, D_ALL, ADDR_FIX_1(4), 8, NULL},

	{"XY_PAT_BLT_IMMEDIATE", OP_XY_PAT_BLT_IMMEDIATE, F_LEN_VAR, R_BCS,
		D_ALL, ADDR_FIX_1(4), 8, NULL},

	{"XY_SRC_COPY_CHROMA_BLT", OP_XY_SRC_COPY_CHROMA_BLT, F_LEN_VAR, R_BCS,
		D_ALL, ADDR_FIX_2(4,7), 8, NULL},

	{"XY_FULL_IMMEDIATE_PATTERN_BLT", OP_XY_FULL_IMMEDIATE_PATTERN_BLT,
		F_LEN_VAR, R_BCS, D_ALL, ADDR_FIX_2(4,7), 8, NULL},

	{"XY_FULL_MONO_SRC_IMMEDIATE_PATTERN_BLT", OP_XY_FULL_MONO_SRC_IMMEDIATE_PATTERN_BLT,
		F_LEN_VAR, R_BCS, D_ALL, ADDR_FIX_2(4,5), 8, NULL},

	{"XY_PAT_CHROMA_BLT", OP_XY_PAT_CHROMA_BLT, F_LEN_VAR, R_BCS, D_ALL,
		ADDR_FIX_2(4,5), 8, NULL},

	{"XY_PAT_CHROMA_BLT_IMMEDIATE", OP_XY_PAT_CHROMA_BLT_IMMEDIATE, F_LEN_VAR,
		R_BCS, D_ALL, ADDR_FIX_1(4), 8, NULL},

	{"3DSTATE_BINDING_TABLE_POINTERS", OP_3DSTATE_BINDING_TABLE_POINTERS,
		F_LEN_VAR, R_RCS, D_SNB, 0, 8, NULL},

	{"3DSTATE_VIEWPORT_STATE_POINTERS_SF_CLIP", OP_3DSTATE_VIEWPORT_STATE_POINTERS_SF_CLIP,
		F_LEN_VAR, R_RCS, D_GEN7PLUS, 0, 8, NULL},

	{"3DSTATE_VIEWPORT_STATE_POINTERS_CC", OP_3DSTATE_VIEWPORT_STATE_POINTERS_CC,
		F_LEN_VAR, R_RCS, D_GEN7PLUS, 0, 8, NULL},

	{"3DSTATE_BLEND_STATE_POINTERS", OP_3DSTATE_BLEND_STATE_POINTERS,
		F_LEN_VAR, R_RCS, D_GEN7PLUS, 0, 8, NULL},

	{"3DSTATE_DEPTH_STENCIL_STATE_POINTERS", OP_3DSTATE_DEPTH_STENCIL_STATE_POINTERS,
		F_LEN_VAR, R_RCS, D_GEN7PLUS, 0, 8, NULL},

	{"3DSTATE_BINDING_TABLE_POINTERS_VS", OP_3DSTATE_BINDING_TABLE_POINTERS_VS,
		F_LEN_VAR, R_RCS, D_GEN7PLUS, 0, 8, NULL},

	{"3DSTATE_BINDING_TABLE_POINTERS_HS", OP_3DSTATE_BINDING_TABLE_POINTERS_HS,
		F_LEN_VAR, R_RCS, D_GEN7PLUS, 0, 8, NULL},

	{"3DSTATE_BINDING_TABLE_POINTERS_DS", OP_3DSTATE_BINDING_TABLE_POINTERS_DS,
		F_LEN_VAR, R_RCS, D_GEN7PLUS, 0, 8, NULL},

	{"3DSTATE_BINDING_TABLE_POINTERS_GS", OP_3DSTATE_BINDING_TABLE_POINTERS_GS,
		F_LEN_VAR, R_RCS, D_GEN7PLUS, 0, 8, NULL},

	{"3DSTATE_BINDING_TABLE_POINTERS_PS", OP_3DSTATE_BINDING_TABLE_POINTERS_PS,
		F_LEN_VAR, R_RCS, D_GEN7PLUS, 0, 8, NULL},

	{"3DSTATE_SAMPLER_STATE_POINTERS_VS", OP_3DSTATE_SAMPLER_STATE_POINTERS_VS,
		F_LEN_VAR, R_RCS, D_GEN7PLUS, 0, 8, NULL},

	{"3DSTATE_SAMPLER_STATE_POINTERS_HS", OP_3DSTATE_SAMPLER_STATE_POINTERS_HS,
		F_LEN_VAR, R_RCS, D_GEN7PLUS, 0, 8, NULL},

	{"3DSTATE_SAMPLER_STATE_POINTERS_DS", OP_3DSTATE_SAMPLER_STATE_POINTERS_DS,
		F_LEN_VAR, R_RCS, D_GEN7PLUS, 0, 8, NULL},

	{"3DSTATE_SAMPLER_STATE_POINTERS_GS", OP_3DSTATE_SAMPLER_STATE_POINTERS_GS,
		F_LEN_VAR, R_RCS, D_GEN7PLUS, 0, 8, NULL},

	{"3DSTATE_SAMPLER_STATE_POINTERS_PS", OP_3DSTATE_SAMPLER_STATE_POINTERS_PS,
		F_LEN_VAR, R_RCS, D_GEN7PLUS, 0, 8, NULL},

	{"3DSTATE_URB_VS", OP_3DSTATE_URB_VS, F_LEN_VAR, R_RCS, D_GEN7PLUS,
		0, 8, NULL},

	{"3DSTATE_URB_HS", OP_3DSTATE_URB_HS, F_LEN_VAR, R_RCS, D_GEN7PLUS,
		0, 8, NULL},

	{"3DSTATE_URB_DS", OP_3DSTATE_URB_DS, F_LEN_VAR, R_RCS, D_GEN7PLUS,
		0, 8, NULL},

	{"3DSTATE_URB_GS", OP_3DSTATE_URB_GS, F_LEN_VAR, R_RCS, D_GEN7PLUS,
		0, 8, NULL},

	{"3DSTATE_GATHER_CONSTANT_VS", OP_3DSTATE_GATHER_CONSTANT_VS,
		F_LEN_VAR, R_RCS, D_HSW_PLUS, 0, 8, NULL},

	{"3DSTATE_GATHER_CONSTANT_GS", OP_3DSTATE_GATHER_CONSTANT_GS,
		F_LEN_VAR, R_RCS, D_HSW_PLUS, 0, 8, NULL},

	{"3DSTATE_GATHER_CONSTANT_HS", OP_3DSTATE_GATHER_CONSTANT_HS,
		F_LEN_VAR, R_RCS, D_HSW_PLUS, 0, 8, NULL},

	{"3DSTATE_GATHER_CONSTANT_DS", OP_3DSTATE_GATHER_CONSTANT_DS,
		F_LEN_VAR, R_RCS, D_HSW_PLUS, 0, 8, NULL},

	{"3DSTATE_GATHER_CONSTANT_PS", OP_3DSTATE_GATHER_CONSTANT_PS,
		F_LEN_VAR, R_RCS, D_HSW_PLUS, 0, 8, NULL},

	{"3DSTATE_DX9_CONSTANTF_VS", OP_3DSTATE_DX9_CONSTANTF_VS,
		F_LEN_VAR, R_RCS, D_HSW_PLUS, 0, 11, NULL},

	{"3DSTATE_DX9_CONSTANTF_PS", OP_3DSTATE_DX9_CONSTANTF_PS,
		F_LEN_VAR, R_RCS, D_HSW_PLUS, 0, 11, NULL},

	{"3DSTATE_DX9_CONSTANTI_VS", OP_3DSTATE_DX9_CONSTANTI_VS,
		F_LEN_VAR, R_RCS, D_HSW_PLUS, 0, 8, NULL},

	{"3DSTATE_DX9_CONSTANTI_PS", OP_3DSTATE_DX9_CONSTANTI_PS,
		F_LEN_VAR, R_RCS, D_HSW_PLUS, 0, 8, NULL},

	{"3DSTATE_DX9_CONSTANTB_VS", OP_3DSTATE_DX9_CONSTANTB_VS,
		F_LEN_VAR, R_RCS, D_HSW_PLUS, 0, 8, NULL},

	{"3DSTATE_DX9_CONSTANTB_PS", OP_3DSTATE_DX9_CONSTANTB_PS,
		F_LEN_VAR, R_RCS, D_HSW_PLUS, 0, 8, NULL},

	{"3DSTATE_DX9_LOCAL_VALID_VS", OP_3DSTATE_DX9_LOCAL_VALID_VS,
		F_LEN_VAR, R_RCS, D_HSW_PLUS, 0, 8, NULL},

	{"3DSTATE_DX9_LOCAL_VALID_PS", OP_3DSTATE_DX9_LOCAL_VALID_PS,
		F_LEN_VAR, R_RCS, D_HSW_PLUS, 0, 8, NULL},

	{"3DSTATE_DX9_GENERATE_ACTIVE_VS", OP_3DSTATE_DX9_GENERATE_ACTIVE_VS,
		F_LEN_VAR, R_RCS, D_HSW_PLUS, 0, 8, NULL},

	{"3DSTATE_DX9_GENERATE_ACTIVE_PS", OP_3DSTATE_DX9_GENERATE_ACTIVE_PS,
		F_LEN_VAR, R_RCS, D_HSW_PLUS, 0, 8, NULL},

	{"3DSTATE_BINDING_TABLE_EDIT_VS", OP_3DSTATE_BINDING_TABLE_EDIT_VS,
		F_LEN_VAR, R_RCS, D_HSW_PLUS, 0, 9, NULL},

	{"3DSTATE_BINDING_TABLE_EDIT_GS", OP_3DSTATE_BINDING_TABLE_EDIT_GS,
		F_LEN_VAR, R_RCS, D_HSW_PLUS, 0, 9, NULL},

	{"3DSTATE_BINDING_TABLE_EDIT_HS", OP_3DSTATE_BINDING_TABLE_EDIT_HS,
		F_LEN_VAR, R_RCS, D_HSW_PLUS, 0, 9, NULL},

	{"3DSTATE_BINDING_TABLE_EDIT_DS", OP_3DSTATE_BINDING_TABLE_EDIT_DS,
		F_LEN_VAR, R_RCS, D_HSW_PLUS, 0, 9, NULL},

	{"3DSTATE_BINDING_TABLE_EDIT_PS", OP_3DSTATE_BINDING_TABLE_EDIT_PS,
		F_LEN_VAR, R_RCS, D_HSW_PLUS, 0, 9, NULL},

	{"3DSTATE_SAMPLER_STATE_POINTERS", OP_3DSTATE_SAMPLER_STATE_POINTERS,
		F_LEN_VAR, R_RCS, D_SNB, 0, 8, NULL},

	{"3DSTATE_URB", OP_3DSTATE_URB, F_LEN_VAR, R_RCS, D_SNB, 0, 8, NULL},

	{"3DSTATE_VERTEX_BUFFERS", OP_3DSTATE_VERTEX_BUFFERS, F_LEN_VAR, R_RCS,
		D_ALL, 0, 8, vgt_cmd_handler_3dstate_vertex_buffers},

	{"3DSTATE_VERTEX_ELEMENTS", OP_3DSTATE_VERTEX_ELEMENTS, F_LEN_VAR, R_RCS,
		D_ALL, 0, 8, NULL},

	{"3DSTATE_INDEX_BUFFER", OP_3DSTATE_INDEX_BUFFER, F_LEN_VAR, R_RCS,
		D_ALL, 0, 8, vgt_cmd_handler_3dstate_index_buffer},

	{"3DSTATE_VF_STATISTICS", OP_3DSTATE_VF_STATISTICS, F_LEN_CONST,
		R_RCS, D_ALL, 0, 1, NULL},

	{"3DSTATE_VF", OP_3DSTATE_VF, F_LEN_VAR, R_RCS, D_GEN75PLUS, 0, 8, NULL},

	{"3DSTATE_VIEWPORT_STATE_POINTERS", OP_3DSTATE_VIEWPORT_STATE_POINTERS,
		F_LEN_VAR, R_RCS, D_ALL, 0, 8, NULL},

	{"3DSTATE_CC_STATE_POINTERS", OP_3DSTATE_CC_STATE_POINTERS, F_LEN_VAR,
		R_RCS, D_ALL, 0, 8, NULL},

	{"3DSTATE_SCISSOR_STATE_POINTERS", OP_3DSTATE_SCISSOR_STATE_POINTERS,
		F_LEN_VAR, R_RCS, D_ALL, 0, 8, NULL},

	{"3DSTATE_GS", OP_3DSTATE_GS, F_LEN_VAR, R_RCS, D_ALL, 0, 8, NULL},

	{"3DSTATE_CLIP", OP_3DSTATE_CLIP, F_LEN_VAR, R_RCS, D_ALL, 0, 8, NULL},

	{"3DSTATE_WM", OP_3DSTATE_WM, F_LEN_VAR, R_RCS, D_ALL, 0, 8, NULL},

	{"3DSTATE_CONSTANT_GS", OP_3DSTATE_CONSTANT_GS, F_LEN_VAR, R_RCS,
		D_ALL, 0, 8, vgt_cmd_handler_3dstate_constant_gs},

	{"3DSTATE_CONSTANT_PS", OP_3DSTATE_CONSTANT_PS, F_LEN_VAR, R_RCS,
		D_ALL, 0, 8, vgt_cmd_handler_3dstate_constant_ps},

	{"3DSTATE_SAMPLE_MASK", OP_3DSTATE_SAMPLE_MASK, F_LEN_VAR, R_RCS,
		D_ALL, 0, 8, NULL},

	{"3DSTATE_CONSTANT_HS", OP_3DSTATE_CONSTANT_HS, F_LEN_VAR, R_RCS,
		D_GEN7PLUS, 0, 8, vgt_cmd_handler_op_3dstate_constant_hs},

	{"3DSTATE_CONSTANT_DS", OP_3DSTATE_CONSTANT_DS, F_LEN_VAR, R_RCS,
		D_GEN7PLUS, 0, 8, vgt_cmd_handler_op_3dstate_constant_ds},

	{"3DSTATE_HS", OP_3DSTATE_HS, F_LEN_VAR, R_RCS,	D_GEN7PLUS, 0, 8, NULL},

	{"3DSTATE_TE", OP_3DSTATE_TE, F_LEN_VAR, R_RCS,	D_GEN7PLUS, 0, 8, NULL},

	{"3DSTATE_DS", OP_3DSTATE_DS, F_LEN_VAR, R_RCS,	D_GEN7PLUS, 0, 8, NULL},

	{"3DSTATE_STREAMOUT", OP_3DSTATE_STREAMOUT, F_LEN_VAR, R_RCS,
		D_GEN7PLUS, 0, 8, NULL},

	{"3DSTATE_SBE", OP_3DSTATE_SBE, F_LEN_VAR, R_RCS, D_GEN7PLUS, 0, 8, NULL},

	{"3DSTATE_PS", OP_3DSTATE_PS, F_LEN_VAR, R_RCS, D_GEN7PLUS, 0, 8, NULL},

	{"3DSTATE_DRAWING_RECTANGLE", OP_3DSTATE_DRAWING_RECTANGLE, F_LEN_VAR,
		R_RCS, D_ALL, 0, 8, NULL},

	{"3DSTATE_SAMPLER_PALETTE_LOAD0", OP_3DSTATE_SAMPLER_PALETTE_LOAD0,
		F_LEN_VAR, R_RCS, D_ALL, 0, 8, NULL},

	{"3DSTATE_CHROMA_KEY", OP_3DSTATE_CHROMA_KEY, F_LEN_VAR, R_RCS, D_ALL,
		0, 8, NULL},

	{"3DSTATE_DEPTH_BUFFER", OP_3DSTATE_DEPTH_BUFFER, F_LEN_VAR, R_RCS,
		D_SNB, ADDR_FIX_1(2), 8, NULL},

	{"GEN7_3DSTATE_DEPTH_BUFFER", OP_GEN7_3DSTATE_DEPTH_BUFFER, F_LEN_VAR, R_RCS,
		D_GEN7PLUS, ADDR_FIX_1(2), 8, NULL},

	{"3DSTATE_POLY_STIPPLE_OFFSET", OP_3DSTATE_POLY_STIPPLE_OFFSET,
		F_LEN_VAR, R_RCS, D_ALL, 0, 8, NULL},

	{"3DSTATE_POLY_STIPPLE_PATTERN", OP_3DSTATE_POLY_STIPPLE_PATTERN,
		F_LEN_VAR, R_RCS, D_ALL, 0, 8, NULL},

	{"3DSTATE_LINE_STIPPLE", OP_3DSTATE_LINE_STIPPLE, F_LEN_VAR, R_RCS,
		D_ALL, 0, 8, NULL},

	{"3DSTATE_AA_LINE_PARAMS", OP_3DSTATE_AA_LINE_PARAMS, F_LEN_VAR, R_RCS,
		D_ALL, 0, 8, NULL},

	{"3DSTATE_GS_SVB_INDEX", OP_3DSTATE_GS_SVB_INDEX, F_LEN_VAR, R_RCS, D_ALL,
		0, 8, NULL},

	{"3DSTATE_SAMPLER_PALETTE_LOAD1", OP_3DSTATE_SAMPLER_PALETTE_LOAD1,
		F_LEN_VAR, R_RCS, D_ALL, 0, 8, NULL},

	{"3DSTATE_MULTISAMPLE", OP_3DSTATE_MULTISAMPLE, F_LEN_VAR, R_RCS, D_ALL,
		0, 8, NULL},

	{"3DSTATE_STENCIL_BUFFER", OP_3DSTATE_STENCIL_BUFFER, F_LEN_VAR, R_RCS,
		D_ALL, ADDR_FIX_1(2), 8, NULL},

	{"GEN7_3DSTATE_STENCIL_BUFFER", OP_GEN7_3DSTATE_STENCIL_BUFFER, F_LEN_VAR, R_RCS,
		D_GEN7PLUS, ADDR_FIX_1(2), 8, NULL},

	{"3DSTATE_HIER_DEPTH_BUFFER", OP_3DSTATE_HIER_DEPTH_BUFFER, F_LEN_VAR,
		R_RCS, D_SNB, ADDR_FIX_1(2), 8, NULL},

	{"GEN7_3DSTATE_HIER_DEPTH_BUFFER", OP_GEN7_3DSTATE_HIER_DEPTH_BUFFER, F_LEN_VAR,
		R_RCS, D_GEN7PLUS, ADDR_FIX_1(2), 8, NULL},

	{"3DSTATE_CLEAR_PARAMS", OP_3DSTATE_CLEAR_PARAMS, F_LEN_VAR, R_RCS, D_SNB,
		0, 8, NULL},

	{"GEN7_3DSTATE_CLEAR_PARAMS", OP_GEN7_3DSTATE_CLEAR_PARAMS, F_LEN_VAR,
		R_RCS, D_GEN7PLUS, 0, 8, NULL},

	{"3DSTATE_PUSH_CONSTANT_ALLOC_VS", OP_3DSTATE_PUSH_CONSTANT_ALLOC_VS,
		F_LEN_VAR, R_RCS, D_GEN7PLUS, 0, 8, NULL},

	{"3DSTATE_PUSH_CONSTANT_ALLOC_HS", OP_3DSTATE_PUSH_CONSTANT_ALLOC_HS,
		F_LEN_VAR, R_RCS, D_GEN7PLUS, 0, 8, NULL},

	{"3DSTATE_PUSH_CONSTANT_ALLOC_DS", OP_3DSTATE_PUSH_CONSTANT_ALLOC_DS,
		F_LEN_VAR, R_RCS, D_GEN7PLUS, 0, 8, NULL},

	{"3DSTATE_PUSH_CONSTANT_ALLOC_GS", OP_3DSTATE_PUSH_CONSTANT_ALLOC_GS,
		F_LEN_VAR, R_RCS, D_GEN7PLUS, 0, 8, NULL},

	{"3DSTATE_PUSH_CONSTANT_ALLOC_PS", OP_3DSTATE_PUSH_CONSTANT_ALLOC_PS,
		F_LEN_VAR, R_RCS, D_GEN7PLUS, 0, 8, NULL},

	{"3DSTATE_MONOFILTER_SIZE", OP_3DSTATE_MONOFILTER_SIZE, F_LEN_VAR, R_RCS,
		D_ALL, 0, 8, NULL},

	{"3DSTATE_SO_DECL_LIST", OP_3DSTATE_SO_DECL_LIST, F_LEN_VAR, R_RCS, D_ALL,
		0, 9, NULL},

	{"3DSTATE_SO_BUFFER", OP_3DSTATE_SO_BUFFER, F_LEN_VAR, R_RCS, D_ALL,
		ADDR_FIX_2(2,3), 8, NULL},

	{"3DSTATE_BINDING_TABLE_POOL_ALLOC", OP_3DSTATE_BINDING_TABLE_POOL_ALLOC,
		F_LEN_VAR, R_RCS, D_GEN75PLUS, 0, 8, vgt_cmd_handler_3dstate_binding_table_pool_alloc},

	{"3DSTATE_GATHER_POOL_ALLOC", OP_3DSTATE_GATHER_POOL_ALLOC,
		F_LEN_VAR, R_RCS, D_GEN75PLUS, 0, 8, vgt_cmd_handler_3dstate_gather_pool_alloc},

	{"3DSTATE_DX9_CONSTANT_BUFFER_POOL_ALLOC", OP_3DSTATE_DX9_CONSTANT_BUFFER_POOL_ALLOC,
		F_LEN_VAR, R_RCS, D_GEN75PLUS, 0, 8, vgt_cmd_handler_3dstate_dx9_constant_buffer_pool_alloc},

	{"PIPE_CONTROL", OP_PIPE_CONTROL, F_LEN_VAR, R_RCS, D_ALL,
		ADDR_FIX_1(2), 8, vgt_cmd_handler_pipe_control},

	{"3DPRIMITIVE", OP_3DPRIMITIVE, F_LEN_VAR, R_RCS, D_ALL, 0, 8, NULL},

	{"PIPELINE_SELECT", OP_PIPELINE_SELECT, F_LEN_CONST, R_RCS, D_ALL, 0, 1, NULL},

	{"STATE_PREFETCH", OP_STATE_PREFETCH, F_LEN_VAR, R_RCS, D_ALL,
		ADDR_FIX_1(1), 8, NULL},

	{"STATE_SIP", OP_STATE_SIP, F_LEN_VAR, R_RCS, D_ALL, 0, 8, NULL},

	{"STATE_BASE_ADDRESS", OP_STATE_BASE_ADDRESS, F_LEN_VAR, R_RCS, D_ALL,
		0, 8, vgt_cmd_handler_state_base_address},

	{"OP_3D_MEDIA_0_1_4", OP_3D_MEDIA_0_1_4, F_LEN_VAR, R_RCS, D_HSW_PLUS,
		ADDR_FIX_1(1), 8, NULL},

	{"3DSTATE_VS", OP_3DSTATE_VS, F_LEN_VAR, R_RCS, D_ALL, 0, 8, NULL},

	{"3DSTATE_SF", OP_3DSTATE_SF, F_LEN_VAR, R_RCS, D_ALL, 0, 8, NULL},

	{"3DSTATE_CONSTANT_VS", OP_3DSTATE_CONSTANT_VS, F_LEN_VAR, R_RCS, D_ALL,
		0, 8, vgt_cmd_handler_3dstate_constant_vs},

	{"MEDIA_INTERFACE_DESCRIPTOR_LOAD", OP_MEDIA_INTERFACE_DESCRIPTOR_LOAD,
		F_LEN_VAR, R_RCS, D_ALL, 0, 16, NULL},

	{"MEDIA_GATEWAY_STATE", OP_MEDIA_GATEWAY_STATE, F_LEN_VAR, R_RCS, D_ALL,
		0, 16, NULL},

	{"MEDIA_STATE_FLUSH", OP_MEDIA_STATE_FLUSH, F_LEN_VAR, R_RCS, D_ALL,
		0, 16, NULL},

	{"MEDIA_OBJECT", OP_MEDIA_OBJECT, F_LEN_VAR, R_RCS, D_ALL, 0, 16, NULL},

	{"MEDIA_CURBE_LOAD", OP_MEDIA_CURBE_LOAD, F_LEN_VAR, R_RCS, D_ALL,
		0, 16, NULL},

	{"MEDIA_OBJECT_PRT", OP_MEDIA_OBJECT_PRT, F_LEN_VAR, R_RCS, D_ALL,
		0, 16, NULL},

	{"MEDIA_OBJECT_WALKER", OP_MEDIA_OBJECT_WALKER, F_LEN_VAR, R_RCS, D_ALL,
		0, 16, NULL},

	{"GPGPU_WALKER", OP_GPGPU_WALKER, F_LEN_VAR, R_RCS, D_ALL,
		0, 8, NULL},

	{"MEDIA_VFE_STATE", OP_MEDIA_VFE_STATE, F_LEN_VAR, R_RCS, D_ALL, 0, 16, NULL},

	{"3DSTATE_VF_STATISTICS_GM45", OP_3DSTATE_VF_STATISTICS_GM45, F_LEN_CONST,
		R_ALL, D_ALL, 0, 1, NULL},

	{"MFX_PIPE_MODE_SELECT", OP_MFX_PIPE_MODE_SELECT, F_LEN_VAR,
		R_VCS, D_ALL, 0, 12, NULL},

	{"MFX_SURFACE_STATE", OP_MFX_SURFACE_STATE, F_LEN_VAR,
		R_VCS, D_ALL, 0, 12, NULL},

	{"MFX_PIPE_BUF_ADDR_STATE", OP_MFX_PIPE_BUF_ADDR_STATE, F_LEN_VAR,
		R_VCS, D_ALL, 0, 12, vgt_cmd_handler_mfx_pipe_buf_addr_state},

	{"MFX_IND_OBJ_BASE_ADDR_STATE", OP_MFX_IND_OBJ_BASE_ADDR_STATE, F_LEN_VAR,
		R_VCS, D_ALL, 0, 12, vgt_cmd_handler_mfx_ind_obj_base_addr_state},

	{"MFX_BSP_BUF_BASE_ADDR_STATE", OP_MFX_BSP_BUF_BASE_ADDR_STATE, F_LEN_VAR,
		R_VCS, D_ALL, ADDR_FIX_3(1,2,3), 12, NULL},

	{"OP_2_0_0_5", OP_2_0_0_5, F_LEN_VAR,
		R_VCS, D_ALL, ADDR_FIX_1(6), 12, NULL},

	{"MFX_STATE_POINTER", OP_MFX_STATE_POINTER, F_LEN_VAR,
		R_VCS, D_ALL, 0, 12, NULL},

	{"MFX_QM_STATE", OP_MFX_QM_STATE, F_LEN_VAR,
		R_VCS, D_GEN7PLUS, 0, 12, NULL},

	{"MFX_FQM_STATE", OP_MFX_FQM_STATE, F_LEN_VAR,
		R_VCS, D_GEN7PLUS, 0, 12, NULL},

	{"MFX_PAK_INSERT_OBJECT", OP_MFX_PAK_INSERT_OBJECT, F_LEN_VAR,
		R_VCS, D_GEN7PLUS, 0, 12, NULL},

	{"MFX_STITCH_OBJECT", OP_MFX_STITCH_OBJECT, F_LEN_VAR,
		R_VCS, D_GEN7PLUS, 0, 12, NULL},

	{"MFD_IT_OBJECT", OP_MFD_IT_OBJECT, F_LEN_VAR,
		R_VCS, D_ALL, 0, 12, NULL},

	{"MFX_WAIT", OP_MFX_WAIT, F_LEN_VAR,
		R_VCS, D_GEN7PLUS, 0, 6, NULL},

	{"MFX_AVC_IMG_STATE", OP_MFX_AVC_IMG_STATE, F_LEN_VAR,
		R_VCS, D_ALL, 0, 12, NULL},

	{"MFX_AVC_QM_STATE", OP_MFX_AVC_QM_STATE, F_LEN_VAR,
		R_VCS, D_ALL, 0, 12, NULL},

	/* to check: is "Direct MV Buffer Base Address" GMA ? */
	{"MFX_AVC_DIRECTMODE_STATE", OP_MFX_AVC_DIRECTMODE_STATE, F_LEN_VAR,
		R_VCS, D_ALL, 0, 12, NULL},

	{"MFX_AVC_SLICE_STATE", OP_MFX_AVC_SLICE_STATE, F_LEN_VAR,
		R_VCS, D_ALL, 0, 12, NULL},

	{"MFX_AVC_REF_IDX_STATE", OP_MFX_AVC_REF_IDX_STATE, F_LEN_VAR,
		R_VCS, D_ALL, 0, 12, NULL},

	{"MFX_AVC_WEIGHTOFFSET_STATE", OP_MFX_AVC_WEIGHTOFFSET_STATE, F_LEN_VAR,
		R_VCS, D_ALL, 0, 12, NULL},

	{"MFD_AVC_PICID_STATE", OP_MFD_AVC_PICID_STATE, F_LEN_VAR,
		R_VCS, D_GEN75PLUS, 0, 12, NULL},
	{"MFD_AVC_DPB_STATE", OP_MFD_AVC_DPB_STATE, F_LEN_VAR,
		R_VCS, D_IVB_PLUS, 0, 12, NULL},

	{"MFD_AVC_BSD_OBJECT", OP_MFD_AVC_BSD_OBJECT, F_LEN_VAR,
		R_VCS, D_ALL, 0, 12, NULL},

	{"MFD_AVC_SLICEADDR", OP_MFD_AVC_SLICEADDR, F_LEN_VAR,
		R_VCS, D_IVB_PLUS, ADDR_FIX_1(2), 12, NULL},

	{"MFC_AVC_FQM_STATE", OP_MFC_AVC_FQM_STATE, F_LEN_VAR,
		R_VCS, D_SNB, 0, 12, NULL},

	{"MFC_AVC_PAK_INSERT_OBJECT", OP_MFC_AVC_PAK_INSERT_OBJECT, F_LEN_VAR,
		R_VCS, D_SNB, 0, 12, NULL},

	{"MFC_AVC_PAK_OBJECT", OP_MFC_AVC_PAK_OBJECT, F_LEN_VAR,
		R_VCS, D_ALL, 0, 12, NULL},

	{"MFX_VC1_PIC_STATE", OP_MFX_VC1_PIC_STATE, F_LEN_VAR,
		R_VCS, D_SNB, 0, 12, NULL},

	{"MFX_VC1_PRED_PIPE_STATE", OP_MFX_VC1_PRED_PIPE_STATE, F_LEN_VAR,
		R_VCS, D_ALL, 0, 12, NULL},

	{"MFX_VC1_DIRECTMODE_STATE", OP_MFX_VC1_DIRECTMODE_STATE, F_LEN_VAR,
		R_VCS, D_ALL, 0, 12, NULL},

	{"MFD_VC1_SHORT_PIC_STATE", OP_MFD_VC1_SHORT_PIC_STATE, F_LEN_VAR,
		R_VCS, D_GEN7PLUS, 0, 12, NULL},

	{"MFD_VC1_LONG_PIC_STATE", OP_MFD_VC1_LONG_PIC_STATE, F_LEN_VAR,
		R_VCS, D_GEN7PLUS, 0, 12, NULL},

	{"MFD_VC1_BSD_OBJECT", OP_MFD_VC1_BSD_OBJECT, F_LEN_VAR,
		R_VCS, D_ALL, 0, 12, NULL},

	{"MFX_MPEG2_PIC_STATE", OP_MFX_MPEG2_PIC_STATE, F_LEN_VAR,
		R_VCS, D_ALL, 0, 12, NULL},

	{"MFX_MPEG2_QM_STATE", OP_MFX_MPEG2_QM_STATE, F_LEN_VAR,
		R_VCS, D_ALL, 0, 12, NULL},

	{"MFD_MPEG2_BSD_OBJECT", OP_MFD_MPEG2_BSD_OBJECT, F_LEN_VAR,
		R_VCS, D_ALL, 0, 12, NULL},

	{"MFX_2_6_0_0", OP_MFX_2_6_0_0, F_LEN_VAR, R_VCS, D_ALL,
		0, 16, vgt_cmd_handler_mfx_2_6_0_0},

	{"MFX_2_6_0_9", OP_MFX_2_6_0_9, F_LEN_VAR, R_VCS, D_ALL, 0, 16, NULL},

	{"MFX_2_6_0_8", OP_MFX_2_6_0_8, F_LEN_VAR, R_VCS, D_ALL, 0, 16, NULL},

	{"MFX_JPEG_PIC_STATE", OP_MFX_JPEG_PIC_STATE, F_LEN_VAR,
		R_VCS, D_GEN7PLUS, 0, 12, NULL},

	{"MFX_JPEG_HUFF_TABLE_STATE", OP_MFX_JPEG_HUFF_TABLE_STATE, F_LEN_VAR,
		R_VCS, D_GEN7PLUS, 0, 12, NULL},

	{"MFD_JPEG_BSD_OBJECT", OP_MFD_JPEG_BSD_OBJECT, F_LEN_VAR,
		R_VCS, D_GEN7PLUS, 0, 12, NULL},

	{"VEBOX_STATE", OP_VEB_STATE, F_LEN_VAR, R_VECS, D_HSW, 0, 12, NULL},

	{"VEBOX_SURFACE_STATE", OP_VEB_SURFACE_STATE, F_LEN_VAR, R_VECS, D_HSW_PLUS, 0, 12, NULL},

	{"VEB_DI_IECP", OP_VEB_DNDI_IECP_STATE, F_LEN_VAR, R_VECS, D_HSW, 0, 12, NULL},
};

static int cmd_hash_init(struct pgt_device *pdev)
{
	int i;
	struct vgt_cmd_entry *e;
	struct cmd_info	*info;
	unsigned int gen_type;

	gen_type = vgt_gen_dev_type(pdev);

	for (i=0; i< ARRAY_SIZE(cmd_info); i++){
		if (!(cmd_info[i].devices & gen_type)){
			vgt_dbg(VGT_DBG_CMD, "CMD[%-30s] op[%04x] flag[%x] devs[%02x] rings[%02x] not registered\n",
					cmd_info[i].name, cmd_info[i].opcode, cmd_info[i].flag,
					cmd_info[i].devices, cmd_info[i].rings);
			continue;
		}

		e = kmalloc(sizeof(*e), GFP_KERNEL);
		if (e == NULL) {
			vgt_err("Insufficient memory in %s\n", __FUNCTION__);
			return -ENOMEM;
		}
		e->info = &cmd_info[i];

		info = vgt_find_cmd_entry_any_ring(e->info->opcode, e->info->rings);
		if (info){
			vgt_err("%s %s duplicated\n", e->info->name, info->name);
			kfree(e);
			return -EINVAL;
		}

		INIT_HLIST_NODE(&e->hlist);
		vgt_add_cmd_entry(e);
		vgt_dbg(VGT_DBG_CMD, "CMD[%-30s] op[%04x] flag[%x] devs[%02x] rings[%02x] registered\n",
				e->info->name,e->info->opcode, e->info->flag, e->info->devices,
				e->info->rings);
	}
	return 0;
}

/* This buffer is used by ftrace to store all commands copied from guest gma
 * space. Sometimes commands can cross pages, this should not be handled in
 * ftrace logic. So this is just used as a 'bounce buffer' */
static u32 cmd_trace_buf[VGT_MAX_CMD_LENGTH];

/* call the cmd handler, and advance ip */
static int vgt_cmd_parser_exec(struct parser_exec_state *s)
{
	uint32_t cmd;
	struct cmd_info *info;
	int rc = 0, i, cmd_len;

	if (!s->vgt->vm_id)
		cmd = *s->ip_va;
	else if (vgt_in_xen)
		cmd = *s->ip_va;
	else { /*kvm guest */
		cmd = kvmgt_read_hva(s->vgt, s->ip_va, CMDLEN, 1);
	}

	info = vgt_get_cmd_info(cmd, s->ring_id);
	if (info == NULL){
		vgt_err("ERROR: unknown cmd 0x%x, opcode=0x%x\n", cmd,
				vgt_get_opcode(cmd, s->ring_id));
		parser_exec_state_dump(s);
		klog_printk("ERROR: unknown cmd %x, ring%d[%lx,%lx] gma[%lx] va[%p]\n",
				cmd, s->ring_id, s->ring_start,
				s->ring_start + s->ring_size, s->ip_gma, s->ip_va);

		return -EFAULT;
	}

	s->info = info;

#ifdef VGT_ENABLE_ADDRESS_FIX
	{
		unsigned int bit;
		for_each_set_bit(bit, (unsigned long*)&info->addr_bitmap, 8*sizeof(info->addr_bitmap))
			address_fixup(s, bit);
	}
#endif

	/* Let's keep this logic here. Someone has special needs for dumping
	 * commands can customize this code snippet.
	 */
#if 0
	klog_printk("%s ip(%08lx): ",
			s->buf_type == RING_BUFFER_INSTRUCTION ?
			"RB" : "BB",
			s->ip_gma);
	cmd_len = cmd_length(s);
	for (i = 0; i < cmd_len; i++) {
		klog_printk("%08x ", cmd_val(s, i));
	}
	klog_printk("\n");
#endif

	cmd_len = cmd_length(s);
	/* The chosen value of VGT_MAX_CMD_LENGTH are just based on
	 * following two considerations:
	 * 1) From observation, most common ring commands is not that long.
	 *    But there are execeptions. So it indeed makes sence to observe
	 *    longer commands.
	 * 2) From the performance and debugging point of view, dumping all
	 *    contents of very commands is not necessary.
	 * We mgith shrink VGT_MAX_CMD_LENGTH or remove this trace event in
	 * future for performance considerations.
	 */
	if (unlikely(cmd_len > VGT_MAX_CMD_LENGTH)) {
		vgt_dbg(VGT_DBG_CMD, "cmd length exceed tracing limitation!\n");
		cmd_len = VGT_MAX_CMD_LENGTH;
	}
	for (i = 0; i < cmd_len; i++)
		cmd_trace_buf[i] = cmd_val(s, i);
	trace_vgt_command(s->vgt->vm_id, s->ring_id, s->ip_gma, cmd_trace_buf,
			cmd_len, s->buf_type == RING_BUFFER_INSTRUCTION);

	if (info->handler) {
		int post_handle = 0;

		if (info->flag & F_POST_HANDLE) {
			post_handle = 1;

			/* Post handle special case.*/
			/*
			 * OP_MI_NOOP: only handles nooped MI_DISPLAY_FILP
			 * to prevent the heavy usage of patch list.
			 */
			if (info->opcode == OP_MI_NOOP && cmd_len == 1)
				post_handle = 0;
		}

		if (!post_handle)
			rc = info->handler(s);
		else
			rc = add_post_handle_entry(s, info->handler);

		if (rc < 0) {
			vgt_err("%s handler error", info->name);
			return rc;
		}
	}

	if (!(info->flag & F_IP_ADVANCE_CUSTOM)){
		rc = vgt_cmd_advance_default(s);
		if (rc < 0){
			vgt_err("%s IP advance error", info->name);
			return rc;
		}
	}

	return rc;
}

static inline bool gma_out_of_range(unsigned long gma, unsigned long gma_head, unsigned gma_tail)
{
	if ( gma_tail >= gma_head)
		return	(gma < gma_head) || (gma > gma_tail);
	else
		return (gma > gma_tail) && (gma < gma_head);

}

#define MAX_PARSER_ERROR_NUM	10

static int __vgt_scan_vring(struct vgt_device *vgt, int ring_id, vgt_reg_t head, vgt_reg_t tail, vgt_reg_t base, vgt_reg_t size)
{
	unsigned long gma_head, gma_tail, gma_bottom;
	struct parser_exec_state s;
	int rc=0;
	uint64_t cmd_nr = 0;
	vgt_state_ring_t *rs = &vgt->rb[ring_id];

	/* ring base is page aligned */
	ASSERT((base & (PAGE_SIZE-1)) == 0);

	gma_head = base + head;
	gma_tail = base + tail;
	gma_bottom = base + size;

	s.buf_type = RING_BUFFER_INSTRUCTION;
	s.buf_addr_type = GTT_BUFFER;
	s.vgt = vgt;
	s.ring_id = ring_id;
	s.ring_start = base;
	s.ring_size = size;
	s.ring_head = gma_head;
	s.ring_tail = gma_tail;

	s.request_id = rs->request_id;

	if (bypass_scan_mask & (1 << ring_id)) {
		add_tail_entry(&s, tail, 100, 0);
		return 0;
	}

	rc = ip_gma_set(&s, base + head);
	if (rc < 0)
		return rc;

	klog_printk("ring buffer scan start on ring %d\n", ring_id);
	vgt_dbg(VGT_DBG_CMD, "scan_start: start=%lx end=%lx\n", gma_head, gma_tail);
	while(s.ip_gma != gma_tail){
		if (s.buf_type == RING_BUFFER_INSTRUCTION){
			ASSERT((s.ip_gma >= base) && (s.ip_gma < gma_bottom));
			if (gma_out_of_range(s.ip_gma, gma_head, gma_tail)){
				vgt_err("ERROR: ip_gma %lx out of range\n", s.ip_gma);
				break;
			}
		}

		cmd_nr++;

		rc = vgt_cmd_parser_exec(&s);
		if (rc < 0){
			vgt_err("cmd parser error\n");
			break;
		}
	}

	if (!rc) {
		add_tail_entry(&s, tail, cmd_nr, 0);
		rs->cmd_nr++;
	}

	klog_printk("ring buffer scan end on ring %d\n", ring_id);
	vgt_dbg(VGT_DBG_CMD, "scan_end\n");
	return rc;
}

/*
 * Scan the guest ring.
 *   Return 0: success
 *         <0: Address violation.
 */
int vgt_scan_vring(struct vgt_device *vgt, int ring_id)
{
	vgt_state_ring_t *rs = &vgt->rb[ring_id];
	vgt_ringbuffer_t *vring = &rs->vring;
	int ret;
	cycles_t t0, t1;
	struct vgt_statistics *stat = &vgt->stat;

	t0 = get_cycles();

	if ( !(vring->ctl & _RING_CTL_ENABLE) ) {
		/* Ring is enabled */
		vgt_dbg(VGT_DBG_CMD, "VGT-Parser.c vring head %x tail %x ctl %x\n",
			vring->head, vring->tail, vring->ctl);
		return 0;
	}

	stat->vring_scan_cnt++;
	rs->request_id++;
	ret = __vgt_scan_vring (vgt, ring_id, rs->last_scan_head,
		vring->tail & RB_TAIL_OFF_MASK,
		vring->start, _RING_CTL_BUF_SIZE(vring->ctl));

	rs->last_scan_head = vring->tail;

	t1 = get_cycles();
	stat->vring_scan_cycles += t1 - t0;
	ASSERT_VM(!ret, vgt);
	return ret;
}

int vgt_cmd_parser_init(struct pgt_device *pdev)
{
	return cmd_hash_init(pdev);
}

void vgt_cmd_parser_exit(void)
{
	vgt_clear_cmd_table();
}
