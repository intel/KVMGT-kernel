/*
 * vGT virtual video BIOS data block parser
 *
 * Copyright(c) 2011-2014 Intel Corporation. All rights reserved.
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

#include "vgt.h"
#include "vbios.h"

static void* get_block_by_id(struct bios_data_header *header, int id)
{
	void *curr = NULL;
	int offset;
	struct block_header *block = NULL;

	ASSERT(header != NULL);

	if (memcmp(header->signature, "BIOS_DATA_BLOCK", 15) != 0) {
		/* invalid bios_data_block */
		return NULL;
	}

	offset = header->header_size;

	while(offset < header->bdb_size) {
		block = (struct block_header*) ( ((u8*) header)+offset);

		/* find block by block ID */
		if (block->block_id == id) {
			curr = block;
			break;
		}
		else {
			/* search for next block */
			offset += block->block_size
				+ sizeof(struct block_header);
		}

	}

	return curr;
}

/*
 * We modify opregion vbios data to indicate that we support full port
 * features: DP, HDMI, DVI
 */
bool vgt_prepare_vbios_general_definition(struct vgt_device *vgt)
{
	bool ret = false;
	struct vbt_header *header;
	struct bios_data_header *data_header;
	struct vbios_general_definitions *gendef;
	struct child_devices* child_dev;
	int child_dev_num = 0;
	int i;

	/* only valid for HSW */
	if (!IS_HSW(vgt->pdev)) {
		vgt_dbg(VGT_DBG_GENERIC, "Not HSW platform. Do nothing\n");
		return false;
	}

	header = (struct vbt_header*) (vgt->state.opregion_va + VBIOS_OFFSET);

	data_header = (struct bios_data_header*)
		(((u8*)header) + header->bios_data_offset);

	gendef = get_block_by_id(data_header, VBIOS_GENERAL_DEFINITIONS);
	if (gendef == NULL) {
		vgt_dbg(VGT_DBG_GENERIC,
			"VBIOS_GENERAL_DEFINITIONS block was not found. \n");
		ret = false;
	}
	else {
		child_dev_num = (gendef->block_header.block_size
		- sizeof(*gendef)
		+ sizeof(struct block_header))/ sizeof(struct child_devices);

		vgt_dbg(VGT_DBG_GENERIC,
			"VGT_VBIOS: block_size=%d child_dev_num=%d \n",
			gendef->block_header.block_size, child_dev_num);

		for (i=0; i<child_dev_num; i++) {
			child_dev = gendef->dev + i;

			if (child_dev->dev_type == 0) {
				continue;
			}

			switch(child_dev->efp_port) {
			case EFP_HDMI_B:
			case EFP_HDMI_C:
			case EFP_HDMI_D:
			case EFP_DPORT_B:
			case EFP_DPORT_C:
			case EFP_DPORT_D:
			case EFP_DPORT_A:
				/* set DP capable bit */
				child_dev->dev_type |=DEVTYPE_FLAG_DISPLAY_PORT;
				child_dev->is_dp_compatible = 1;

				/* set HDMI capable bit */
				child_dev->dev_type &= (~DEVTYPE_FLAG_NOT_HDMI);
				child_dev->is_hdmi_compatible = 1;

				/* set DVI capable bit */
				child_dev->dev_type |= DEVTYPE_FLAG_DVI;
				child_dev->is_dvi_compatible = 1;

				vgt_dbg(VGT_DBG_GENERIC,
		"VGT_VBIOS: child_dev modified. child_dev[%d].dev_type=%04x \n",
		i, child_dev->dev_type);

				ret = true;
				break;
			default:
				/* not port description. Skip this child_dev */
				continue;
			}
		}
	}

	return ret;
}

