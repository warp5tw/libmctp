/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2020 Intel Corporation */
/* Copyright (c) 2020 Nuvoton Technology Corporation */

#ifndef _UAPI_LINUX_NUVOTON_MCTP_H
#define _UAPI_LINUX_NUVOTON_MCTP_H

#include <linux/ioctl.h>
#include <linux/types.h>

/*
 * nuvoton-mctp is a simple device driver exposing a read/write interface:
 *  +----------------------+
 *  | PCIe VDM Header      | 16 bytes (Big Endian)
 *  +----------------------+
 *  | MCTP Message Payload | 64/128/256/512 bytes (Little Endian)
 *  +----------------------+
 *
 * MCTP packet description can be found in DMTF DSP0238,
 * MCTP PCIe VDM Transport Specification.
 *
 */

#define NUVOTON_MCTP_PCIE_VDM_HDR_SIZE 16


#endif /* _UAPI_LINUX_NUVOTON_MCTP_H */
