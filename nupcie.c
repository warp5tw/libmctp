/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
/* Copyright (c) 2020 Nuvoton Technology Corporation */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <byteswap.h>
#include <endian.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <linux/nuvoton-mctp.h>

#include "container_of.h"
#include "libmctp-alloc.h"
#include "libmctp-nupcie.h"
#include "libmctp-log.h"
#include "nupcie.h"
#include <stdio.h>

#undef pr_fmt
#define pr_fmt(fmt) "nupcie: " fmt

/*
 * PCIe header template in "network format" - Big Endian
 */
static const struct mctp_pcie_hdr mctp_pcie_hdr_template_be = {
	.fmt_type = MSG_4DW_HDR,
	.mbz_attr_length = MCTP_PCIE_VDM_ATTR,
	.code = MSG_CODE_VDM_TYPE_1,
	.vendor = VENDOR_ID_DMTF_VDM
};

static int mctp_nupcie_open(struct mctp_binding_nupcie *nupcie)
{
	int fd = open(NU_DRV_FILE, O_RDWR);

	if (fd < 0) {
		mctp_prerr("Cannot open: %s, errno = %d", NU_DRV_FILE, errno);

		return fd;
	}

	nupcie->fd = fd;
	return 0;
}

/*
 * Start function. Opens driver and read bdf
 */
static int mctp_nupcie_start(struct mctp_binding *b)
{
	struct mctp_binding_nupcie *nupcie = binding_to_nupcie(b);
	int rc;

	assert(nupcie);

	rc = mctp_nupcie_open(nupcie);
#if 0
	if (!rc)
		rc = mctp_binding_astpcie_get_bdf(astpcie);
#endif
	return rc;
}

static uint8_t mctp_nupcie_tx_get_pad_len(struct mctp_pktbuf *pkt)
{
	size_t sz = mctp_pktbuf_size(pkt);

	return PCIE_PKT_ALIGN(sz) - sz;
}

static uint16_t mctp_nupcie_tx_get_payload_size_dw(struct mctp_pktbuf *pkt)
{
	size_t sz = mctp_pktbuf_size(pkt);

	return PCIE_PKT_ALIGN(sz) / sizeof(uint32_t) - MCTP_HDR_SIZE_DW;
}
/*
 * Tx function which writes single packet to device driver
 */
static int mctp_nupcie_tx(struct mctp_binding *b,
				   struct mctp_pktbuf *pkt)
{
	struct mctp_nupcie_pkt_private *pkt_prv =
		(struct mctp_nupcie_pkt_private *)pkt->msg_binding_private;
	struct mctp_binding_nupcie *nupcie = binding_to_nupcie(b);
	struct mctp_pcie_hdr *hdr = (struct mctp_pcie_hdr *)pkt->data;
	struct mctp_hdr *mctp_hdr = mctp_pktbuf_hdr(pkt);
	uint16_t payload_len_dw = mctp_nupcie_tx_get_payload_size_dw(pkt);
	uint8_t pad = mctp_nupcie_tx_get_pad_len(pkt);
	ssize_t write_len, len, i;

	memcpy(hdr, &mctp_pcie_hdr_template_be, sizeof(*hdr));

#ifdef MCTP_ASTPCIE_RESPONSE_WA
	if (!(pkt_prv->flags_seq_tag & MCTP_HDR_FLAG_TO))
		mctp_hdr->flags_seq_tag = pkt_prv->flags_seq_tag;
#endif

	mctp_prdebug("TX, len: %d, pad: %d", payload_len_dw, pad);

	PCIE_SET_ROUTING(hdr, pkt_prv->routing);
	PCIE_SET_DATA_LEN(hdr, payload_len_dw);
	PCIE_SET_REQ_ID(hdr, nupcie->bdf);
	PCIE_SET_TARGET_ID(hdr, pkt_prv->remote_id);
	PCIE_SET_PAD_LEN(hdr, pad);

	len = (payload_len_dw * sizeof(uint32_t)) +
	      NUVOTON_MCTP_PCIE_VDM_HDR_SIZE;

	for (i = 0; i < len ; i+=4)
		fprintf(stderr, "TX i: %d data:0x%02x%02x%02x%02x\r\n", i, pkt->data[i+3], pkt->data[i+2], pkt->data[i+1], pkt->data[i]);


	write_len = write(nupcie->fd, pkt->data, len);
	if (write_len < 0) {
		mctp_prerr("TX error");
		return -1;
	}

	return 0;
}

static size_t mctp_nupcie_rx_get_payload_size(struct mctp_pcie_hdr *hdr)
{
	size_t len = PCIE_GET_DATA_LEN(hdr) * sizeof(uint32_t);
	uint8_t pad = PCIE_GET_PAD_LEN(hdr);

	return len - pad;
}

/*
 * Simple poll implementation for use
 */
int mctp_nupcie_poll(struct mctp_binding_nupcie *nupcie, int timeout)
{
	struct pollfd fds[1];
	int rc;

	fds[0].fd = nupcie->fd;
	fds[0].events = POLLIN | POLLOUT;

	rc = poll(fds, 1, timeout);

	if (rc > 0)
		return fds[0].revents;

	if (rc < 0) {
		mctp_prwarn("Poll returned error status (errno=%d)", errno);

		return -1;
	}

	return 0;
}

static int mctp_data_rx(struct mctp_binding_nupcie *nupcie, uint32_t *data)
{
	struct mctp_nupcie_pkt_private pkt_prv;
	struct mctp_pktbuf *pkt;
	struct mctp_pcie_hdr *hdr;
	struct mctp_hdr *mctp_hdr;
	size_t read_len, payload_len;
	int rc;

	hdr = (struct mctp_pcie_hdr *)data;

	if (hdr->vendor != VENDOR_ID_DMTF_VDM ) {
		fprintf(stderr, "it's not DMTF VDMs header\r\n");
		return 0;
	}

	if (hdr->code != MSG_CODE_VDM_TYPE_1) {
		fprintf(stderr, "it's not VDM code\r\n");
		return 0;
	}

	if (hdr->mbz != 0) {
		fprintf(stderr, "Traffic Class is no zero\r\n");
		return 0;
	}

	payload_len = mctp_nupcie_rx_get_payload_size(hdr);
	pkt_prv.routing = PCIE_GET_ROUTING(hdr);
	pkt_prv.remote_id = PCIE_GET_REQ_ID(hdr);

	pkt = mctp_pktbuf_alloc(&nupcie->binding, 0);
	if (!pkt) {
		mctp_prerr("pktbuf allocation failed");
		return -1;
	}

	rc = mctp_pktbuf_push(pkt, data + PCIE_HDR_SIZE_DW,
			      payload_len + sizeof(struct mctp_hdr));

	if (rc) {
		mctp_prerr("Cannot push to pktbuf");
		mctp_pktbuf_free(pkt);
		return -1;
	}

	mctp_hdr = mctp_pktbuf_hdr(pkt);
#ifdef MCTP_ASTPCIE_RESPONSE_WA
	pkt_prv.flags_seq_tag = mctp_hdr->flags_seq_tag;
#endif
	memcpy(pkt->msg_binding_private, &pkt_prv, sizeof(pkt_prv));
	mctp_bus_rx(&nupcie->binding, pkt);

	return PCIE_GET_DATA_LEN(hdr) + PCIE_VDM_HDR_SIZE_DW;
}

int mctp_nupcie_rx(struct mctp_binding_nupcie *nupcie)
{
	uint32_t data[MCTP_NUPCIE_BINDING_DEFAULT_BUFFER];
	struct mctp_nupcie_pkt_private pkt_prv;
	struct mctp_pktbuf *pkt;
	struct mctp_pcie_hdr *hdr;
	struct mctp_hdr *mctp_hdr;
	size_t read_len, payload_len;
	int ret, index = 0, i;

	read_len = read(nupcie->fd, &data, sizeof(data));;
	if (read_len < 0) {
		mctp_prerr("Reading RX data failed (errno = %d)", errno);
		return -1;
	}

  	fprintf(stderr,"rx data read_len:0x%x\r\n", read_len);

	for (i = 0; i < read_len ; i++)
		fprintf(stderr, "Rx i: %d data:0x%lx\r\n", i, data[i]);

 	while (index < read_len) {
		ret = mctp_data_rx(nupcie, &data[index]);
		if (ret == 0)
			return 0;

		if (ret < 0)
			return ret;
		index += ret;
		fprintf(stderr, "index: %d ret %d\r\n", index, ret);
	}

	return 0;
}

/*
 * Initializes PCIe binding structure
 */
struct mctp_binding_nupcie *mctp_nupcie_init(void)
{
	struct mctp_binding_nupcie *nupcie;

	nupcie = __mctp_alloc(sizeof(*nupcie));
	if (!nupcie)
		return NULL;

	memset(nupcie, 0, sizeof(*nupcie));

	nupcie->binding.name = "nupcie";
	nupcie->binding.version = 1;
	nupcie->binding.tx = mctp_nupcie_tx;
	nupcie->binding.start = mctp_nupcie_start;
	nupcie->binding.pkt_size = MCTP_PACKET_SIZE(MCTP_BTU);

	/* where mctp_hdr starts in in/out comming data
	 * note: there are two approaches: first (used here) that core
	 * allocates pktbuf to contain all binding metadata or this is handled
	 * other way by only by binding.
	 * This might change as smbus binding implements support for medium
	 * specific layer */
	nupcie->binding.pkt_pad = sizeof(struct mctp_pcie_hdr);
	nupcie->binding.pkt_priv_size = sizeof(struct mctp_nupcie_pkt_private);

	return nupcie;
}

/*
 * Closes file descriptor and releases binding memory
 */
void mctp_nupcie_free(struct mctp_binding_nupcie *b)
{
	close(b->fd);
	__mctp_free(b);
}

/*
 * Returns generic binder handler from PCIe binding handler
 */
struct mctp_binding *
mctp_nupcie_core(struct mctp_binding_nupcie *nupcie)
{
	return &nupcie->binding;
}

int mctp_nupcie_get_fd(struct mctp_binding_nupcie *nupcie)
{
	return nupcie->fd;
}