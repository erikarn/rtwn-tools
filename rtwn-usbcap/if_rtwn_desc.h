#ifndef	__IF_RTWN_DESC_H__
#define	__IF_RTWN_DESC_H__

struct rtwn_rx_stat_common {
	uint32_t rxdw0;
	uint32_t rxdw1;
	uint32_t rxdw2;
	uint32_t rxdw3;
	uint32_t rxdw4;
	uint32_t tsf_low;
} __packed __attribute__((aligned(4)));

#endif	/* __IF_RTWN_DESC_H__ */
