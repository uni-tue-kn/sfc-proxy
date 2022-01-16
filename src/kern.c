#include <assert.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/mpls.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <stdbool.h>

#include "../include/bpf_endian.h"
#include "../include/helpers.h"
#include "../include/custom_helpers.h"
#include "../include/enums.h"
#include "../include/config.h"

// Note: Always allocating MAX_MPLS_LABELS is not very efficient (memory
// bandwidth) but due to the limits of eBPF maps a more efficient
// implementation is too complex (would e.g. require multiple maps):
struct mpls_label_stack {
	unsigned int count;
	__be32 entries[MAX_MPLS_LABELS];
};

#ifdef USE_PKG_METADATA
#define RND_SIZE 2
struct header_stack_key {
	unsigned long long rnd[RND_SIZE];
};
#define DERIVE_KEY()                                                           \
	struct header_stack_key key = { 0 };                                   \
	for (unsigned int i = 0; i < RND_SIZE; ++i) {                          \
		key.rnd[i] = bpf_get_prandom_u32();                            \
	}
#else
struct header_stack_key {
	struct iphdr iph;
	struct tcphdr tcph;
};
#define DERIVE_KEY()                                                           \
	struct header_stack_key key = { .iph = *iph, .tcph = *tcph };          \
	key.iph.ttl = 0;                                                       \
	key.iph.tot_len = 0;                                                   \
	key.iph.check = 0;                                                     \
	key.tcph.check = 0;
#endif

// Some extra definitions (so that we don't have to include headers for them):
#define IPPROTO_TCP 0x06

// eBPF maps:
// Note: To delete a map, e.g.:
// rm /sys/fs/bpf/tc/globals/CACHE_MAP_HEADER_STACK
// TODO: Investigate alternatives to eBPF maps (e.g. per packet metadata that
// can be set via XDP and at least be used for TC-ingress hooks).

// For compiling on Ubuntu 18.04 (the Linux kernel headers are too old):
#ifndef BPF_ADJ_ROOM_MAC
#define BPF_ADJ_ROOM_MAC 1
#endif

/**
 * An eBPF map for configuration settings (e.g. a switch to control printk
 * messages for debugging output). This can be used for implementing basic
 * control plane functionality to change parts of the program's behaviour
 * at runtime.
 */
#ifndef NO_DEBUG // Note: We should drop this if we add settings or introduce NO_CONFIG
struct bpf_elf_map SEC("maps") CONFIG_MAP = {
	.type = BPF_MAP_TYPE_ARRAY,
	.size_key = sizeof(unsigned int),
	.size_value = sizeof(bool),
	.pinning = PIN_GLOBAL_NS,
	.max_elem = 1,
};
#endif // !NO_DEBUG

/**
 * An eBPF map for statistics.
 */
#ifndef NO_STATS
struct bpf_elf_map SEC("maps") STATS_MAP = {
	.type = BPF_MAP_TYPE_ARRAY,
	.size_key = sizeof(int),
	.size_value = sizeof(long),
	.pinning = PIN_GLOBAL_NS,
	.max_elem = STATS_SIZE,
};
#endif // !NO_STATS

// A map to cache the relevant packet headers:
struct bpf_elf_map SEC("maps") CACHE_MAP_HEADER_STACK = {
	.type = BPF_MAP_TYPE_LRU_HASH,
	.size_key = sizeof(struct header_stack_key),
	.size_value = sizeof(struct mpls_label_stack), // MPLS header stack
	.pinning = PIN_GLOBAL_NS,
	.max_elem = HEADER_CACHE_MAP_SIZE,
};

// The default actions for various cases:
#define RX_IGNORED_ACTION XDP_PASS
#define TX_IGNORED_ACTION TC_ACT_OK
#ifdef STRICT_MODE
#define RX_MALFORMED_ACTION XDP_DROP
#define TX_MALFORMED_ACTION TC_ACT_SHOT
#define TX_NOT_CACHED_ACTION TC_ACT_SHOT
#else
#define RX_MALFORMED_ACTION XDP_PASS
#define TX_MALFORMED_ACTION TC_ACT_OK
#define TX_NOT_CACHED_ACTION TC_ACT_OK
#endif

#ifdef NO_DEBUG
// Do nothing:
#define DEBUG(x, ...)
#define DEBUG_RX(id, x, ...)
#define DEBUG_TX(id, x, ...)
#define REQUEST_ID
#else // NO_DEBUG
/*
 * Check whether the debug flag is set via user space.
 */
bool is_debug(void);

forced_inline bool is_debug()
{
	int index = 0; // the map has size of 1 so index is always 0
	bool *value = (bool *)bpf_map_lookup_elem(&CONFIG_MAP, &index);
	if (!value) {
		return false;
	}
	return *value;
}

#define bpf_debug_printk(fmt, ...)                                             \
	({                                                                     \
		if (unlikely(is_debug())) {                                    \
			char ____fmt[] = fmt;                                  \
			bpf_trace_printk(____fmt, sizeof(____fmt),             \
					 ##__VA_ARGS__);                       \
		}                                                              \
	})
#define DEBUG(x, ...) bpf_debug_printk(x, ##__VA_ARGS__)

#define DEBUG_RX(id, x, ...) DEBUG("[RX][%u] " x, id, ##__VA_ARGS__)
#define DEBUG_TX(id, x, ...) DEBUG("[TX][%u] " x, id, ##__VA_ARGS__)

/*
 * Since packet handling and printk can be interleaved, this will
 * add a unique identifier for an individual invocation so you can grep the
 * request identifier and see the trace log messages in isolation.
 */
#define REQUEST_ID unsigned long long request_id = bpf_get_prandom_u32()
#endif // NO_DEBUG

#ifdef NO_STATS
// Do nothing:
#define increment_stats_counter(stats_index)
#else // NO_STATS
static inline void increment_stats_counter(int stats_index)
{
	long *elem = bpf_map_lookup_elem(&STATS_MAP, &stats_index);
	if (elem) {
		__sync_fetch_and_add(elem, 1);
	} else {
		DEBUG("Warning: Could not increment the stats counter number %i.\n",
		      stats_index);
	}
}
#endif // NO_STATS

// We always use these macros instead of "return" to correctly count all
// packets and provide optional debugging output:
#define return_and_log_rx(code, counter, ...)                                  \
	increment_stats_counter(counter);                                      \
	DEBUG_RX(request_id, ##__VA_ARGS__);                                   \
	return code
#define return_and_log_tx(code, counter, ...)                                  \
	increment_stats_counter(counter);                                      \
	DEBUG_TX(request_id, ##__VA_ARGS__);                                   \
	return code

/*
 * XDP L2 decapsulation program.
 */
int sfc_proxy_decap_xdp_prog(struct xdp_md *);
SEC("decap_xdp") int sfc_proxy_decap_xdp_prog(struct xdp_md *ctx)
{
	REQUEST_ID; // Only relevant for debugging
	DEBUG_RX(request_id, "Starting to process the packet\n");

	// Cursor for parsing:
	struct hdr_cursor cursor = { .start = (void *)(long)ctx->data,
				     .end = (void *)(long)ctx->data_end,
				     .pos = (void *)(long)ctx->data };

	// Parse the Ethernet header:
	struct ethhdr *eth;
	parse_header_or(eth, cursor)
	{
		return_and_log_rx(RX_MALFORMED_ACTION, RX_MALFORMED,
				  "Warning: Invalid/non-Ethernet packet\n");
	}

	// Store whether there is any SFC encapsulation (MPLS label stack) or not:
	bool encapsulated;
	// Note: mpls_stack must be zero-filled for the eBPF verifier to avoid
	// "invalid read from stack" and this sets mpls_stack.counter to the
	// correct value (zero) in case we jump to ingress_parse_ip_header:
	struct mpls_label_stack mpls_stack = { 0 };
	// Check if it's an MPLS packet:
	if (eth->h_proto == bpf_htons(ETH_P_MPLS_UC)) {
		DEBUG_RX(request_id, "Ethernet is wrapping MPLS_UC packet\n");
		encapsulated = true;
	} else if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		DEBUG_RX(request_id, "Ethernet is wrapping IP packet\n");
		encapsulated = false;
		goto ingress_parse_ip_header;
	} else {
		DEBUG_RX(
			request_id,
			"Ethernet is not wrapping MPLS_UC or IP packet: 0x%x\n",
			bpf_ntohs(eth->h_proto));
		return_and_log_rx(RX_IGNORED_ACTION, RX_IGNORED,
				  "Ignoring non-MPLS and non-IP packet\n");
	}

	// Parse the MPLS header stack:
	// Note mpls_stack.count should start at 1 but that is more complicated
	// due to the eBPF verifier.
	for (mpls_stack.count = 0; mpls_stack.count < MAX_MPLS_LABELS;
	     ++mpls_stack.count) {
		struct mpls_label *mplsh;
		parse_header_or(mplsh, cursor)
		{
			return_and_log_rx(RX_MALFORMED_ACTION, RX_MALFORMED,
					  "Warning: Malformed MPLS packet\n");
		}
#ifdef NO_DEBUG
		if (cursor.pos + 1 > cursor.end) {
			// This is actually quite interesting and feels like it
			// should be due to an eBPF verifier bug (unless the
			// compiler does something strange / has a bug) but it
			// requires further analysis. The extremely strange
			// thing is that this check is **only** required with
			// NO_DEBUG which just disables all code for the
			// debugging output. The "parse_header_or(mplsh, cursor)"
			// line above already exits if "cursor.pos > cursor.end"
			// but apparently that is not enough in this case.
			// Even more interestingly "cursor.pos >= cursor.end"
			// is also not enough but that might be explained by
			// some pointer arithmetic details. Anyway, the
			// following code is technically reachable but should
			// never be reached in practice because even if this is
			// the last MPLS label an IP header should come next:
			return_and_log_rx(XDP_DROP, ERROR,
					  "Error: Reached unreachable code\n");
		}
#endif // NO_DEBUG

		// Store the MPLS header:
		mpls_stack.entries[mpls_stack.count] = mplsh->entry;
		// Optional (to verify):
		DEBUG_RX(request_id, "Found MPLS label: %d\n",
			 (bpf_ntohl(mplsh->entry) & MPLS_LS_LABEL_MASK) >>
				 MPLS_LS_LABEL_SHIFT);

		if (bpf_ntohl(mplsh->entry) & MPLS_LS_S_MASK) {
			DEBUG_RX(
				request_id,
				"Reached the bottom of the MPLS label stack\n");
			// Fix the count (array index -> count) and exit the
			// loop:
			mpls_stack.count++;
			break;
		} else {
			if (mpls_stack.count + 1 == MAX_MPLS_LABELS) {
				return_and_log_rx(
					RX_MALFORMED_ACTION, RX_TOO_BIG,
					"Warning: Packet with too many MPLS labels\n");
			}
		}
	}

	// Parse the IP header (note: The code assumes an IP header after the
	// last MPLS header - packets must be generated accordingly):
	struct iphdr *iph;
ingress_parse_ip_header:
	parse_header_or(iph, cursor)
	{
		if (encapsulated) {
			return_and_log_rx(
				RX_MALFORMED_ACTION, RX_MALFORMED,
				"Warning: Packet with no/invalid IP header after MPLS header\n");
		} else {
			return_and_log_rx(
				RX_MALFORMED_ACTION, RX_MALFORMED,
				"Warning: Packet with no/invalid IP header after Ethernet header\n");
		}
	}
	// Check if it's an IPv4 packet:
	if (iph->version != 4) {
		DEBUG_RX(request_id, "Unexpected IP version: %i\n",
			 iph->version);
		return_and_log_rx(RX_IGNORED_ACTION, RX_IGNORED,
				  "Ignoring non-IPv4 packet\n");
	}

	// Check if it's a TCP packet:
	if (iph->protocol != IPPROTO_TCP) {
		DEBUG_RX(request_id, "IP is not wrapping TCP packet: 0x%x\n",
			 iph->protocol);
		return_and_log_rx(RX_IGNORED_ACTION, RX_IGNORED,
				  "Ignoring non-TCP packet\n");
	}
	DEBUG_RX(request_id, "IP is wrapping TCP packet\n");

	// Parse the TCP header:
	struct tcphdr *tcph;
	parse_header_or(tcph, cursor)
	{
		return_and_log_rx(
			RX_MALFORMED_ACTION, RX_MALFORMED,
			"Warning: Packet with invalid TCP header after IP header\n");
	}

#ifndef SKIP_STORING_LABEL_STACK
	DERIVE_KEY()
	// Optional: Print the key (but requires converting the struct into a string:
	// DEBUG_RX(request_id, "Caching the headers with key: 0x%x\n", key);
	// TODO: Shouldn't be required but currently required to satisfy
	// the eBPF verifier:
	struct mpls_label_stack mpls_stack_copy = mpls_stack;
	if (bpf_map_update_elem(&CACHE_MAP_HEADER_STACK, &key, &mpls_stack_copy,
				BPF_NOEXIST) != 0) {
		// We have a collision: An entry for the key is already stored in the eBPF map.
		// We need to drop this packet because another packet with the
		// same key might still be processed:
		return_and_log_rx(
			XDP_DROP, RX_COLLISION,
			"Warning: Dropping packet due to key collision\n");
		// Note: It's also possible that the other packet was dropped
		// by the VNF and if LRU (FIFO) is not enough we could consider
		// storing a timestamp as well to decide if we want to
		// replace the cached entry or not.
	}
#endif

	// Copy the Ethernet header:
	struct ethhdr eth_cpy;
	__builtin_memcpy(&eth_cpy, eth, sizeof(eth_cpy));

#ifdef USE_PKG_METADATA
	// Store the unique key via user-defined packet metadata:
	int meta_ret =
		bpf_xdp_adjust_meta(ctx, -(int)sizeof(struct header_stack_key));
	if (meta_ret) {
		return_and_log_rx(XDP_DROP, ERROR,
				  "Error: XDP adjust meta failed: %i\n",
				  meta_ret);
	}
	struct header_stack_key *pkg_metadata = (void *)(long)ctx->data_meta;
	if ((void *)(pkg_metadata + 1) > (void *)(long)ctx->data) {
		// Could not parse and store the packet metadata:
		return_and_log_rx(
			XDP_DROP, ERROR,
			"Error: Failed to parse the packet metadata\n");
	}
	__builtin_memcpy(pkg_metadata, &key, sizeof(struct header_stack_key));
#endif

	if (!encapsulated) {
		// No headers to remove -> we're done:
		return_and_log_rx(XDP_PASS, RX_SUCCESS,
				  "Packet processing succeeded\n");
	}

	// Remove the MPLS labels:
	DEBUG_RX(request_id, "Removing the MPLS labels\n");
	int ret = bpf_xdp_adjust_head(
		ctx, (int)(mpls_stack.count * sizeof(struct mpls_label)));
	if (ret) {
		return_and_log_rx(XDP_DROP, ERROR,
				  "Error: XDP adjust head failed: %i\n", ret);
	}
	cursor.start = (void *)(long)ctx->data;
	cursor.end = (void *)(long)ctx->data_end;
	cursor.pos = cursor.start;
	parse_header_or(eth, cursor)
	{
		// Drop the now invalid packet (partially modified):
		return_and_log_rx(
			XDP_DROP, ERROR,
			"Error: Failed to parse Ethernet header after dropping MPLS label stack\n");
	}
	__builtin_memcpy(eth, &eth_cpy, sizeof(eth_cpy));
	eth->h_proto = bpf_htons(ETH_P_IP); // Optional: Don't hardcode

	return_and_log_rx(XDP_PASS, RX_SUCCESS,
			  "MPLS decapsulation succeeded\n");
}

/*
 * TC L2 encapsulation program.
 */
int sfc_proxy_encap_tc_filter(struct __sk_buff *);
SEC("encap_tc") int sfc_proxy_encap_tc_filter(struct __sk_buff *skb)
{
	REQUEST_ID; // Only relevant for debugging
	DEBUG_TX(request_id, "Starting to process the packet\n");

	// Cursor for parsing:
	struct hdr_cursor cursor = { .start = (void *)(long)skb->data,
				     .end = (void *)(long)skb->data_end,
				     .pos = (void *)(long)skb->data };

	// Parse the Ethernet header:
	struct ethhdr *eth;
	parse_header_or(eth, cursor)
	{
		return_and_log_tx(TX_MALFORMED_ACTION, TX_MALFORMED,
				  "Warning: Invalid/non-Ethernet packet\n");
	}

	// Check if it's an IP packet:
	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		DEBUG_TX(request_id,
			 "Ethernet is not wrapping IP packet: 0x%x\n",
			 bpf_ntohs(eth->h_proto));
		return_and_log_tx(TX_IGNORED_ACTION, TX_IGNORED,
				  "Ignoring non-IP packet\n");
	}
	DEBUG_TX(request_id, "Ethernet is wrapping IP packet\n");

	// Parse the IP header:
	struct iphdr *iph;
	parse_header_or(iph, cursor)
	{
		return_and_log_tx(
			TX_MALFORMED_ACTION, TX_MALFORMED,
			"Warning: Packet with malformed IPv4 header\n");
	}
	// Check if it's an IPv4 packet:
	if (iph->version != 4) {
		DEBUG_TX(request_id, "Unexpected IP version: %i\n",
			 iph->version);
		return_and_log_tx(TX_IGNORED_ACTION, TX_IGNORED,
				  "Ignoring non-IPv4 packet\n");
	}

	// We're only interested in IP packets that have a TCP header next:
	if (iph->protocol != IPPROTO_TCP) {
		DEBUG_TX(request_id, "IP is not wrapping TCP packet: 0x%x\n",
			 iph->protocol);
		return_and_log_tx(TX_IGNORED_ACTION, TX_IGNORED,
				  "Ignoring non-TCP packet\n");
	}
	DEBUG_TX(request_id, "IP is wrapping TCP packet\n");

	// Parse the TCP header:
	struct tcphdr *tcph;
	parse_header_or(tcph, cursor)
	{
		return_and_log_tx(
			TX_MALFORMED_ACTION, TX_MALFORMED,
			"Warning: Packet with invalid TCP header after IP header\n");
	}

	// Retrieve the cached headers:
#ifndef SKIP_LOADING_LABEL_STACK
	struct mpls_label_stack mpls_stack;
#ifdef USE_PKG_METADATA
	struct header_stack_key *pkg_metadata = (void *)(long)skb->data_meta;
	if ((void *)(pkg_metadata + 1) > (void *)(long)skb->data) {
		// Could not parse and load the packet metadata:
		return_and_log_tx(TX_NOT_CACHED_ACTION, TX_NOT_CACHED,
				  "Warning: Matching packet without a key\n");
	}
	// Copy the key to avoid USE_PKG_METADATA conditionals in the rest of the code:
	struct header_stack_key key;
	__builtin_memcpy(&key, pkg_metadata, sizeof(struct header_stack_key));
#else
	DERIVE_KEY()
#endif
	// Optional: Print the key (but requires converting the struct into a string:
	// DEBUG_TX(request_id, "Retrieving the cached headers with key: 0x%x\n",
	// 	 key);
	struct mpls_label_stack *mpls_stack_ptr =
		bpf_map_lookup_elem(&CACHE_MAP_HEADER_STACK, &key);
	if (mpls_stack_ptr) {
		// Optional: We could also avoid this copy and use *mpls_stack_ptr directly:
		__builtin_memcpy(&mpls_stack, mpls_stack_ptr,
				 sizeof(struct mpls_label_stack));
#ifndef SKIP_DELETING_LABEL_STACK
		const int ret =
			bpf_map_delete_elem(&CACHE_MAP_HEADER_STACK, &key);
		if (ret) {
			DEBUG_TX(
				request_id,
				"Warning: Failed to delete a map element: %i\n",
				ret);
		}
#endif
	} else {
		// No cached header was found for this packet. Either it wasn't
		// encapuslated (e.g. if it originates from this host) or the
		// cached header is not available anymore (due to LRU or a key
		// collision (deleted by bpf_map_delete_elem above)). To avoid
		// issues we have to forward this packet without encapsulation
		// (vs. dropping it):
		return_and_log_tx(
			TX_NOT_CACHED_ACTION, TX_NOT_CACHED,
			"Warning: Matching packet without a cached header\n");
	}
#else
	// Use a static label stack:
	DEBUG_TX(request_id, "Using a hardcoded MPLS label stack\n");
	struct mpls_label_stack mpls_stack = { 0 };
	mpls_stack.count = 2;
	// Optional: Assign proper values:
	mpls_stack.entries[0] = 0;
	mpls_stack.entries[1] = 0;
#endif

	// Add the MPLS labels:
	DEBUG_TX(request_id, "Adding the MPLS labels\n");
	const int mpls_labels = (int)mpls_stack.count - POP_MPLS_LABELS_COUNT;

	// TODO: Decide what to do in these cases:
	if (mpls_labels < 0) {
		// TODO: We might not necessarily want to drop the packet if mpls_labels < 0
		// (if we want to allow fewer labels than POP_MPLS_LABELS_COUNT)
		return_and_log_tx(
			TC_ACT_SHOT, ERROR,
			"Error: Dropping packet without enough MPLS labels left to pop\n");
	} else if (mpls_labels > MAX_MPLS_LABELS - POP_MPLS_LABELS_COUNT) {
		return_and_log_tx(
			TC_ACT_SHOT, ERROR,
			"Error: Dropping packet with invalid cached header stack\n");
	}
	const int padlen = mpls_labels * (int)sizeof(struct mpls_label);

	if (mpls_labels == 0) {
		// No MPLS labels left to push back -> nothing to do:
		return_and_log_tx(TC_ACT_OK, TX_NOT_MODIFIED,
				  "No MPLS labels needed to be pushed\n");
	}

	// Add the cached MPLS label stack -> ETH / MPLS+ / IP:
	eth->h_proto = bpf_htons(ETH_P_MPLS_UC);

	int ret = bpf_skb_adjust_room(skb, padlen, BPF_ADJ_ROOM_MAC, 0);
	if (ret) { // Some failure -> drop the packet
		return_and_log_tx(TC_ACT_SHOT, ERROR,
				  "Error: SKB adjust room failed: %i\n", ret);
	}

	unsigned long offset = sizeof(struct ethhdr);
	for (unsigned int i = POP_MPLS_LABELS_COUNT; i < mpls_stack.count;
	     ++i) {
		if (i >= MAX_MPLS_LABELS) { // For the eBPF verifier
			return_and_log_tx(TC_ACT_SHOT, ERROR,
					  "Error: Reached unreachable code\n");
		}
		ret = bpf_skb_store_bytes(skb, (int)offset,
					  &mpls_stack.entries[i],
					  sizeof(__be32), BPF_F_RECOMPUTE_CSUM);
		if (ret) { // Some failure -> drop the packet
			return_and_log_tx(TC_ACT_SHOT, ERROR,
					  "Error: SKB store bytes failed: %i\n",
					  ret);
		}
		offset += sizeof(struct mpls_label);
	}

#ifdef REMOVE_LABEL_STACK_AFTER_ADDING_IT
	// Remove the whole MPLS label stack again:
	DEBUG_TX(
		request_id,
		"Warning: Removing the MPLS labels again. Only use this for testing purposes!\n");
	ret = bpf_skb_adjust_room(skb, -padlen, BPF_ADJ_ROOM_MAC, 0);
	if (ret) { // Some failure -> drop the packet
		return_and_log_tx(TC_ACT_SHOT, ERROR,
				  "Error: SKB adjust room failed: %i\n", ret);
	}
	// Need to reset our pointers and parse the ethernet header again for
	// the eBPF verifier (we've modified the underlying packet buffer):
	cursor.start = (void *)(long)skb->data;
	cursor.end = (void *)(long)skb->data_end;
	cursor.pos = (void *)(long)skb->data;
	parse_header_or(eth, cursor)
	{
		// Packet would be malformed (wrong eth->h_proto)
		return_and_log_tx(
			TC_ACT_SHOT, ERROR,
			"Error: Cannot parse Ethernet header after modification\n");
	}
	// Not ETH_P_MPLS_UC anymore:
	eth->h_proto = bpf_htons(ETH_P_IP);
#endif

	return_and_log_tx(TC_ACT_OK, TX_SUCCESS,
			  "MPLS encapsulation succeeded\n");
}

/*
 * XDP program to remove the MPLS label stack on incoming packets.
 */
int mpls_decap_xdp_prog(struct xdp_md *);
SEC("decap_mpls") int mpls_decap_xdp_prog(struct xdp_md *ctx)
{
	// Cursor for parsing:
	struct hdr_cursor cursor = { .start = (void *)(long)ctx->data,
				     .end = (void *)(long)ctx->data_end,
				     .pos = (void *)(long)ctx->data };

	// Parse the Ethernet header:
	struct ethhdr *eth;
	parse_header_or(eth, cursor)
	{
		return RX_MALFORMED_ACTION; // Malformed Ethernet packet
	}

	// Check if it's an MPLS unicast packet:
	if (eth->h_proto != bpf_htons(ETH_P_MPLS_UC)) {
		return RX_IGNORED_ACTION; // Ignore non-MPLS packet
	}

	// Parse the entire MPLS label stack:
	int label_stack_size = -1;
	for (int i = 0; i < MAX_MPLS_LABELS; ++i) {
		struct mpls_label *mplsh;
		parse_header_or(mplsh, cursor)
		{
			return RX_MALFORMED_ACTION; // Malformed MPLS header
		}
		if (bpf_ntohl(mplsh->entry) & MPLS_LS_S_MASK) {
			// Reached the bottom of the MPLS label stack
			// -> save the size and exit the loop:
			label_stack_size = i + 1;
			break;
		} else if (i == MAX_MPLS_LABELS - 1) {
			// More MPLS labels are left but this is the last iteration
			// -> abort:
			return RX_MALFORMED_ACTION;
		}
	}

	// Remove the MPLS label stack:
	struct ethhdr eth_cpy;
	__builtin_memcpy(&eth_cpy, eth, sizeof(eth_cpy));
	int ret = bpf_xdp_adjust_head(
		ctx, label_stack_size * (int)sizeof(struct mpls_label));
	if (ret) {
		return XDP_DROP; // Something went wrong
	}
	cursor.start = (void *)(long)ctx->data;
	cursor.end = (void *)(long)ctx->data_end;
	cursor.pos = cursor.start;
	parse_header_or(eth, cursor)
	{
		return XDP_DROP; // Drop the now invalid packet (partially modified)
	}
	__builtin_memcpy(eth, &eth_cpy, sizeof(eth_cpy));
	// We assume that an IP header comes next:
	eth->h_proto = bpf_htons(ETH_P_IP);

	return XDP_PASS; // Successfully decapsulated the packet
}

static char _license[] SEC("license") = "GPL";
