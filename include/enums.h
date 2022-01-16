// Contains enums for the "control plane". This information is relevant for both the eBPF
// programs running in the kernel and the user space application that communicates with them.

enum stats {
	RX_MALFORMED, // Invalid packets that are ignored but accepted
	RX_IGNORED, // Packets that don't match the rules
	RX_TOO_BIG, // Too many MPLS labels
	RX_COLLISION, // Dropped due to a key collision
	RX_SUCCESS, // Successfully decapsulated
	TX_MALFORMED, // Invalid packets that are ignored but accepted
	TX_IGNORED, // Packets that don't match the rules
	TX_NOT_CACHED, // A matching packet without a cached header (could also be a locally generated packet)
	TX_NOT_MODIFIED, // No MPLS labels where left to push (accepted but nothing to do)
	TX_SUCCESS, // Successfully encapsulated
	ERROR, // Should always remain zero (a program error counter)
	STATS_SIZE // Hack to get the number of elements
};

static const char *stats_names[] = {
	"RX_MALFORMED",	   "RX_IGNORED",   "RX_TOO_BIG", "RX_COLLISION",
	"RX_SUCCESS",	   "TX_MALFORMED", "TX_IGNORED", "TX_NOT_CACHED",
	"TX_NOT_MODIFIED", "TX_SUCCESS",   "ERROR"
};
