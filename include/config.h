// Macros for configuring the program behaviour

// MPLS header caching macros:

// We limit the size of the MPLS label stack. This isn't a problem because the
// rest of the testbed is already limited to 10 labels as well (Menth20e.pdf):
#ifndef MAX_MPLS_LABELS
#define MAX_MPLS_LABELS 10
#endif
// How many MPLS labels to pop.
// Must be an integer x so that 0 <= x <= MAX_MPLS_LABELS:
#ifndef POP_MPLS_LABELS_COUNT
#define POP_MPLS_LABELS_COUNT 0
#endif
// Size of the eBPF map for the header cache (number of elements). The optimal
// size depends on parameters like the bandwidth and size of the VNF's queue.
#ifndef HEADER_CACHE_MAP_SIZE
#define HEADER_CACHE_MAP_SIZE 100000
#endif

// Drop packets in case of any parsing errors, cache misses, etc.:
#define STRICT_MODE

// When the following macro is enabled, a unique key will be generated and
// stored via metadata associated to the packet (xdp_md->data_meta and
// __sk_buff->data_meta):
// #define USE_PKG_METADATA

// Performance tuning macros:

//#define NO_DEBUG // To completely disable debugging support
//#define NO_STATS // To disable the stats counters

// Macros for testing purposes only:

//#define SKIP_STORING_LABEL_STACK
//#define SKIP_LOADING_LABEL_STACK
//#define SKIP_DELETING_LABEL_STACK
// A temporary hack to avoid the slow tc-mpls decapsulation:
//#define REMOVE_LABEL_STACK_AFTER_ADDING_IT
