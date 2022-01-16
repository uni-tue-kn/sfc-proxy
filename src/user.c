#include <argp.h>
#include <asm/unistd_64.h>
#include <errno.h>
#include <linux/bpf.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../include/enums.h"
#include "../include/config.h"

/*********************************************************************************
 * Copied only relevant needed libbpf helpers from mini library
 * found: https://elixir.bootlin.com/linux/v4.4/source/samples/bpf/libbpf.h#L19
 *********************************************************************************/

static unsigned long ptr_to_u64(const void *ptr)
{
	return (unsigned long)ptr;
}

static inline long sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr,
			   unsigned int size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}

long bpf_obj_get(const char *pathname);
long bpf_map_update_elem(unsigned int fd, void *key, void *value,
			 unsigned long long flags);
long bpf_map_lookup_elem(unsigned int fd, void *key, void *value);

long bpf_obj_get(const char *pathname)
{
	union bpf_attr attr;

	bzero(&attr, sizeof(attr));
	attr.pathname = ptr_to_u64((const void *)pathname);

	return sys_bpf(BPF_OBJ_GET, &attr, sizeof(attr));
}

long bpf_map_update_elem(unsigned int fd, void *key, void *value,
			 unsigned long long flags)
{
	union bpf_attr attr;

	bzero(&attr, sizeof(attr));
	attr.map_fd = fd;
	attr.key = ptr_to_u64(key);
	attr.value = ptr_to_u64(value);
	attr.flags = flags;

	return sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

long bpf_map_lookup_elem(unsigned int fd, void *key, void *value)
{
	union bpf_attr attr;

	bzero(&attr, sizeof(attr));
	attr.map_fd = fd;
	attr.key = ptr_to_u64(key);
	attr.value = ptr_to_u64(value);

	return sys_bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

/*********************************************************************************/

/**
 * When PIN_GLOBAL_NS is used, this is deafult global namespace that is loaded.
 */
static const char *TC_GLOBAL_NS = "/sys/fs/bpf/tc/globals";

static const char *BPF_CONFIG_MAP_NAME = "CONFIG_MAP";
#ifndef NO_STATS
static const char *BPF_STATS_MAP_NAME = "STATS_MAP";
#endif // !NO_STATS

/* Program documentation. */
const char *argp_program_version = "SFC proxy 1.0";
static char doc[] = "SFC proxy user control program.";

/* A description of the arguments we accept. */
static char args_doc[] = "[show] [disable|enable]";

/*
   OPTIONS.  Field 1 in ARGP.
   Order of fields: {NAME, KEY, ARG, FLAGS, DOC}.
*/
static struct argp_option options[] = {
	{ 0, 0, 0, 0, 0, 0 },
};

/* This structure is used by main to communicate with parse_opt. */
struct arguments {
	void (*cmd)(void);
};

void show(void);
void show_json(void);
void disable(void);
void enable(void);
long get_map_fd(const char *BPF_MAP_NAME);

long get_map_fd(const char *BPF_MAP_NAME)
{
	char pinned_file[256];
	snprintf(pinned_file, sizeof(pinned_file), "%s/%s", TC_GLOBAL_NS,
		 BPF_MAP_NAME);
	long fd = bpf_obj_get(pinned_file);
	if (fd < 0) {
		fprintf(stderr, "could not find map %s [%s].\n", BPF_MAP_NAME,
			strerror(errno));
		exit(1);
	}
	return fd;
}

void show(void)
{
	// Config:
	printf("Static configuration:\n");
	printf("- MAX_MPLS_LABELS: %i\n", MAX_MPLS_LABELS);
	printf("- POP_MPLS_LABELS_COUNT: %i\n", POP_MPLS_LABELS_COUNT);
#ifdef NO_DEBUG
	printf("- NO_DEBUG: true\n");
#else // NO_DEBUG
	printf("- NO_DEBUG: false\n");
#endif // NO_DEBUG
#ifdef NO_STATS
	printf("- NO_STATS: true\n");
#else // NO_STATS
	printf("- NO_STATS: false\n");
#endif // NO_STATS
	printf("Dynamic configuration:\n");
#ifndef NO_DEBUG
	long fd = get_map_fd(BPF_CONFIG_MAP_NAME);

	bool value = false;
	int index = 0;
	long ret = bpf_map_lookup_elem((unsigned int)fd, &index, &value);
	if (ret != 0) {
		fprintf(stderr, "- Could not lookup value [%s].\n",
			strerror(errno));
	} else {
		printf("- Debug: %s\n", value ? "true" : "false");
	}
#endif // NO_DEBUG

#ifndef NO_STATS
	// Stats:
	printf("Statistics:\n");
	const long stats_map_fd = get_map_fd(BPF_STATS_MAP_NAME);

	for (int i = 0; i < STATS_SIZE; ++i) {
		long v = -1;
		long r =
			bpf_map_lookup_elem((unsigned int)stats_map_fd, &i, &v);
		if (r != 0) {
			fprintf(stderr, "- Could not lookup value [%s].\n",
				strerror(errno));
		} else {
			printf("- %s: %li\n", stats_names[i], v);
		}
	}
#endif // !NO_STATS
}

void show_json(void)
{
	// Our data is simple enough not to require an external dependency on a
	// JSON library. This approach is a hack though...

	printf("{\n");
	printf("  \"static_configuration\": {\n");
	printf("    \"MAX_MPLS_LABELS\": %i,\n", MAX_MPLS_LABELS);
	printf("    \"POP_MPLS_LABELS_COUNT\": %i,\n", POP_MPLS_LABELS_COUNT);
#ifdef NO_DEBUG
	printf("    \"NO_DEBUG\": true,\n");
#else // NO_DEBUG
	printf("    \"NO_DEBUG\": false,\n");
#endif // NO_DEBUG
#ifdef NO_STATS
	printf("    \"NO_STATS\": true\n");
#else // NO_STATS
	printf("    \"NO_STATS\": false\n");
#endif // NO_STATS
	printf("  },\n");
	printf("  \"dynamic_configuration\": {\n");
#ifndef NO_DEBUG
	long config_map_fd = get_map_fd(BPF_CONFIG_MAP_NAME);
	bool debug = false;
	int debug_index = 0;
	long ret = bpf_map_lookup_elem((unsigned int)config_map_fd,
				       &debug_index, &debug);
	if (ret != 0) {
		fprintf(stderr, "Error: Could not lookup value [%s].\n",
			strerror(errno));
		exit(1);
	}
	printf("    \"debug\": %s\n", debug ? "true" : "false");
#endif // NO_DEBUG

#ifndef NO_STATS
	printf("  },\n");
	printf("  \"statistics\": {\n");
	const long stats_map_fd = get_map_fd(BPF_STATS_MAP_NAME);
	for (int i = 0; i < STATS_SIZE; ++i) {
		long v = -1;
		long r =
			bpf_map_lookup_elem((unsigned int)stats_map_fd, &i, &v);
		if (r != 0) {
			fprintf(stderr, "Error: Could not lookup value [%s].\n",
				strerror(errno));
			exit(1);
		}
		char comma[] = ",";
		if (i == STATS_SIZE - 1) {
			comma[0] = '\0';
		}
		printf("    \"%s\": %li%s\n", stats_names[i], v, comma);
	}
#endif // !NO_STATS
	printf("  }\n");
	printf("}\n");
}

void disable(void)
{
	long fd = get_map_fd(BPF_CONFIG_MAP_NAME);
	int index = 0;
	bool value = false;
	long ret =
		bpf_map_update_elem((unsigned int)fd, &index, &value, BPF_ANY);
	if (ret != 0) {
		fprintf(stderr, "Could not update element [%ld] [%s].\n", ret,
			strerror(errno));
	} else {
		printf("Successfully disabled.\n");
	}
}

void enable(void)
{
	long fd = get_map_fd(BPF_CONFIG_MAP_NAME);
	bool value = true;
	int index = 0;
	long ret =
		bpf_map_update_elem((unsigned int)fd, &index, &value, BPF_ANY);
	if (ret != 0) {
		fprintf(stderr, "Could not update element [%ld] [%s].\n", ret,
			strerror(errno));
	} else {
		printf("Successfully enabled.\n");
	}
}

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	/* Get the input argument from argp_parse, which we
	 know is a pointer to our arguments structure. */
	struct arguments *arguments = state->input;
	switch (key) {
	case ARGP_KEY_NO_ARGS:
		argp_usage(state);
		break;
	case ARGP_KEY_ARG:
		if (strcmp(arg, "show") == 0) {
			if (isatty(STDOUT_FILENO) == 0) {
				arguments->cmd = &show_json;
			} else {
				arguments->cmd = &show;
			}
		} else if (strcmp(arg, "disable") == 0) {
			arguments->cmd = &disable;
		} else if (strcmp(arg, "enable") == 0) {
			arguments->cmd = &enable;
		} else {
			argp_error(state, "%s is not a valid command", arg);
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

/* Our argp parser. */
static struct argp argp = { options, parse_opt, args_doc, doc, 0, 0, 0 };

int main(int argc, char **argv)
{
	struct arguments arguments;
	arguments.cmd = NULL;
	/* Where the magic happens */
	argp_parse(&argp, argc, argv, 0, 0, &arguments);
	if (arguments.cmd != NULL) {
		void (*cmd)(void) = arguments.cmd;
		(*cmd)();
	}
}
