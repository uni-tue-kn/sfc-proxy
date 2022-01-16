#ifndef CUSTOM_HELPERS_H
#define CUSTOM_HELPERS_H

// Header cursor (to simplify parsing)
struct hdr_cursor {
	void *start; // Start of the packet
	void *end; // End of the packet
	void *pos; // Current parsing position (next header)
};

// Helper macro for parsing packet headers
#define parse_header_or(hdr, cursor)                                           \
	hdr = cursor.pos;                                                      \
	cursor.pos = (void *)(hdr + 1);                                        \
	if (cursor.pos > cursor.end)

#endif // CUSTOM_HELPERS_H
