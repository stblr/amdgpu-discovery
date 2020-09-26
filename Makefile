CFLAGS = -Wall -Wextra -Wpedantic -Wstrict-aliasing -O3

all: amdgpu-discovery

amdgpu-discovery: main.c
	$(CC) $(CFLAGS) $^ -o $@
