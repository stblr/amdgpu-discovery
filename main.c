#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;

static bool read_file(const char *path, size_t *size, u8 **data) {
        bool ret = false;

        FILE *input = fopen(path, "r");
        if (!input) {
                return ret;
        }

        if (fseek(input, 0, SEEK_END)) {
                goto cleanup;
        }

        long pos = ftell(input);
        if (pos < 0) {
                goto cleanup;
        }
        *size = pos; // FIXME possible overflow if sizeof(size_t) < sizeof(long)

        if (fseek(input, 0, SEEK_SET)) {
                goto cleanup;
        }

        *data = malloc(*size * sizeof(u8));
        if (!*data) {
                goto cleanup;
        }

        if (fread(*data, sizeof(u8), *size, input) != *size) {
                goto cleanup;
        }

        ret = true;

cleanup:
        fclose(input);

        return ret;
}

struct binary_header {
        u32 binary_signature;
        u16 version_major;
        u16 version_minor;
        u16 binary_checksum;
        u16 binary_size;
        struct {
                u16 offset;
                u16 checksum;
                u16 size;
                u16 padding;
        } table_list[6];
};

static void print_binary_header(struct binary_header hdr) {
        printf("binary_signature: 0x%08x\n", hdr.binary_signature);
        printf("version_major: %u\n", hdr.version_major);
        printf("version_minor: %u\n", hdr.version_minor);
        printf("binary_checksum: %u\n", hdr.binary_checksum);
        printf("binary_size: %u\n", hdr.binary_size);
        for (u8 i = 0; i < 6; i++) {
                if (hdr.table_list[i].offset == 0) {
                        continue;
                }
                printf("table_list[%u]:\n", i);
                printf("    offset: %u\n", hdr.table_list[i].offset);
                printf("    checksum: 0x%04x\n", hdr.table_list[i].checksum);
                printf("    size: %u\n", hdr.table_list[i].size);
        }
        printf("\n");
}

struct ip_discovery_header {
        u32 signature;
        u16 version;
        u16 size;
        u32 id;
        u16 num_dies;
        struct {
                u16 die_id;
                u16 die_offset;
        } die_info[16];
        u16 padding;
};

static void print_ip_discovery_header(struct ip_discovery_header hdr) {
        printf("signature: %u\n", hdr.signature);
        printf("version: %u\n", hdr.version);
        printf("size: %u\n", hdr.size);
        printf("id: %u\n", hdr.id);
        printf("num_dies: %u\n", hdr.num_dies);
        if (hdr.num_dies != 1) {
                return;
        }
        printf("die_id: %u\n", hdr.die_info[0].die_id);
        printf("die_offset: %u\n", hdr.die_info[0].die_offset);
        printf("\n");
}

struct die_header {
        u16 die_id;
        u16 num_ips;
};

static void print_die_header(struct die_header hdr) {
        printf("die_id: %u\n", hdr.die_id);
        printf("num_ips: %u\n", hdr.num_ips);
        printf("\n");
}

struct ip {
        u16 hw_id;
        u8 number_instance;
        u8 num_base_address;
        u8 major;
        u8 minor;
        u8 revision;
        u8 harvest : 4;
        u8 reserved : 4;
        u32 base_address[1];
};

static void print_ip(struct ip ip) {
        printf("hw_id: %u\n", ip.hw_id);
        printf("number_instance: %u\n", ip.number_instance);
        printf("version: %u.%u.%u\n", ip.major, ip.minor, ip.revision);
        printf("harvest: %u\n", ip.harvest);
        printf("\n");
}

struct gc_info_header {
        u32 table_id;
        u16 version_major;
        u16 version_minor;
        u32 size;
};

static void print_gc_info_header(struct gc_info_header hdr) {
        printf("table_id: %u\n", hdr.table_id);
        printf("version_major: %u\n", hdr.version_major);
        printf("version_minor: %u\n", hdr.version_minor);
        printf("size: %u\n", hdr.size);
}

struct gc_info_v1_0 {
        struct gc_info_header header;
        u32 num_se;
        u32 num_wgp0_per_sa;
        u32 num_wgp1_per_sa;
        u32 num_rb_per_se;
        u32 num_gl2c;
        u32 num_gprs;
        u32 num_max_gs_thds;
        u32 gs_table_depth;
        u32 gsprim_buff_depth;
        u32 parameter_cache_depth;
        u32 double_offchip_lds_buffer;
        u32 wave_size;
        u32 max_waves_per_simd;
        u32 max_scratch_slots_per_cu;
        u32 lds_size;
        u32 num_sc_per_se;
        u32 num_sa_per_se;
        u32 num_packer_per_sc;
        u32 num_gl2a;
};

static void print_gc_info_v1_0(struct gc_info_v1_0 gc_info) {
        print_gc_info_header(gc_info.header);
        printf("num_se: %u\n", gc_info.num_se);
        printf("num_wgp0_per_sa: %u\n", gc_info.num_wgp0_per_sa);
        printf("num_wgp1_per_sa: %u\n", gc_info.num_wgp1_per_sa);
        printf("num_rb_per_se: %u\n", gc_info.num_rb_per_se);
        printf("num_gl2c: %u\n", gc_info.num_gl2c);
        printf("num_gprs: %u\n", gc_info.num_gprs);
        printf("num_max_gs_thds: %u\n", gc_info.num_max_gs_thds);
        printf("gs_table_depth: %u\n", gc_info.gs_table_depth);
        printf("gsprim_buff_depth: %u\n", gc_info.gsprim_buff_depth);
        printf("parameter_cache_depth: %u\n", gc_info.parameter_cache_depth);
        printf("double_offchip_lds_buffer: %u\n", gc_info.double_offchip_lds_buffer);
        printf("wave_size: %u\n", gc_info.wave_size);
        printf("max_waves_per_simd: %u\n", gc_info.max_waves_per_simd);
        printf("max_scratch_slots_per_cu: %u\n", gc_info.max_scratch_slots_per_cu);
        printf("lds_size: %u\n", gc_info.lds_size);
        printf("num_sc_per_se: %u\n", gc_info.num_sc_per_se);
        printf("num_sa_per_se: %u\n", gc_info.num_sa_per_se);
        printf("num_packer_per_sc: %u\n", gc_info.num_packer_per_sc);
        printf("num_gl2a: %u\n", gc_info.num_gl2a);
        u32 num_cus = 2 * (gc_info.num_wgp0_per_sa + gc_info.num_wgp1_per_sa) * 
                      gc_info.num_sa_per_se * gc_info.num_se;
        printf("num_cus (computed): %u\n", num_cus);
}

struct gc_info_v1_1 {
        struct gc_info_v1_0 v1_0;
        u32 unknown0; // num_cu_per_sa?
        u32 unknown1; // == num_gl2c?
        u32 unknown2; // num_cus?
};

static void print_gc_info_v1_1(struct gc_info_v1_1 gc_info) {
        print_gc_info_v1_0(gc_info.v1_0);
        printf("unknown0: %u\n", gc_info.unknown0);
        printf("unknown1: %u\n", gc_info.unknown1);
        printf("unknown2: %u\n", gc_info.unknown2);
}

struct gc_info_v2_0 {
        struct gc_info_header header;
        u32 num_se;
        u32 num_cu_per_sh;
        u32 num_sh_per_se;
        u32 num_rb_per_se;
        u32 num_tccs; // same as gl2c
        u32 num_gprs;
        u32 num_max_gs_thds;
        u32 gs_table_depth;
        u32 gsprim_buff_depth;
        u32 parameter_cache_depth;
        u32 double_offchip_lds_buffer;
        u32 wave_size;
        u32 max_waves_per_simd;
        u32 max_scratch_slots_per_cu;
        u32 lds_size;
        u32 num_sc_per_sh;
        u32 num_packer_per_sc;
};

static void print_gc_info_v2_0(struct gc_info_v2_0 gc_info) {
        print_gc_info_header(gc_info.header);
        printf("num_se: %u\n", gc_info.num_se);
        printf("num_cu_per_sh: %u\n", gc_info.num_cu_per_sh);
        printf("num_sh_per_se: %u\n", gc_info.num_sh_per_se);
        printf("num_rb_per_se: %u\n", gc_info.num_rb_per_se);
        printf("num_tccs: %u\n", gc_info.num_tccs);
        printf("num_gprs: %u\n", gc_info.num_gprs);
        printf("num_max_gs_thds: %u\n", gc_info.num_max_gs_thds);
        printf("gs_table_depth: %u\n", gc_info.gs_table_depth);
        printf("gsprim_buff_depth: %u\n", gc_info.gsprim_buff_depth);
        printf("parameter_cache_depth: %u\n", gc_info.parameter_cache_depth);
        printf("double_offchip_lds_buffer: %u\n", gc_info.double_offchip_lds_buffer);
        printf("wave_size: %u\n", gc_info.wave_size);
        printf("max_waves_per_simd: %u\n", gc_info.max_waves_per_simd);
        printf("max_scratch_slots_per_cu: %u\n", gc_info.max_scratch_slots_per_cu);
        printf("lds_size: %u\n", gc_info.lds_size);
        printf("num_sc_per_sh: %u\n", gc_info.num_sc_per_sh);
        printf("num_packer_per_sc: %u\n", gc_info.num_packer_per_sc);
        u32 num_cus = gc_info.num_cu_per_sh * gc_info.num_sh_per_se * gc_info.num_se;
        printf("num_cus (computed): %u\n", num_cus);
}

int main(int argc, char **argv) {
        int ret = 1;

        if (argc != 2) {
                return ret;
        }

        size_t size;
        u8 *data = NULL;
        if (!read_file(argv[1], &size, &data)) {
                goto cleanup;
        }

        if (size < sizeof(struct binary_header)) {
                goto cleanup;
        }

        struct binary_header hdr = *(struct binary_header *)data;
        print_binary_header(hdr);

        u16 ip_discovery_offset = hdr.table_list[0].offset;
        if (ip_discovery_offset == 0 ||
            (size_t)ip_discovery_offset + sizeof(struct ip_discovery_header) > size) {
                goto cleanup;
        }

        struct ip_discovery_header ip_discovery_header =
                *(struct ip_discovery_header *)(data + ip_discovery_offset);
        print_ip_discovery_header(ip_discovery_header);

        if (ip_discovery_header.num_dies != 1) {
                goto cleanup;
        }
        u16 die_offset = ip_discovery_header.die_info[0].die_offset;
        struct die_header die_header = *(struct die_header *)(data + die_offset);
        print_die_header(die_header);

        u16 ip_offset = die_offset + sizeof(struct die_header);
        for (u16 i = 0; i < die_header.num_ips; i++) {
                struct ip ip = *(struct ip *)(data + ip_offset);
                print_ip(ip);
                ip_offset += sizeof(struct ip) + 4 * (ip.num_base_address - 1);
        }

        size_t gc_info_offset = hdr.table_list[1].offset;
        if (gc_info_offset == 0 || gc_info_offset + sizeof(struct gc_info_header) > size) {
                goto cleanup;
        }

        u8 *gc_info_ptr = data + gc_info_offset;
        struct gc_info_header gc_info_header = *(struct gc_info_header *)gc_info_ptr;
        switch (gc_info_header.version_major) {
        case 1:
                switch (gc_info_header.version_minor) {
                case 0:
                        if (gc_info_offset + sizeof(struct gc_info_v1_0) > size) {
                                goto cleanup;
                        } else {
                                struct gc_info_v1_0 gc_info = *(struct gc_info_v1_0 *)gc_info_ptr;
                                print_gc_info_v1_0(gc_info);
                                break;
                        }
                case 1:
                        if (gc_info_offset + sizeof(struct gc_info_v1_1) > size) {
                                goto cleanup;
                        } else {
                                struct gc_info_v1_1 gc_info = *(struct gc_info_v1_1 *)gc_info_ptr;
                                print_gc_info_v1_1(gc_info);
                                break;
                        }
                }
                break;
        case 2:
                switch (gc_info_header.version_minor) {
                case 0:
                        if (gc_info_offset + sizeof(struct gc_info_v1_1) > size) {
                                goto cleanup;
                        } else {
                                struct gc_info_v2_0 gc_info = *(struct gc_info_v2_0 *)gc_info_ptr;
                                print_gc_info_v2_0(gc_info);
                                break;
                        }
                }
        }

        ret = 0;

cleanup:
        free(data);

        return ret;
}
