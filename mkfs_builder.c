// Build: gcc -O2 -std=c17 -Wall -Wextra mkfs_minivsfs.c -o mkfs_builder
#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include <time.h>
#include <assert.h>
#include <unistd.h>
#include <getopt.h>

#define BS 4096u               // block size
#define INODE_SIZE 128u
#define ROOT_INO 1u
#define MAGIC 0x4D565346       // MiniVSFS magic number
#define VERSION 1

uint64_t g_random_seed = 0; // This should be replaced by seed value from the CLI.

// Command line options
typedef struct {
    char *image_name;
    uint64_t size_kib;
    uint64_t inodes;
} options_t;

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t block_size;
    uint64_t total_blocks;
    uint64_t inode_count;
    uint64_t inode_bitmap_start;
    uint64_t inode_bitmap_blocks;
    uint64_t data_bitmap_start;
    uint64_t data_bitmap_blocks;
    uint64_t inode_table_start;
    uint64_t inode_table_blocks;
    uint64_t data_region_start;
    uint64_t data_region_blocks;
    uint64_t root_inode;
    uint64_t mtime_epoch;
    uint32_t flags;
    uint32_t checksum;            // crc32(superblock[0..4091])
} superblock_t;
#pragma pack(pop)
_Static_assert(sizeof(superblock_t) == 116, "superblock must fit in one block");

#pragma pack(push,1)
typedef struct {
    uint16_t mode;
    uint16_t links;
    uint32_t uid;
    uint32_t gid;
    uint64_t size_bytes;
    uint64_t atime;
    uint64_t mtime;
    uint64_t ctime;
    uint32_t direct[12];
    uint32_t reserved_0;
    uint32_t reserved_1;
    uint32_t reserved_2;
    uint32_t proj_id;
    uint32_t uid16_gid16;
    uint64_t xattr_ptr;
    uint64_t inode_crc;   // low 4 bytes store crc32 of bytes [0..119]; high 4 bytes 0
} inode_t;
#pragma pack(pop)
_Static_assert(sizeof(inode_t)==INODE_SIZE, "inode size mismatch");

#pragma pack(push,1)
typedef struct {
    uint32_t inode_no;
    uint8_t type;
    char name[58];
    uint8_t  checksum; // XOR of bytes 0..62
} dirent64_t;
#pragma pack(pop)
_Static_assert(sizeof(dirent64_t)==64, "dirent size mismatch");


// ==========================DO NOT CHANGE THIS PORTION=========================
// These functions are there for your help. You should refer to the specifications to see how you can use them.
// ====================================CRC32====================================
uint32_t CRC32_TAB[256];
void crc32_init(void){
    for (uint32_t i=0;i<256;i++){
        uint32_t c=i;
        for(int j=0;j<8;j++) c = (c&1)?(0xEDB88320u^(c>>1)):(c>>1);
        CRC32_TAB[i]=c;
    }
}
uint32_t crc32(const void* data, size_t n){
    const uint8_t* p=(const uint8_t*)data; uint32_t c=0xFFFFFFFFu;
    for(size_t i=0;i<n;i++) c = CRC32_TAB[(c^p[i])&0xFF] ^ (c>>8);
    return c ^ 0xFFFFFFFFu;
}
// ====================================CRC32====================================

// WARNING: CALL THIS ONLY AFTER ALL OTHER SUPERBLOCK ELEMENTS HAVE BEEN FINALIZED
static uint32_t superblock_crc_finalize(superblock_t *sb) {
    sb->checksum = 0;
    uint32_t s = crc32((void *) sb, BS - 4);
    sb->checksum = s;
    return s;
}

// WARNING: CALL THIS ONLY AFTER ALL OTHER SUPERBLOCK ELEMENTS HAVE BEEN FINALIZED
void inode_crc_finalize(inode_t* ino){
    uint8_t tmp[INODE_SIZE]; memcpy(tmp, ino, INODE_SIZE);
    // zero crc area before computing
    memset(&tmp[120], 0, 8);
    uint32_t c = crc32(tmp, 120);
    ino->inode_crc = (uint64_t)c; // low 4 bytes carry the crc
}

// WARNING: CALL THIS ONLY AFTER ALL OTHER SUPERBLOCK ELEMENTS HAVE BEEN FINALIZED
void dirent_checksum_finalize(dirent64_t* de) {
    const uint8_t* p = (const uint8_t*)de;
    uint8_t x = 0;
    for (int i = 0; i < 63; i++) x ^= p[i];   // covers ino(4) + type(1) + name(58)
    de->checksum = x;
}

// Function to parse command line arguments
int parse_arguments(int argc, char *argv[], options_t *opts) {
    static struct option long_options[] = {
        {"image", required_argument, 0, 'i'},
        {"size-kib", required_argument, 0, 's'},
        {"inodes", required_argument, 0, 'n'},
        {0, 0, 0, 0}
    };
    
    int opt;
    int option_index = 0;
    
    while ((opt = getopt_long(argc, argv, "i:s:n:", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'i':
                opts->image_name = optarg;
                break;
            case 's':
                opts->size_kib = strtoul(optarg, NULL, 10);
                if (opts->size_kib < 180 || opts->size_kib > 4096 || (opts->size_kib % 4 != 0)) {
                    fprintf(stderr, "Error: size-kib must be between 180 and 4096 and a multiple of 4\n");
                    return -1;
                }
                break;
            case 'n':
                opts->inodes = strtoul(optarg, NULL, 10);
                if (opts->inodes < 128 || opts->inodes > 512) {
                    fprintf(stderr, "Error: inodes must be between 128 and 512\n");
                    return -1;
                }
                break;
            default:
                fprintf(stderr, "Usage: %s --image <filename> --size-kib <size> --inodes <count>\n", argv[0]);
                return -1;
        }
    }
    
    if (!opts->image_name || !opts->size_kib || !opts->inodes) {
        fprintf(stderr, "Error: All arguments are required\n");
        fprintf(stderr, "Usage: %s --image <filename> --size-kib <size> --inodes <count>\n", argv[0]);
        return -1;
    }
    
    return 0;
}

// Function to initialize the superblock
void init_superblock(superblock_t *sb, options_t *opts) {
    uint64_t total_blocks = opts->size_kib * 1024 / BS;
    uint64_t inode_table_blocks = (opts->inodes * INODE_SIZE + BS - 1) / BS;
    
    sb->magic = MAGIC;
    sb->version = VERSION;
    sb->block_size = BS;
    sb->total_blocks = total_blocks;
    sb->inode_count = opts->inodes;
    sb->inode_bitmap_start = 1;
    sb->inode_bitmap_blocks = 1;
    sb->data_bitmap_start = 2;
    sb->data_bitmap_blocks = 1;
    sb->inode_table_start = 3;
    sb->inode_table_blocks = inode_table_blocks;
    sb->data_region_start = 3 + inode_table_blocks;
    sb->data_region_blocks = total_blocks - sb->data_region_start;
    sb->root_inode = ROOT_INO;
    sb->mtime_epoch = time(NULL);
    sb->flags = 0;
}

// Function to initialize the root inode
void init_root_inode(inode_t *inode) {
    inode->mode = 0040000;  // Directory
    inode->links = 2;       // . and ..
    inode->uid = 0;
    inode->gid = 0;
    inode->size_bytes = BS; // One block for directory entries
    inode->atime = time(NULL);
    inode->mtime = time(NULL);
    inode->ctime = time(NULL);
    inode->direct[0] = 3;   // First data block (after inode table)
    for (int i = 1; i < 12; i++) {
        inode->direct[i] = 0;  // Unused
    }
    inode->reserved_0 = 0;
    inode->reserved_1 = 0;
    inode->reserved_2 = 0;
    inode->proj_id = 7;     // Your group ID
    inode->uid16_gid16 = 0;
    inode->xattr_ptr = 0;
}

// Function to initialize directory entries for root
void init_root_dirents(dirent64_t *entries) {
    // Entry for "."
    entries[0].inode_no = ROOT_INO;
    entries[0].type = 2;  // Directory
    strncpy(entries[0].name, ".", sizeof(entries[0].name));
    dirent_checksum_finalize(&entries[0]);
    
    // Entry for ".."
    entries[1].inode_no = ROOT_INO;
    entries[1].type = 2;  // Directory
    strncpy(entries[1].name, "..", sizeof(entries[1].name));
    dirent_checksum_finalize(&entries[1]);
    
    // Calculate the number of directory entries per block
    size_t entries_per_block = BS / sizeof(dirent64_t);
    
    // Mark remaining entries as free
    for (size_t i = 2; i < entries_per_block; i++) {
        entries[i].inode_no = 0;
        entries[i].type = 0;
        memset(entries[i].name, 0, sizeof(entries[i].name));
        entries[i].checksum = 0;
    }
}

int main(int argc, char *argv[]) {
    crc32_init();
    
    // Parse command line arguments
    options_t opts = {0};
    if (parse_arguments(argc, argv, &opts) != 0) {
        return EXIT_FAILURE;
    }
    
    // Calculate sizes
    uint64_t total_blocks = opts.size_kib * 1024 / BS;
    uint64_t inode_table_blocks = (opts.inodes * INODE_SIZE + BS - 1) / BS;
    uint64_t data_region_start = 3 + inode_table_blocks;
    
    // Validate that we have enough space
    if (data_region_start >= total_blocks) {
        fprintf(stderr, "Error: Not enough space for file system structures\n");
        return EXIT_FAILURE;
    }
    
    // Allocate memory for the image
    size_t image_size = total_blocks * BS;
    uint8_t *image = calloc(1, image_size);
    if (!image) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        return EXIT_FAILURE;
    }
    
    // Initialize superblock
    superblock_t *sb = (superblock_t *)image;
    init_superblock(sb, &opts);
    superblock_crc_finalize(sb);
    
    // Initialize inode bitmap (mark inode 1 as used)
    uint8_t *inode_bitmap = image + BS;
    inode_bitmap[0] = 0x01;  // First bit set for inode 1
    
    // Initialize data bitmap (mark first data block as used)
    uint8_t *data_bitmap = image + 2 * BS;
    data_bitmap[0] = 0x01;   // First bit set for data block 0
    
    // Initialize inode table
    inode_t *inode_table = (inode_t *)(image + 3 * BS);
    init_root_inode(&inode_table[0]);  // Root inode at index 0 (inode number 1)
    inode_crc_finalize(&inode_table[0]);
    
    // Initialize root directory data block
    dirent64_t *root_dir = (dirent64_t *)(image + data_region_start * BS);
    init_root_dirents(root_dir);
    
    // Write image to file
    FILE *fp = fopen(opts.image_name, "wb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot create output file %s\n", opts.image_name);
        free(image);
        return EXIT_FAILURE;
    }
    
    if (fwrite(image, 1, image_size, fp) != image_size) {
        fprintf(stderr, "Error: Writing to output file failed\n");
        fclose(fp);
        free(image);
        return EXIT_FAILURE;
    }
    
    fclose(fp);
    free(image);
    
    printf("MiniVSFS image created successfully: %s\n", opts.image_name);
    printf("Size: %" PRIu64 " KiB, Inodes: %" PRIu64 ", Blocks: %" PRIu64 "\n", 
           opts.size_kib, opts.inodes, total_blocks);
    
    return 0;
}
