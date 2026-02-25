#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>

#define BS 4096u
#define INODE_SIZE 128u
#define ROOT_INO 1u
#define DIRECT_MAX 12
#define MAGIC 0x4D565346

// Command line options
typedef struct {
    char *input_name;
    char *output_name;
    char *file_name;
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
    uint32_t checksum;
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
    uint64_t inode_crc;
} inode_t;
#pragma pack(pop)
_Static_assert(sizeof(inode_t)==INODE_SIZE, "inode size mismatch");

#pragma pack(push,1)
typedef struct {
    uint32_t inode_no;
    uint8_t type;
    char name[58];
    uint8_t checksum;
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
        {"input", required_argument, 0, 'i'},
        {"output", required_argument, 0, 'o'},
        {"file", required_argument, 0, 'f'},
        {0, 0, 0, 0}
    };
    
    int opt;
    int option_index = 0;
    
    while ((opt = getopt_long(argc, argv, "i:o:f:", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'i':
                opts->input_name = optarg;
                break;
            case 'o':
                opts->output_name = optarg;
                break;
            case 'f':
                opts->file_name = optarg;
                break;
            default:
                fprintf(stderr, "Usage: %s --input <input.img> --output <output.img> --file <filename>\n", argv[0]);
                return -1;
        }
    }
    
    if (!opts->input_name || !opts->output_name || !opts->file_name) {
        fprintf(stderr, "Error: All arguments are required\n");
        fprintf(stderr, "Usage: %s --input <input.img> --output <output.img> --file <filename>\n", argv[0]);
        return -1;
    }
    
    return 0;
}

// Function to find a free inode
uint32_t find_free_inode(uint8_t *inode_bitmap, uint64_t inode_count) {
    for (uint32_t i = 0; i < inode_count / 8 + 1; i++) {
        if (inode_bitmap[i] != 0xFF) { // Not all bits are set
            for (int j = 0; j < 8; j++) {
                if (!(inode_bitmap[i] & (1 << j))) {
                    return i * 8 + j + 1; // Inodes are 1-indexed
                }
            }
        }
    }
    return 0; // No free inode found
}

// Function to find free data blocks
uint32_t find_free_data_blocks(uint8_t *data_bitmap, uint64_t data_blocks, int count) {
    for (uint32_t i = 0; i < data_blocks / 8 + 1; i++) {
        if (data_bitmap[i] != 0xFF) { // Not all bits are set
            for (int j = 0; j < 8; j++) {
                if (!(data_bitmap[i] & (1 << j))) {
                    // Check if we have enough consecutive blocks
                    int free_count = 1;
                    for (int k = 1; k < count; k++) {
                        if (i * 8 + j + k >= data_blocks) break;
                        int byte_idx = (i * 8 + j + k) / 8;
                        int bit_idx = (i * 8 + j + k) % 8;
                        if (data_bitmap[byte_idx] & (1 << bit_idx)) {
                            break;
                        }
                        free_count++;
                    }
                    
                    if (free_count >= count) {
                        return i * 8 + j;
                    }
                }
            }
        }
    }
    return 0; // No free blocks found
}

// Function to update bitmap
void set_bitmap_bits(uint8_t *bitmap, uint32_t start, int count) {
    for (int i = 0; i < count; i++) {
        uint32_t bit_pos = start + i;
        uint32_t byte_idx = bit_pos / 8;
        uint8_t bit_idx = bit_pos % 8;
        bitmap[byte_idx] |= (1 << bit_idx);
    }
}

int main(int argc, char *argv[]) {
    crc32_init();
    
    // Parse command line arguments
    options_t opts = {0};
    if (parse_arguments(argc, argv, &opts) != 0) {
        return EXIT_FAILURE;
    }
    
    // Open the input file
    FILE *input_fp = fopen(opts.input_name, "rb");
    if (!input_fp) {
        fprintf(stderr, "Error: Cannot open input file %s\n", opts.input_name);
        return EXIT_FAILURE;
    }
    
    // Get file size
    fseek(input_fp, 0, SEEK_END);
    size_t file_size = ftell(input_fp);
    fseek(input_fp, 0, SEEK_SET);
    
    // Read the entire file into memory
    uint8_t *image = malloc(file_size);
    if (!image) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        fclose(input_fp);
        return EXIT_FAILURE;
    }
    
    if (fread(image, 1, file_size, input_fp) != file_size) {
        fprintf(stderr, "Error: Reading input file failed\n");
        fclose(input_fp);
        free(image);
        return EXIT_FAILURE;
    }
    
    fclose(input_fp);
    
    // Validate the superblock
    superblock_t *sb = (superblock_t *)image;
    if (sb->magic != MAGIC) {
        fprintf(stderr, "Error: Invalid MiniVSFS image (bad magic number)\n");
        free(image);
        return EXIT_FAILURE;
    }
    
    // Open the file to be added
    FILE *file_fp = fopen(opts.file_name, "rb");
    if (!file_fp) {
        fprintf(stderr, "Error: Cannot open file %s\n", opts.file_name);
        free(image);
        return EXIT_FAILURE;
    }
    
    // Get file size
    fseek(file_fp, 0, SEEK_END);
    size_t file_to_add_size = ftell(file_fp);
    fseek(file_fp, 0, SEEK_SET);
    
    // Check if file is too large
    uint32_t blocks_needed = (file_to_add_size + BS - 1) / BS;
    if (blocks_needed > DIRECT_MAX) {
        fprintf(stderr, "Warning: File too large to be accommodated with direct blocks only\n");
        fclose(file_fp);
        free(image);
        return EXIT_FAILURE;
    }
    
    // Read file content
    uint8_t *file_content = malloc(file_to_add_size);
    if (!file_content) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        fclose(file_fp);
        free(image);
        return EXIT_FAILURE;
    }
    
    if (fread(file_content, 1, file_to_add_size, file_fp) != file_to_add_size) {
        fprintf(stderr, "Error: Reading file %s failed\n", opts.file_name);
        fclose(file_fp);
        free(image);
        free(file_content);
        return EXIT_FAILURE;
    }
    
    fclose(file_fp);
    
    // Find a free inode
    uint8_t *inode_bitmap = image + sb->inode_bitmap_start * BS;
    uint32_t free_inode = find_free_inode(inode_bitmap, sb->inode_count);
    if (!free_inode) {
        fprintf(stderr, "Error: No free inodes available\n");
        free(image);
        free(file_content);
        return EXIT_FAILURE;
    }
    
    // Find free data blocks
    uint8_t *data_bitmap = image + sb->data_bitmap_start * BS;
    uint32_t free_data_block = find_free_data_blocks(data_bitmap, sb->data_region_blocks, blocks_needed);
    if (!free_data_block) {
        fprintf(stderr, "Error: Not enough free data blocks\n");
        free(image);
        free(file_content);
        return EXIT_FAILURE;
    }
    
    // Update bitmaps
    set_bitmap_bits(inode_bitmap, free_inode - 1, 1); // Inodes are 1-indexed in bitmap
    set_bitmap_bits(data_bitmap, free_data_block, blocks_needed);
    
    // Create the new inode
    inode_t *inode_table = (inode_t *)(image + sb->inode_table_start * BS);
    inode_t *new_inode = &inode_table[free_inode - 1]; // Inodes are 1-indexed in table
    
    time_t now = time(NULL);
    new_inode->mode = 0100000;  // Regular file
    new_inode->links = 1;
    new_inode->uid = 0;
    new_inode->gid = 0;
    new_inode->size_bytes = file_to_add_size;
    new_inode->atime = now;
    new_inode->mtime = now;
    new_inode->ctime = now;
    
    // Set direct blocks
    for (uint32_t i = 0; i < blocks_needed; i++) {
        new_inode->direct[i] = sb->data_region_start + free_data_block + i;
    }
    for (uint32_t i = blocks_needed; i < DIRECT_MAX; i++) {
        new_inode->direct[i] = 0;
    }
    
    new_inode->reserved_0 = 0;
    new_inode->reserved_1 = 0;
    new_inode->reserved_2 = 0;
    new_inode->proj_id = 7; // Your group ID
    new_inode->uid16_gid16 = 0;
    new_inode->xattr_ptr = 0;
    
    inode_crc_finalize(new_inode);
    
    // Write file content to data blocks
    for (uint32_t i = 0; i < blocks_needed; i++) {
        uint32_t block_offset = (sb->data_region_start + free_data_block + i) * BS;
        size_t bytes_to_write = (i == blocks_needed - 1) ? 
            file_to_add_size - (i * BS) : BS;
        memcpy(image + block_offset, file_content + (i * BS), bytes_to_write);
    }
    
    // Add directory entry to root directory
    inode_t *root_inode = &inode_table[ROOT_INO - 1]; // Root inode is at index 0
    uint32_t root_data_block = root_inode->direct[0];
    dirent64_t *root_dir = (dirent64_t *)(image + root_data_block * BS);
    
    // Find a free directory entry
    size_t entries_per_block = BS / sizeof(dirent64_t);
    dirent64_t *free_entry = NULL;
    for (size_t i = 0; i < entries_per_block; i++) {
        if (root_dir[i].inode_no == 0) {
            free_entry = &root_dir[i];
            break;
        }
    }
    
    if (!free_entry) {
        fprintf(stderr, "Error: No space in root directory\n");
        free(image);
        free(file_content);
        return EXIT_FAILURE;
    }
    
    // Create the directory entry
    free_entry->inode_no = free_inode;
    free_entry->type = 1; // File
    strncpy(free_entry->name, opts.file_name, sizeof(free_entry->name));
    // Ensure null termination if filename is too long
    free_entry->name[sizeof(free_entry->name) - 1] = '\0';
    dirent_checksum_finalize(free_entry);
    
    // Update root directory size and timestamp
    root_inode->size_bytes += sizeof(dirent64_t);
    root_inode->mtime = now;
    root_inode->ctime = now;
    inode_crc_finalize(root_inode);
    
    // Update superblock timestamp
    sb->mtime_epoch = now;
    superblock_crc_finalize(sb);
    
    // Write the updated image to output file
    FILE *output_fp = fopen(opts.output_name, "wb");
    if (!output_fp) {
        fprintf(stderr, "Error: Cannot create output file %s\n", opts.output_name);
        free(image);
        free(file_content);
        return EXIT_FAILURE;
    }
    
    if (fwrite(image, 1, file_size, output_fp) != file_size) {
        fprintf(stderr, "Error: Writing to output file failed\n");
        fclose(output_fp);
        free(image);
        free(file_content);
        return EXIT_FAILURE;
    }
    
    fclose(output_fp);
    free(image);
    free(file_content);
    
    printf("File %s added successfully to inode %u\n", opts.file_name, free_inode);
    printf("Output image: %s\n", opts.output_name);
    
    return 0;
}
