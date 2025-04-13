/*
 * Test Input Generator for Complex Fuzzing Target
 *
 * This program generates valid input files for the complex_target
 * to be used as initial seeds for fuzzing.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

/* Define the maximum sizes for various components */
#define MAX_HEADER_SIZE 64
#define MAX_METADATA_SIZE 256
#define MAX_CONTENT_SIZE 8192
#define MAX_BUFFER_SIZE (MAX_HEADER_SIZE + MAX_METADATA_SIZE + MAX_CONTENT_SIZE)

/* File format magic values */
#define MAGIC_HEADER 0x4D4D5046  /* "MMPF" in hex */
#define FORMAT_VERSION 0x0100    /* Version 1.0 */

/* Content type identifiers */
#define TYPE_IMAGE 0x01
#define TYPE_AUDIO 0x02
#define TYPE_TEXT  0x03
#define TYPE_MIXED 0x04

/* Processing flags */
#define FLAG_COMPRESS 0x01
#define FLAG_ENCRYPT  0x02
#define FLAG_FILTER   0x04
#define FLAG_VALIDATE 0x08

/* File format header structure */
typedef struct {
    uint32_t magic;          /* Magic number to identify the file format */
    uint16_t version;        /* Format version */
    uint8_t  type;           /* Content type */
    uint8_t  flags;          /* Processing flags */
    uint32_t metadata_size;  /* Size of metadata section */
    uint32_t content_size;   /* Size of content section */
    uint32_t checksum;       /* Header checksum */
} FileHeader;

/* Metadata structure */
typedef struct {
    char     title[64];      /* Content title */
    char     author[64];     /* Content author */
    uint32_t created_time;   /* Creation timestamp */
    uint16_t width;          /* Width (for images) */
    uint16_t height;         /* Height (for images) */
    uint32_t duration;       /* Duration (for audio) */
    uint16_t channels;       /* Number of channels (for audio) */
    uint16_t sample_rate;    /* Sample rate (for audio) */
    uint32_t reserved[4];    /* Reserved for future use */
} Metadata;

/* Calculate a simple checksum */
uint32_t calculate_checksum(const void *data, size_t size) {
    const uint8_t *bytes = (const uint8_t *)data;
    uint32_t checksum = 0;

    for (size_t i = 0; i < size; i++) {
        checksum = ((checksum << 7) | (checksum >> 25)) + bytes[i];
    }

    return checksum;
}

/* Generate random data */
void generate_random_data(uint8_t *buffer, size_t size) {
    for (size_t i = 0; i < size; i++) {
        buffer[i] = rand() % 256;
    }
}

/* Generate an image content */
size_t generate_image_content(uint8_t *buffer, size_t max_size) {
    if (max_size < 100) return 0;

    /* First byte contains compression and filter type */
    buffer[0] = (rand() % 3) | ((rand() % 3) << 4);

    /* Generate some random image data */
    size_t content_size = 50 + rand() % (max_size - 50);
    generate_random_data(buffer + 1, content_size - 1);

    return content_size;
}

/* Generate audio content */
size_t generate_audio_content(uint8_t *buffer, size_t max_size) {
    if (max_size < 100) return 0;

    /* First byte contains audio format and effect type */
    buffer[0] = (rand() % 4) | ((rand() % 3) << 4);

    /* Generate some random audio data */
    size_t content_size = 50 + rand() % (max_size - 50);
    generate_random_data(buffer + 1, content_size - 1);

    return content_size;
}

/* Generate text content */
size_t generate_text_content(uint8_t *buffer, size_t max_size) {
    if (max_size < 100) return 0;

    /* First byte contains text format and processing type */
    buffer[0] = (rand() % 4) | ((rand() % 3) << 4);

    /* Generate some text data based on format */
    size_t content_size = 0;
    uint8_t format = buffer[0] & 0x0F;

    switch (format) {
        case 0: /* Plain text */
            {
                const char *sample_text = "This is a sample text for testing the complex target. "
                                         "It contains various words and characters to exercise "
                                         "different code paths in the text processing module.";
                size_t text_len = strlen(sample_text);
                content_size = 1 + text_len;
                if (content_size > max_size) content_size = max_size;
                memcpy(buffer + 1, sample_text, content_size - 1);
            }
            break;

        case 1: /* RLE compressed text */
            {
                /* Create a simple RLE sequence */
                content_size = 1;
                const char *chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
                size_t chars_len = strlen(chars);

                while (content_size + 2 < max_size) {
                    uint8_t count = 1 + rand() % 10;
                    uint8_t value = chars[rand() % chars_len];

                    buffer[content_size++] = count;
                    buffer[content_size++] = value;
                }
            }
            break;

        case 2: /* Markup language */
            {
                const char *markup_text = "<h1>Sample Document</h1>\n"
                                         "This is a <b>bold text</b> and this is <i>italic text</i>.\n"
                                         "<h2>Section 1</h2>\n"
                                         "This is a sample section with some content.\n"
                                         "<h2>Section 2</h2>\n"
                                         "This is another section with different content.";
                size_t text_len = strlen(markup_text);
                content_size = 1 + text_len;
                if (content_size > max_size) content_size = max_size;
                memcpy(buffer + 1, markup_text, content_size - 1);
            }
            break;

        case 3: /* Template language */
            {
                const char *template_text = "# {{title}}\n\n"
                                           "Author: {{author}}\n"
                                           "Version: {{version}}\n\n"
                                           "## Description\n\n"
                                           "{{description}}\n\n"
                                           "Created in {{year}}";
                size_t text_len = strlen(template_text);
                content_size = 1 + text_len;
                if (content_size > max_size) content_size = max_size;
                memcpy(buffer + 1, template_text, content_size - 1);
            }
            break;
    }

    return content_size;
}

/* Generate mixed content */
size_t generate_mixed_content(uint8_t *buffer, size_t max_size) {
    if (max_size < 100) return 0;

    size_t pos = 0;

    /* Generate 2-3 sections of different types */
    int num_sections = 2 + rand() % 2;

    for (int i = 0; i < num_sections && pos + 50 < max_size; i++) {
        /* Section type */
        uint8_t section_type = 1 + rand() % 3; /* IMAGE, AUDIO, or TEXT */
        buffer[pos++] = section_type;

        /* Reserve space for section size (4 bytes) */
        size_t size_pos = pos;
        pos += 4;

        /* Generate section content */
        size_t section_size = 0;
        size_t remaining = max_size - pos;

        switch (section_type) {
            case TYPE_IMAGE:
                section_size = generate_image_content(buffer + pos, remaining < 1000 ? remaining : 1000);
                break;

            case TYPE_AUDIO:
                section_size = generate_audio_content(buffer + pos, remaining < 1000 ? remaining : 1000);
                break;

            case TYPE_TEXT:
                section_size = generate_text_content(buffer + pos, remaining < 1000 ? remaining : 1000);
                break;
        }

        /* Write section size (little endian) */
        buffer[size_pos] = section_size & 0xFF;
        buffer[size_pos + 1] = (section_size >> 8) & 0xFF;
        buffer[size_pos + 2] = (section_size >> 16) & 0xFF;
        buffer[size_pos + 3] = (section_size >> 24) & 0xFF;

        /* Move position */
        pos += section_size;
    }

    return pos;
}

/* Generate a test input file */
void generate_test_file(const char *filename, uint8_t type, uint8_t flags) {
    /* Allocate buffer */
    uint8_t *buffer = (uint8_t *)malloc(MAX_BUFFER_SIZE);
    if (!buffer) {
        perror("Failed to allocate memory");
        return;
    }

    /* Initialize header */
    FileHeader header = {0};
    header.magic = MAGIC_HEADER;
    header.version = FORMAT_VERSION;
    header.type = type;
    header.flags = flags;

    /* Initialize metadata */
    Metadata metadata = {0};
    strcpy(metadata.title, "Test File");
    strcpy(metadata.author, "Generator");
    metadata.created_time = (uint32_t)time(NULL);

    /* Set type-specific metadata */
    switch (type) {
        case TYPE_IMAGE:
            metadata.width = 64 + rand() % 256;
            metadata.height = 64 + rand() % 256;
            break;

        case TYPE_AUDIO:
            metadata.channels = 1 + rand() % 2;
            metadata.sample_rate = 8000 + rand() % 40000;
            metadata.duration = 1 + rand() % 10;
            break;
    }

    /* Set metadata size */
    header.metadata_size = sizeof(Metadata);

    /* Generate content based on type */
    uint8_t *content_buffer = buffer + sizeof(FileHeader) + sizeof(Metadata);
    size_t content_size = 0;

    switch (type) {
        case TYPE_IMAGE:
            content_size = generate_image_content(content_buffer, MAX_CONTENT_SIZE);
            break;

        case TYPE_AUDIO:
            content_size = generate_audio_content(content_buffer, MAX_CONTENT_SIZE);
            break;

        case TYPE_TEXT:
            content_size = generate_text_content(content_buffer, MAX_CONTENT_SIZE);
            break;

        case TYPE_MIXED:
            content_size = generate_mixed_content(content_buffer, MAX_CONTENT_SIZE);
            break;
    }

    header.content_size = (uint32_t)content_size;

    /* Calculate header checksum */
    header.checksum = 0;
    header.checksum = calculate_checksum(&header, sizeof(FileHeader));

    /* Write to file */
    FILE *f = fopen(filename, "wb");
    if (!f) {
        perror("Failed to open output file");
        free(buffer);
        return;
    }

    /* Write header */
    fwrite(&header, sizeof(FileHeader), 1, f);

    /* Write metadata */
    fwrite(&metadata, sizeof(Metadata), 1, f);

    /* Write content */
    fwrite(content_buffer, content_size, 1, f);

    fclose(f);
    free(buffer);

    printf("Generated test file: %s (Type: %d, Flags: 0x%02X, Size: %lu bytes)\n",
           filename, type, flags, sizeof(FileHeader) + sizeof(Metadata) + content_size);
}

int main(int argc, char *argv[]) {
    /* Seed random number generator */
    srand((unsigned int)time(NULL));

    /* Generate test files for each type */
    generate_test_file("image_basic.bin", TYPE_IMAGE, 0);
    generate_test_file("image_compressed.bin", TYPE_IMAGE, FLAG_COMPRESS);
    generate_test_file("image_filtered.bin", TYPE_IMAGE, FLAG_FILTER);
    generate_test_file("image_both.bin", TYPE_IMAGE, FLAG_COMPRESS | FLAG_FILTER);

    generate_test_file("audio_basic.bin", TYPE_AUDIO, 0);
    generate_test_file("audio_filtered.bin", TYPE_AUDIO, FLAG_FILTER);

    generate_test_file("text_basic.bin", TYPE_TEXT, 0);
    generate_test_file("text_filtered.bin", TYPE_TEXT, FLAG_FILTER);

    generate_test_file("mixed_basic.bin", TYPE_MIXED, 0);
    generate_test_file("mixed_complex.bin", TYPE_MIXED, FLAG_COMPRESS | FLAG_FILTER);

    printf("Generated 10 test files in the current directory\n");
    return 0;
}
