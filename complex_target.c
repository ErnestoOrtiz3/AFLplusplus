/*
 * Complex Fuzzing Target for AFL++ Scheduler Testing
 *
 * This target simulates a multimedia file parser with multiple components
 * and varying computational complexity to test the effectiveness of the
 * AFL++ CPU scheduler.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
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

/* Error codes */
#define ERR_NONE 0
#define ERR_INVALID_HEADER 1
#define ERR_INVALID_METADATA 2
#define ERR_INVALID_CONTENT 3
#define ERR_PROCESSING_FAILED 4
#define ERR_MEMORY_ERROR 5

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

/* Global state */
typedef struct {
    FileHeader header;
    Metadata metadata;
    uint8_t *content;
    uint8_t *processed_data;
    size_t processed_size;
    int error_code;
} ParserState;

/* Function prototypes */
bool parse_header(const uint8_t *data, size_t size, ParserState *state);
bool parse_metadata(const uint8_t *data, size_t size, ParserState *state);
bool process_content(const uint8_t *data, size_t size, ParserState *state);
void cleanup_state(ParserState *state);

/* Calculate a simple checksum */
uint32_t calculate_checksum(const void *data, size_t size) {
    const uint8_t *bytes = (const uint8_t *)data;
    uint32_t checksum = 0;

    for (size_t i = 0; i < size; i++) {
        checksum = ((checksum << 7) | (checksum >> 25)) + bytes[i];
    }

    return checksum;
}

/* Parse the file header */
bool parse_header(const uint8_t *data, size_t size, ParserState *state) {
    if (size < sizeof(FileHeader)) {
        state->error_code = ERR_INVALID_HEADER;
        return false;
    }

    memcpy(&state->header, data, sizeof(FileHeader));

    /* Validate the header */
    if (state->header.magic != MAGIC_HEADER) {
        state->error_code = ERR_INVALID_HEADER;
        return false;
    }

    /* Check version compatibility */
    if ((state->header.version & 0xFF00) > (FORMAT_VERSION & 0xFF00)) {
        state->error_code = ERR_INVALID_HEADER;
        return false;
    }

    /* Validate sizes */
    if (state->header.metadata_size > MAX_METADATA_SIZE ||
        state->header.content_size > MAX_CONTENT_SIZE) {
        state->error_code = ERR_INVALID_HEADER;
        return false;
    }

    /* Verify checksum (excluding the checksum field itself) */
    uint32_t original_checksum = state->header.checksum;
    state->header.checksum = 0;
    uint32_t calculated_checksum = calculate_checksum(&state->header, sizeof(FileHeader));
    state->header.checksum = original_checksum;

    if (calculated_checksum != original_checksum) {
        state->error_code = ERR_INVALID_HEADER;
        return false;
    }

    return true;
}

/* Parse the metadata section */
bool parse_metadata(const uint8_t *data, size_t size, ParserState *state) {
    if (size < state->header.metadata_size) {
        state->error_code = ERR_INVALID_METADATA;
        return false;
    }

    /* For now, just copy the metadata */
    memcpy(&state->metadata, data, state->header.metadata_size > sizeof(Metadata) ?
           sizeof(Metadata) : state->header.metadata_size);

    /* Perform some basic validation */
    if (state->header.type == TYPE_IMAGE) {
        if (state->metadata.width == 0 || state->metadata.height == 0) {
            state->error_code = ERR_INVALID_METADATA;
            return false;
        }
    } else if (state->header.type == TYPE_AUDIO) {
        if (state->metadata.channels == 0 || state->metadata.sample_rate == 0) {
            state->error_code = ERR_INVALID_METADATA;
            return false;
        }
    }

    return true;
}

/* Image processing functions */
bool process_image(ParserState *state) {
    if (!state->content || state->header.content_size == 0) {
        state->error_code = ERR_INVALID_CONTENT;
        return false;
    }

    uint16_t width = state->metadata.width;
    uint16_t height = state->metadata.height;

    /* Validate dimensions */
    if (width == 0 || height == 0 ||
        width > 8192 || height > 8192 ||
        (size_t)width * height > state->header.content_size) {
        state->error_code = ERR_INVALID_CONTENT;
        return false;
    }

    /* Allocate memory for processed image */
    state->processed_data = (uint8_t *)malloc(width * height * 3); /* RGB format */
    if (!state->processed_data) {
        state->error_code = ERR_MEMORY_ERROR;
        return false;
    }

    state->processed_size = width * height * 3;

    /* Simulate image processing with varying computational complexity */
    uint8_t compression_type = state->content[0] & 0x0F;
    uint8_t filter_type = (state->content[0] & 0xF0) >> 4;

    /* Simulate decompression (computationally intensive) */
    if (state->header.flags & FLAG_COMPRESS) {
        /* Different compression algorithms have different complexity */
        switch (compression_type) {
            case 0: /* Simple RLE */
                {
                    /* Simple run-length decoding */
                    size_t src_pos = 1;
                    size_t dst_pos = 0;

                    while (src_pos < state->header.content_size && dst_pos < state->processed_size) {
                        uint8_t count = state->content[src_pos++];
                        if (src_pos >= state->header.content_size) break;

                        uint8_t value = state->content[src_pos++];

                        /* Potential buffer overflow vulnerability if count is manipulated */
                        for (uint8_t i = 0; i < count && dst_pos < state->processed_size; i++) {
                            state->processed_data[dst_pos++] = value;
                        }
                    }
                }
                break;

            case 1: /* "Complex" compression - more CPU intensive */
                {
                    /* Simulate a more complex decompression algorithm */
                    for (size_t i = 0; i < width * height; i++) {
                        /* Computationally intensive loop with data dependencies */
                        uint32_t x = i % width;
                        uint32_t y = i / width;
                        uint32_t offset = (x + y) % state->header.content_size;

                        /* Introduce a hidden bug: potential out-of-bounds read */
                        uint8_t pixel_value = state->content[offset];

                        /* Perform some "complex" calculations */
                        for (int j = 0; j < 50; j++) {
                            pixel_value = (pixel_value * 1103515245 + 12345) & 0xFF;
                        }

                        /* Write to output buffer - potential overflow if dimensions are wrong */
                        if (i * 3 + 2 < state->processed_size) {
                            state->processed_data[i * 3] = pixel_value;
                            state->processed_data[i * 3 + 1] = pixel_value;
                            state->processed_data[i * 3 + 2] = pixel_value;
                        }
                    }
                }
                break;

            case 2: /* Very complex compression - extremely CPU intensive */
                {
                    /* Simulate a very computationally intensive algorithm */
                    uint32_t seed = (state->content[1] << 24) |
                                   (state->content[2] << 16) |
                                   (state->content[3] << 8) |
                                    state->content[4];

                    /* This will take a lot of CPU time */
                    for (size_t i = 0; i < width * height; i++) {
                        uint32_t x = i % width;
                        uint32_t y = i / width;

                        /* Complex calculation with multiple iterations */
                        uint32_t value = seed;
                        for (int j = 0; j < 200; j++) {
                            value = value ^ (value << 13);
                            value = value ^ (value >> 17);
                            value = value ^ (value << 5);
                            value = (value + x * y) & 0xFFFFFFFF;
                        }

                        /* Write to output buffer */
                        if (i * 3 + 2 < state->processed_size) {
                            state->processed_data[i * 3] = (value & 0xFF);
                            state->processed_data[i * 3 + 1] = ((value >> 8) & 0xFF);
                            state->processed_data[i * 3 + 2] = ((value >> 16) & 0xFF);
                        }
                    }
                }
                break;

            default:
                /* Unknown compression type */
                state->error_code = ERR_PROCESSING_FAILED;
                return false;
        }
    } else {
        /* No compression, just copy the data */
        /* Potential vulnerability: no bounds checking if content_size > processed_size */
        memcpy(state->processed_data, state->content,
               state->header.content_size < state->processed_size ?
               state->header.content_size : state->processed_size);
    }

    /* Apply filters if requested */
    if (state->header.flags & FLAG_FILTER) {
        switch (filter_type) {
            case 0: /* Simple inversion filter */
                for (size_t i = 0; i < state->processed_size; i++) {
                    state->processed_data[i] = 255 - state->processed_data[i];
                }
                break;

            case 1: /* "Blur" filter - medium complexity */
                {
                    /* Allocate temporary buffer for blur operation */
                    uint8_t *temp = (uint8_t *)malloc(state->processed_size);
                    if (!temp) {
                        state->error_code = ERR_MEMORY_ERROR;
                        return false;
                    }

                    /* Copy data to temp buffer */
                    memcpy(temp, state->processed_data, state->processed_size);

                    /* Apply a simple blur filter */
                    for (uint16_t y = 1; y < height - 1; y++) {
                        for (uint16_t x = 1; x < width - 1; x++) {
                            for (int c = 0; c < 3; c++) {
                                uint32_t sum = 0;
                                size_t center = (y * width + x) * 3 + c;

                                /* 3x3 kernel blur - potential out of bounds access if width/height are manipulated */
                                sum += temp[center - width * 3 - 3 + c];
                                sum += temp[center - width * 3 + c];
                                sum += temp[center - width * 3 + 3 + c];
                                sum += temp[center - 3 + c];
                                sum += temp[center + c];
                                sum += temp[center + 3 + c];
                                sum += temp[center + width * 3 - 3 + c];
                                sum += temp[center + width * 3 + c];
                                sum += temp[center + width * 3 + 3 + c];

                                state->processed_data[center] = sum / 9;
                            }
                        }
                    }

                    free(temp);
                }
                break;

            case 2: /* "Edge detection" filter - high complexity */
                {
                    /* Allocate temporary buffer */
                    uint8_t *temp = (uint8_t *)malloc(state->processed_size);
                    if (!temp) {
                        state->error_code = ERR_MEMORY_ERROR;
                        return false;
                    }

                    /* Copy data to temp buffer */
                    memcpy(temp, state->processed_data, state->processed_size);

                    /* Apply edge detection filter */
                    for (uint16_t y = 1; y < height - 1; y++) {
                        for (uint16_t x = 1; x < width - 1; x++) {
                            for (int c = 0; c < 3; c++) {
                                int gx = 0, gy = 0;
                                size_t center = (y * width + x) * 3 + c;

                                /* Sobel operator - computationally intensive */
                                /* Horizontal gradient */
                                gx -= temp[center - width * 3 - 3 + c];
                                gx -= 2 * temp[center - 3 + c];
                                gx -= temp[center + width * 3 - 3 + c];
                                gx += temp[center - width * 3 + 3 + c];
                                gx += 2 * temp[center + 3 + c];
                                gx += temp[center + width * 3 + 3 + c];

                                /* Vertical gradient */
                                gy -= temp[center - width * 3 - 3 + c];
                                gy -= 2 * temp[center - width * 3 + c];
                                gy -= temp[center - width * 3 + 3 + c];
                                gy += temp[center + width * 3 - 3 + c];
                                gy += 2 * temp[center + width * 3 + c];
                                gy += temp[center + width * 3 + 3 + c];

                                /* Magnitude */
                                int mag = (abs(gx) + abs(gy)) / 2;
                                if (mag > 255) mag = 255;

                                state->processed_data[center] = mag;
                            }
                        }
                    }

                    free(temp);
                }
                break;

            default:
                /* Unknown filter type */
                state->error_code = ERR_PROCESSING_FAILED;
                return false;
        }
    }

    return true;
}

/* Audio processing functions */
bool process_audio(ParserState *state) {
    if (!state->content || state->header.content_size == 0) {
        state->error_code = ERR_INVALID_CONTENT;
        return false;
    }

    uint16_t channels = state->metadata.channels;
    uint16_t sample_rate = state->metadata.sample_rate;
    uint32_t duration = state->metadata.duration;

    /* Validate audio parameters */
    if (channels == 0 || channels > 8 || sample_rate == 0 || duration == 0) {
        state->error_code = ERR_INVALID_CONTENT;
        return false;
    }

    /* Calculate expected data size (16-bit samples) */
    size_t expected_size = channels * sample_rate * duration * 2;
    if (expected_size > MAX_CONTENT_SIZE) {
        state->error_code = ERR_INVALID_CONTENT;
        return false;
    }

    /* Allocate memory for processed audio */
    state->processed_data = (uint8_t *)malloc(expected_size);
    if (!state->processed_data) {
        state->error_code = ERR_MEMORY_ERROR;
        return false;
    }

    state->processed_size = expected_size;

    /* Get audio format and effect type from the first byte */
    uint8_t audio_format = state->content[0] & 0x0F;
    uint8_t effect_type = (state->content[0] & 0xF0) >> 4;

    /* Process based on audio format */
    switch (audio_format) {
        case 0: /* Raw PCM data */
            {
                /* Just copy the data with potential buffer overflow */
                size_t copy_size = state->header.content_size - 1; /* Skip format byte */
                if (copy_size > state->processed_size) {
                    copy_size = state->processed_size;
                }
                memcpy(state->processed_data, state->content + 1, copy_size);
            }
            break;

        case 1: /* Simple delta encoding */
            {
                /* Delta decoding - medium complexity */
                int16_t sample = 0;
                size_t src_pos = 1; /* Skip format byte */
                size_t dst_pos = 0;

                while (src_pos < state->header.content_size && dst_pos + 1 < state->processed_size) {
                    /* Read delta value (8-bit) */
                    int8_t delta = (int8_t)state->content[src_pos++];

                    /* Apply delta to current sample */
                    sample += delta;

                    /* Write 16-bit sample */
                    state->processed_data[dst_pos++] = sample & 0xFF;
                    state->processed_data[dst_pos++] = (sample >> 8) & 0xFF;
                }
            }
            break;

        case 2: /* ADPCM-like encoding - high complexity */
            {
                /* Adaptive delta with prediction - high complexity */
                int16_t sample = 0;
                int16_t step_size = 16;
                size_t src_pos = 1; /* Skip format byte */
                size_t dst_pos = 0;

                /* This is computationally intensive */
                while (src_pos < state->header.content_size && dst_pos + 1 < state->processed_size) {
                    uint8_t code = state->content[src_pos++];

                    /* Process 2 samples from each byte */
                    for (int i = 0; i < 2 && dst_pos + 1 < state->processed_size; i++) {
                        uint8_t nibble = (i == 0) ? (code & 0x0F) : ((code >> 4) & 0x0F);

                        /* Complex decoding algorithm */
                        int16_t diff = step_size >> 3;
                        if (nibble & 1) diff += step_size >> 2;
                        if (nibble & 2) diff += step_size >> 1;
                        if (nibble & 4) diff += step_size;
                        if (nibble & 8) diff = -diff;

                        /* Apply difference */
                        sample += diff;

                        /* Clamp sample to 16-bit range */
                        if (sample > 32767) sample = 32767;
                        if (sample < -32768) sample = -32768;

                        /* Adjust step size */
                        step_size = (step_size * ((nibble & 7) + 8)) >> 3;
                        if (step_size < 1) step_size = 1;
                        if (step_size > 32767) step_size = 32767;

                        /* Write 16-bit sample */
                        state->processed_data[dst_pos++] = sample & 0xFF;
                        state->processed_data[dst_pos++] = (sample >> 8) & 0xFF;
                    }
                }
            }
            break;

        case 3: /* Frequency domain encoding - very high complexity */
            {
                /* Simulate a very CPU intensive decoding process */
                /* This would normally be something like MP3 or AAC decoding */

                /* Initialize with a seed from the content */
                uint32_t seed = (state->content[1] << 24) |
                               (state->content[2] << 16) |
                               (state->content[3] << 8) |
                                state->content[4];

                /* Generate synthetic audio data with high computational complexity */
                for (size_t i = 0; i < state->processed_size / 2; i++) {
                    /* Very CPU intensive calculation */
                    uint32_t value = seed;
                    for (int j = 0; j < 100; j++) {
                        value = value ^ (value << 13);
                        value = value ^ (value >> 17);
                        value = value ^ (value << 5);
                        value = (value + i) & 0xFFFFFFFF;
                    }

                    /* Convert to 16-bit sample */
                    int16_t sample = (value % 65536) - 32768;

                    /* Write 16-bit sample */
                    if (i * 2 + 1 < state->processed_size) {
                        state->processed_data[i * 2] = sample & 0xFF;
                        state->processed_data[i * 2 + 1] = (sample >> 8) & 0xFF;
                    }
                }
            }
            break;

        default:
            state->error_code = ERR_PROCESSING_FAILED;
            return false;
    }

    /* Apply audio effects if requested */
    if (state->header.flags & FLAG_FILTER) {
        switch (effect_type) {
            case 0: /* Volume adjustment - simple */
                {
                    /* Simple volume scaling */
                    float volume = 0.5f; /* 50% volume */

                    for (size_t i = 0; i < state->processed_size / 2; i++) {
                        /* Read 16-bit sample */
                        int16_t sample = state->processed_data[i * 2] |
                                        (state->processed_data[i * 2 + 1] << 8);

                        /* Apply volume */
                        sample = (int16_t)(sample * volume);

                        /* Write back */
                        state->processed_data[i * 2] = sample & 0xFF;
                        state->processed_data[i * 2 + 1] = (sample >> 8) & 0xFF;
                    }
                }
                break;

            case 1: /* Echo effect - medium complexity */
                {
                    /* Echo effect with delay buffer */
                    const size_t delay_samples = sample_rate / 4; /* 250ms delay */
                    const float decay = 0.5f;

                    /* Allocate delay buffer - potential vulnerability if sample_rate is manipulated */
                    int16_t *delay_buffer = (int16_t *)malloc(delay_samples * sizeof(int16_t));
                    if (!delay_buffer) {
                        state->error_code = ERR_MEMORY_ERROR;
                        return false;
                    }

                    /* Initialize delay buffer */
                    memset(delay_buffer, 0, delay_samples * sizeof(int16_t));

                    /* Process each sample */
                    size_t delay_pos = 0;
                    for (size_t i = 0; i < state->processed_size / 2; i++) {
                        /* Read 16-bit sample */
                        int16_t sample = state->processed_data[i * 2] |
                                        (state->processed_data[i * 2 + 1] << 8);

                        /* Get delayed sample */
                        int16_t delayed = delay_buffer[delay_pos];

                        /* Mix original and delayed sample */
                        int16_t output = sample + (int16_t)(delayed * decay);

                        /* Update delay buffer */
                        delay_buffer[delay_pos] = sample;
                        delay_pos = (delay_pos + 1) % delay_samples;

                        /* Write output sample */
                        state->processed_data[i * 2] = output & 0xFF;
                        state->processed_data[i * 2 + 1] = (output >> 8) & 0xFF;
                    }

                    free(delay_buffer);
                }
                break;

            case 2: /* Equalizer - high complexity */
                {
                    /* Simulate a multi-band equalizer (very CPU intensive) */
                    /* This would normally involve FFT and inverse FFT */

                    /* For simulation, we'll just do a simple filter that's computationally intensive */
                    const int num_bands = 10;
                    float gains[10] = {0.8f, 1.2f, 0.7f, 1.5f, 0.5f, 1.0f, 1.3f, 0.6f, 1.1f, 0.9f};

                    /* Process in chunks to simulate frequency domain processing */
                    const size_t chunk_size = 1024;
                    int16_t *chunk = (int16_t *)malloc(chunk_size * sizeof(int16_t));
                    if (!chunk) {
                        state->error_code = ERR_MEMORY_ERROR;
                        return false;
                    }

                    for (size_t offset = 0; offset < state->processed_size / 2; offset += chunk_size) {
                        size_t samples_to_process = chunk_size;
                        if (offset + samples_to_process > state->processed_size / 2) {
                            samples_to_process = state->processed_size / 2 - offset;
                        }

                        /* Read samples into chunk */
                        for (size_t i = 0; i < samples_to_process; i++) {
                            chunk[i] = state->processed_data[(offset + i) * 2] |
                                     (state->processed_data[(offset + i) * 2 + 1] << 8);
                        }

                        /* Process each sample with a complex algorithm */
                        for (size_t i = 0; i < samples_to_process; i++) {
                            /* Determine which frequency band this sample belongs to */
                            /* This is a simplification; real EQ would use FFT */
                            int band = (i * num_bands) / samples_to_process;

                            /* Apply gain for this band */
                            float gain = gains[band];

                            /* Computationally intensive processing */
                            float processed = chunk[i];
                            for (int j = 0; j < 50; j++) {
                                processed = processed * 0.99f + (processed * gain - processed) * 0.01f;
                            }

                            /* Convert back to int16 */
                            int16_t output = (int16_t)processed;

                            /* Write back */
                            state->processed_data[(offset + i) * 2] = output & 0xFF;
                            state->processed_data[(offset + i) * 2 + 1] = (output >> 8) & 0xFF;
                        }
                    }

                    free(chunk);
                }
                break;

            default:
                state->error_code = ERR_PROCESSING_FAILED;
                return false;
        }
    }

    return true;
}

/* Text processing functions */
bool process_text(ParserState *state) {
    if (!state->content || state->header.content_size == 0) {
        state->error_code = ERR_INVALID_CONTENT;
        return false;
    }

    /* Get text format and processing type from the first byte */
    uint8_t text_format = state->content[0] & 0x0F;
    uint8_t processing_type = (state->content[0] & 0xF0) >> 4;

    /* Allocate memory for processed text */
    /* We'll allocate twice the content size to allow for expansion */
    state->processed_data = (uint8_t *)malloc(state->header.content_size * 2);
    if (!state->processed_data) {
        state->error_code = ERR_MEMORY_ERROR;
        return false;
    }

    state->processed_size = state->header.content_size * 2;

    /* Process based on text format */
    switch (text_format) {
        case 0: /* Plain text */
            {
                /* Just copy the content (skipping the format byte) */
                size_t copy_size = state->header.content_size - 1;
                if (copy_size > state->processed_size) {
                    copy_size = state->processed_size;
                }
                memcpy(state->processed_data, state->content + 1, copy_size);
                state->processed_size = copy_size;
            }
            break;

        case 1: /* Simple compression (run-length encoding) */
            {
                /* RLE decompression */
                size_t src_pos = 1; /* Skip format byte */
                size_t dst_pos = 0;

                while (src_pos < state->header.content_size && dst_pos < state->processed_size) {
                    /* Check if we have enough data for a complete RLE pair */
                    if (src_pos + 1 >= state->header.content_size) break;

                    uint8_t count = state->content[src_pos++];
                    uint8_t value = state->content[src_pos++];

                    /* Expand the run - potential buffer overflow if count is manipulated */
                    for (uint8_t i = 0; i < count && dst_pos < state->processed_size; i++) {
                        state->processed_data[dst_pos++] = value;
                    }
                }

                state->processed_size = dst_pos;
            }
            break;

        case 2: /* Markup language */
            {
                /* Parse and process a simple markup language */
                /* This is medium complexity with potential for bugs */

                size_t src_pos = 1; /* Skip format byte */
                size_t dst_pos = 0;
                bool in_tag = false;
                char tag_name[32] = {0};
                size_t tag_pos = 0;

                while (src_pos < state->header.content_size && dst_pos + 1 < state->processed_size) {
                    char c = state->content[src_pos++];

                    if (c == '<') {
                        in_tag = true;
                        tag_pos = 0;
                        memset(tag_name, 0, sizeof(tag_name));
                    } else if (in_tag && c == '>') {
                        in_tag = false;

                        /* Process the tag */
                        if (strcmp(tag_name, "b") == 0) {
                            /* Bold tag - add markdown equivalent */
                            if (dst_pos + 2 <= state->processed_size) {
                                state->processed_data[dst_pos++] = '*';
                                state->processed_data[dst_pos++] = '*';
                            }
                        } else if (strcmp(tag_name, "/b") == 0) {
                            /* End bold tag */
                            if (dst_pos + 2 <= state->processed_size) {
                                state->processed_data[dst_pos++] = '*';
                                state->processed_data[dst_pos++] = '*';
                            }
                        } else if (strcmp(tag_name, "i") == 0) {
                            /* Italic tag */
                            if (dst_pos < state->processed_size) {
                                state->processed_data[dst_pos++] = '_';
                            }
                        } else if (strcmp(tag_name, "/i") == 0) {
                            /* End italic tag */
                            if (dst_pos < state->processed_size) {
                                state->processed_data[dst_pos++] = '_';
                            }
                        } else if (strncmp(tag_name, "h", 1) == 0 && tag_name[1] >= '1' && tag_name[1] <= '6') {
                            /* Heading tag */
                            int level = tag_name[1] - '0';
                            for (int i = 0; i < level && dst_pos < state->processed_size; i++) {
                                state->processed_data[dst_pos++] = '#';
                            }
                            if (dst_pos < state->processed_size) {
                                state->processed_data[dst_pos++] = ' ';
                            }
                        }
                    } else if (in_tag) {
                        /* Collect tag name - potential buffer overflow */
                        if (tag_pos < sizeof(tag_name) - 1) {
                            tag_name[tag_pos++] = c;
                        }
                    } else {
                        /* Regular character */
                        if (dst_pos < state->processed_size) {
                            state->processed_data[dst_pos++] = c;
                        }
                    }
                }

                /* Null-terminate the processed text */
                if (dst_pos < state->processed_size) {
                    state->processed_data[dst_pos] = '\0';
                }

                state->processed_size = dst_pos;
            }
            break;

        case 3: /* Template language - high complexity */
            {
                /* Process a simple template language with variable substitution */
                /* This is high complexity with potential for bugs */

                /* Define some template variables */
                struct {
                    const char *name;
                    const char *value;
                } variables[] = {
                    {"title", state->metadata.title},
                    {"author", state->metadata.author},
                    {"year", "2023"},
                    {"version", "1.0"},
                    {"description", "A complex fuzzing target"},
                    {NULL, NULL}
                };

                size_t src_pos = 1; /* Skip format byte */
                size_t dst_pos = 0;
                bool in_var = false;
                char var_name[64] = {0};
                size_t var_pos = 0;

                /* This is computationally intensive with lots of string operations */
                while (src_pos < state->header.content_size && dst_pos < state->processed_size) {
                    char c = state->content[src_pos++];

                    if (c == '{' && src_pos < state->header.content_size && state->content[src_pos] == '{') {
                        /* Start of variable */
                        in_var = true;
                        var_pos = 0;
                        memset(var_name, 0, sizeof(var_name));
                        src_pos++; /* Skip second '{' */
                    } else if (in_var && c == '}' && src_pos < state->header.content_size && state->content[src_pos] == '}') {
                        /* End of variable */
                        in_var = false;
                        src_pos++; /* Skip second '}' */

                        /* Look up the variable */
                        bool found = false;
                        for (int i = 0; variables[i].name != NULL; i++) {
                            if (strcmp(var_name, variables[i].name) == 0) {
                                /* Found the variable, substitute its value */
                                const char *value = variables[i].value;
                                size_t value_len = strlen(value);

                                /* Potential buffer overflow if value is too long */
                                if (dst_pos + value_len <= state->processed_size) {
                                    memcpy(state->processed_data + dst_pos, value, value_len);
                                    dst_pos += value_len;
                                }

                                found = true;
                                break;
                            }
                        }

                        if (!found) {
                            /* Variable not found, just output the original */
                            if (dst_pos + 4 + var_pos <= state->processed_size) {
                                state->processed_data[dst_pos++] = '{';
                                state->processed_data[dst_pos++] = '{';
                                memcpy(state->processed_data + dst_pos, var_name, var_pos);
                                dst_pos += var_pos;
                                state->processed_data[dst_pos++] = '}';
                                state->processed_data[dst_pos++] = '}';
                            }
                        }
                    } else if (in_var) {
                        /* Collect variable name - potential buffer overflow */
                        if (var_pos < sizeof(var_name) - 1) {
                            var_name[var_pos++] = c;
                        }
                    } else {
                        /* Regular character */
                        if (dst_pos < state->processed_size) {
                            state->processed_data[dst_pos++] = c;
                        }
                    }
                }

                /* Null-terminate the processed text */
                if (dst_pos < state->processed_size) {
                    state->processed_data[dst_pos] = '\0';
                }

                state->processed_size = dst_pos;
            }
            break;

        default:
            state->error_code = ERR_PROCESSING_FAILED;
            return false;
    }

    /* Apply text processing if requested */
    if (state->header.flags & FLAG_FILTER) {
        switch (processing_type) {
            case 0: /* Simple text transformation - low complexity */
                {
                    /* Convert to uppercase */
                    for (size_t i = 0; i < state->processed_size; i++) {
                        char c = state->processed_data[i];
                        if (c >= 'a' && c <= 'z') {
                            state->processed_data[i] = c - 'a' + 'A';
                        }
                    }
                }
                break;

            case 1: /* Word wrapping - medium complexity */
                {
                    /* Perform simple word wrapping at 80 characters */
                    const size_t line_width = 80;

                    /* Allocate temporary buffer */
                    uint8_t *temp = (uint8_t *)malloc(state->processed_size);
                    if (!temp) {
                        state->error_code = ERR_MEMORY_ERROR;
                        return false;
                    }

                    /* Copy to temp buffer */
                    memcpy(temp, state->processed_data, state->processed_size);

                    size_t src_pos = 0;
                    size_t dst_pos = 0;
                    size_t line_pos = 0;
                    size_t last_space = 0;

                    while (src_pos < state->processed_size && dst_pos < state->processed_size) {
                        char c = temp[src_pos++];

                        if (c == '\n') {
                            /* Reset line position on newline */
                            line_pos = 0;
                            last_space = dst_pos + 1;
                        } else if (c == ' ') {
                            last_space = dst_pos;
                        }

                        /* Add character to output */
                        if (dst_pos < state->processed_size) {
                            state->processed_data[dst_pos++] = c;
                        }

                        line_pos++;

                        /* Check if we need to wrap */
                        if (line_pos >= line_width && last_space > 0) {
                            /* Replace the last space with a newline */
                            state->processed_data[last_space] = '\n';
                            line_pos = dst_pos - last_space - 1;
                            last_space = 0;
                        }
                    }

                    free(temp);
                }
                break;

            case 2: /* Text analysis - high complexity */
                {
                    /* Perform a "complex" text analysis */
                    /* This is computationally intensive */

                    /* Count word frequencies */
                    #define MAX_WORDS 100
                    #define MAX_WORD_LEN 32

                    struct {
                        char word[MAX_WORD_LEN];
                        int count;
                    } word_counts[MAX_WORDS] = {0};

                    int word_count = 0;
                    char current_word[MAX_WORD_LEN] = {0};
                    int current_word_len = 0;

                    /* First pass: count words */
                    for (size_t i = 0; i < state->processed_size; i++) {
                        char c = state->processed_data[i];

                        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
                            /* Part of a word */
                            if (current_word_len < MAX_WORD_LEN - 1) {
                                current_word[current_word_len++] = c;
                            }
                        } else if (current_word_len > 0) {
                            /* End of word */
                            current_word[current_word_len] = '\0';

                            /* Look for this word in our counts */
                            bool found = false;
                            for (int j = 0; j < word_count; j++) {
                                if (strcmp(word_counts[j].word, current_word) == 0) {
                                    word_counts[j].count++;
                                    found = true;
                                    break;
                                }
                            }

                            /* Add new word if not found and we have space */
                            if (!found && word_count < MAX_WORDS) {
                                strcpy(word_counts[word_count].word, current_word);
                                word_counts[word_count].count = 1;
                                word_count++;
                            }

                            /* Reset for next word */
                            current_word_len = 0;
                        }
                    }

                    /* Sort words by frequency (bubble sort - inefficient but complex) */
                    for (int i = 0; i < word_count - 1; i++) {
                        for (int j = 0; j < word_count - i - 1; j++) {
                            if (word_counts[j].count < word_counts[j + 1].count) {
                                /* Swap */
                                char temp_word[MAX_WORD_LEN];
                                strcpy(temp_word, word_counts[j].word);
                                int temp_count = word_counts[j].count;

                                strcpy(word_counts[j].word, word_counts[j + 1].word);
                                word_counts[j].count = word_counts[j + 1].count;

                                strcpy(word_counts[j + 1].word, temp_word);
                                word_counts[j + 1].count = temp_count;
                            }
                        }
                    }

                    /* Generate a summary at the beginning of the text */
                    char summary[1024] = "Word frequency analysis:\n";
                    size_t summary_len = strlen(summary);

                    /* Add top 5 words to summary */
                    int top_words = word_count < 5 ? word_count : 5;
                    for (int i = 0; i < top_words; i++) {
                        char word_info[100];
                        snprintf(word_info, sizeof(word_info), "%d. %s (%d)\n",
                                i + 1, word_counts[i].word, word_counts[i].count);

                        size_t word_info_len = strlen(word_info);
                        if (summary_len + word_info_len < sizeof(summary)) {
                            strcat(summary, word_info);
                            summary_len += word_info_len;
                        }
                    }

                    strcat(summary, "\n");
                    summary_len += 2;

                    /* Prepend summary to processed data */
                    if (summary_len + state->processed_size <= state->processed_size * 2) {
                        /* We have enough space in our buffer */
                        memmove(state->processed_data + summary_len, state->processed_data, state->processed_size);
                        memcpy(state->processed_data, summary, summary_len);
                        state->processed_size += summary_len;
                    }
                }
                break;

            default:
                state->error_code = ERR_PROCESSING_FAILED;
                return false;
        }
    }

    return true;
}

/* Mixed content processing */
bool process_mixed(ParserState *state) {
    if (!state->content || state->header.content_size == 0) {
        state->error_code = ERR_INVALID_CONTENT;
        return false;
    }

    /* Mixed content has a special format with sections for different content types */
    /* Format: [type][size][data][type][size][data]... */

    /* Allocate memory for processed content */
    /* We'll allocate twice the content size to allow for expansion */
    state->processed_data = (uint8_t *)malloc(state->header.content_size * 2);
    if (!state->processed_data) {
        state->error_code = ERR_MEMORY_ERROR;
        return false;
    }

    state->processed_size = 0;

    size_t pos = 0;

    /* Process each section */
    while (pos + 5 <= state->header.content_size) { /* Need at least 5 bytes for header */
        /* Read section header */
        uint8_t section_type = state->content[pos++];
        uint32_t section_size = 0;

        /* Read 4-byte size (little endian) */
        section_size = state->content[pos] |
                      (state->content[pos + 1] << 8) |
                      (state->content[pos + 2] << 16) |
                      (state->content[pos + 3] << 24);
        pos += 4;

        /* Validate section size */
        if (section_size == 0 || pos + section_size > state->header.content_size) {
            state->error_code = ERR_INVALID_CONTENT;
            return false;
        }

        /* Process section based on type */
        switch (section_type) {
            case TYPE_IMAGE: /* Image section */
                {
                    /* Create a temporary state for image processing */
                    ParserState image_state = {0};

                    /* Set up header */
                    image_state.header.type = TYPE_IMAGE;
                    image_state.header.flags = state->header.flags;
                    image_state.header.content_size = section_size;

                    /* Set up metadata */
                    /* Extract width and height from the first 4 bytes of the section */
                    if (section_size >= 4) {
                        image_state.metadata.width = state->content[pos] | (state->content[pos + 1] << 8);
                        image_state.metadata.height = state->content[pos + 2] | (state->content[pos + 3] << 8);
                    } else {
                        /* Default values if not enough data */
                        image_state.metadata.width = 16;
                        image_state.metadata.height = 16;
                    }

                    /* Allocate and copy content */
                    image_state.content = (uint8_t *)malloc(section_size);
                    if (!image_state.content) {
                        state->error_code = ERR_MEMORY_ERROR;
                        return false;
                    }
                    memcpy(image_state.content, state->content + pos, section_size);

                    /* Process the image */
                    if (!process_image(&image_state)) {
                        /* Propagate error code */
                        state->error_code = image_state.error_code;
                        free(image_state.content);
                        if (image_state.processed_data) {
                            free(image_state.processed_data);
                        }
                        return false;
                    }

                    /* Append processed data to output */
                    if (image_state.processed_data && image_state.processed_size > 0) {
                        /* Check if we have enough space */
                        if (state->processed_size + image_state.processed_size <= state->header.content_size * 2) {
                            memcpy(state->processed_data + state->processed_size,
                                   image_state.processed_data,
                                   image_state.processed_size);
                            state->processed_size += image_state.processed_size;
                        }
                    }

                    /* Clean up */
                    free(image_state.content);
                    if (image_state.processed_data) {
                        free(image_state.processed_data);
                    }
                }
                break;

            case TYPE_AUDIO: /* Audio section */
                {
                    /* Create a temporary state for audio processing */
                    ParserState audio_state = {0};

                    /* Set up header */
                    audio_state.header.type = TYPE_AUDIO;
                    audio_state.header.flags = state->header.flags;
                    audio_state.header.content_size = section_size;

                    /* Set up metadata */
                    /* Extract audio parameters from the first 8 bytes of the section */
                    if (section_size >= 8) {
                        audio_state.metadata.channels = state->content[pos] | (state->content[pos + 1] << 8);
                        audio_state.metadata.sample_rate = state->content[pos + 2] | (state->content[pos + 3] << 8);
                        audio_state.metadata.duration = state->content[pos + 4] |
                                                      (state->content[pos + 5] << 8) |
                                                      (state->content[pos + 6] << 16) |
                                                      (state->content[pos + 7] << 24);
                    } else {
                        /* Default values if not enough data */
                        audio_state.metadata.channels = 1;
                        audio_state.metadata.sample_rate = 8000;
                        audio_state.metadata.duration = 1;
                    }

                    /* Allocate and copy content */
                    audio_state.content = (uint8_t *)malloc(section_size);
                    if (!audio_state.content) {
                        state->error_code = ERR_MEMORY_ERROR;
                        return false;
                    }
                    memcpy(audio_state.content, state->content + pos, section_size);

                    /* Process the audio */
                    if (!process_audio(&audio_state)) {
                        /* Propagate error code */
                        state->error_code = audio_state.error_code;
                        free(audio_state.content);
                        if (audio_state.processed_data) {
                            free(audio_state.processed_data);
                        }
                        return false;
                    }

                    /* Append processed data to output */
                    if (audio_state.processed_data && audio_state.processed_size > 0) {
                        /* Check if we have enough space */
                        if (state->processed_size + audio_state.processed_size <= state->header.content_size * 2) {
                            memcpy(state->processed_data + state->processed_size,
                                   audio_state.processed_data,
                                   audio_state.processed_size);
                            state->processed_size += audio_state.processed_size;
                        }
                    }

                    /* Clean up */
                    free(audio_state.content);
                    if (audio_state.processed_data) {
                        free(audio_state.processed_data);
                    }
                }
                break;

            case TYPE_TEXT: /* Text section */
                {
                    /* Create a temporary state for text processing */
                    ParserState text_state = {0};

                    /* Set up header */
                    text_state.header.type = TYPE_TEXT;
                    text_state.header.flags = state->header.flags;
                    text_state.header.content_size = section_size;

                    /* Set up metadata - not much needed for text */

                    /* Allocate and copy content */
                    text_state.content = (uint8_t *)malloc(section_size);
                    if (!text_state.content) {
                        state->error_code = ERR_MEMORY_ERROR;
                        return false;
                    }
                    memcpy(text_state.content, state->content + pos, section_size);

                    /* Process the text */
                    if (!process_text(&text_state)) {
                        /* Propagate error code */
                        state->error_code = text_state.error_code;
                        free(text_state.content);
                        if (text_state.processed_data) {
                            free(text_state.processed_data);
                        }
                        return false;
                    }

                    /* Append processed data to output */
                    if (text_state.processed_data && text_state.processed_size > 0) {
                        /* Check if we have enough space */
                        if (state->processed_size + text_state.processed_size <= state->header.content_size * 2) {
                            memcpy(state->processed_data + state->processed_size,
                                   text_state.processed_data,
                                   text_state.processed_size);
                            state->processed_size += text_state.processed_size;
                        }
                    }

                    /* Clean up */
                    free(text_state.content);
                    if (text_state.processed_data) {
                        free(text_state.processed_data);
                    }
                }
                break;

            default: /* Unknown section type */
                {
                    /* Just copy the raw data */
                    if (state->processed_size + section_size <= state->header.content_size * 2) {
                        memcpy(state->processed_data + state->processed_size,
                               state->content + pos,
                               section_size);
                        state->processed_size += section_size;
                    }
                }
                break;
        }

        /* Move to next section */
        pos += section_size;
    }

    /* Special crash condition for mixed content */
    /* If the content contains a specific pattern, trigger a crash */
    for (size_t i = 0; i < state->processed_size - 7; i++) {
        if (state->processed_data[i] == 'C' &&
            state->processed_data[i+1] == 'R' &&
            state->processed_data[i+2] == 'A' &&
            state->processed_data[i+3] == 'S' &&
            state->processed_data[i+4] == 'H' &&
            state->processed_data[i+5] == 'M' &&
            state->processed_data[i+6] == 'E') {

            /* Trigger a crash with a null pointer dereference */
            int *crash_ptr = NULL;
            *crash_ptr = 0xDEADBEEF; /* This will crash */
        }
    }

    return true;
}

/* Process the content based on type and flags */
bool process_content(const uint8_t *data, size_t size, ParserState *state) {
    if (size < state->header.content_size) {
        state->error_code = ERR_INVALID_CONTENT;
        return false;
    }

    /* Allocate memory for content */
    state->content = (uint8_t *)malloc(state->header.content_size);
    if (!state->content) {
        state->error_code = ERR_MEMORY_ERROR;
        return false;
    }

    /* Copy content data */
    memcpy(state->content, data, state->header.content_size);

    /* Process based on content type */
    bool result = false;
    switch (state->header.type) {
        case TYPE_IMAGE:
            result = process_image(state);
            break;

        case TYPE_AUDIO:
            result = process_audio(state);
            break;

        case TYPE_TEXT:
            result = process_text(state);
            break;

        case TYPE_MIXED:
            result = process_mixed(state);
            break;

        default:
            state->error_code = ERR_INVALID_CONTENT;
            return false;
    }

    return result;
}

/* Clean up allocated resources */
void cleanup_state(ParserState *state) {
    if (state->content) {
        free(state->content);
        state->content = NULL;
    }

    if (state->processed_data) {
        free(state->processed_data);
        state->processed_data = NULL;
    }
}

/* Main processing function */
int process_file(const uint8_t *data, size_t size) {
    ParserState state = {0};

    /* Parse header */
    if (!parse_header(data, size, &state)) {
        cleanup_state(&state);
        return state.error_code;
    }

    /* Parse metadata */
    const uint8_t *metadata_start = data + sizeof(FileHeader);
    if (!parse_metadata(metadata_start, size - sizeof(FileHeader), &state)) {
        cleanup_state(&state);
        return state.error_code;
    }

    /* Process content */
    const uint8_t *content_start = metadata_start + state.header.metadata_size;
    if (!process_content(content_start, size - sizeof(FileHeader) - state.header.metadata_size, &state)) {
        cleanup_state(&state);
        return state.error_code;
    }

    /* Clean up and return success */
    cleanup_state(&state);
    return ERR_NONE;
}

/* Main function */
int main(int argc, char *argv[]) {
    /* Check command line arguments */
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    /* Open input file */
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("Failed to open input file");
        return 1;
    }

    /* Get file size */
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (file_size <= 0 || file_size > MAX_BUFFER_SIZE) {
        fprintf(stderr, "Invalid file size: %ld\n", file_size);
        fclose(f);
        return 1;
    }

    /* Allocate buffer */
    uint8_t *buffer = (uint8_t *)malloc(file_size);
    if (!buffer) {
        perror("Failed to allocate memory");
        fclose(f);
        return 1;
    }

    /* Read file content */
    size_t bytes_read = fread(buffer, 1, file_size, f);
    fclose(f);

    if (bytes_read != (size_t)file_size) {
        fprintf(stderr, "Failed to read the entire file\n");
        free(buffer);
        return 1;
    }

    /* Process the file */
    int result = process_file(buffer, file_size);

    /* Clean up */
    free(buffer);

    return result;
}
