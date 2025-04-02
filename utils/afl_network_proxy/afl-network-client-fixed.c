#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <errno.h>

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>

// Define constants from AFL
#define FORKSRV_FD 198
#define MAP_SIZE 65536

// Global variables
unsigned char *__afl_area_ptr;
unsigned int __afl_map_size = MAP_SIZE;

// Function to read a testcase from AFL
static unsigned int read_testcase(unsigned char *buf, unsigned int max_len) {
    int status;
    int res = 0x0fffffff;  // Dummy PID

    // Wait for parent by reading from the pipe
    if (read(FORKSRV_FD, &status, 4) != 4) {
        fprintf(stderr, "Failed to read from AFL\n");
        return 0;
    }

    // Read the testcase from stdin
    status = read(0, buf, max_len);

    // Report that we're starting the target
    if (write(FORKSRV_FD + 1, &res, 4) != 4) {
        fprintf(stderr, "Failed to write to AFL\n");
        return 0;
    }

    if (status < 1) return 0;
    return status;
}

// Function to report the test case result back to AFL
static void end_testcase(int status) {
    if (write(FORKSRV_FD + 1, &status, 4) != 4) {
        fprintf(stderr, "Failed to write status to AFL\n");
        exit(1);
    }
}

// Helper function to print data in hex format
void print_hex(const char* desc, const void* addr, size_t len) {
    const unsigned char* pc = (const unsigned char*)addr;
    fprintf(stderr, "%s (length=%zu):\n", desc, len);
    for (size_t i = 0; i < len; i++) {
        fprintf(stderr, "%02x ", pc[i]);
        if ((i + 1) % 16 == 0) fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s host port\n", argv[0]);
        return 1;
    }

    // Allocate a dummy area for coverage
    __afl_area_ptr = calloc(1, MAP_SIZE);

    // Create socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    // Connect to server
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(atoi(argv[2]));
    inet_pton(AF_INET, argv[1], &server_addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        return 1;
    }
    fprintf(stderr, "Connected to server %s:%s\n", argv[1], argv[2]);

    // Buffer for test cases
    unsigned char buffer[65536];

    // Use a hardcoded test case "FUZZTEST\n"
    const char *test_data = "FUZZTEST\n";
    unsigned int size = strlen(test_data);
    memcpy(buffer + 4, test_data, size);

    // Main loop - just send the test case once
    {
        // Prepare size in little-endian format
        unsigned char size_buf[4];
        size_buf[0] = size & 0xFF;
        size_buf[1] = (size >> 8) & 0xFF;
        size_buf[2] = (size >> 16) & 0xFF;
        size_buf[3] = (size >> 24) & 0xFF;

        fprintf(stderr, "Sending testcase with size %u bytes\n", size);
        print_hex("Size", size_buf, 4);

        // First send just the size (4 bytes)
        if (send(sock, size_buf, 4, 0) != 4) {
            perror("send size");
            return 1;
        }

        // Then send the actual data
        if (send(sock, buffer + 4, size, 0) != size) {
            perror("send data");
            return 1;
        }

        // Receive response (coverage map)
        unsigned char response[65536];
        int received = 0;
        int ret;

        // First receive the status (4 bytes)
        while (received < 4 && (ret = recv(sock, response + received, 4 - received, 0)) > 0) {
            received += ret;
        }

        if (received != 4) {
            fprintf(stderr, "Failed to receive status\n");
            return 1;
        }

        // Extract status
        int result_status;
        memcpy(&result_status, response, 4);

        // Now receive the coverage map
        received = 0;
        while (received < __afl_map_size &&
               (ret = recv(sock, __afl_area_ptr + received, __afl_map_size - received, 0)) > 0) {
            received += ret;
        }

        if (received != __afl_map_size) {
            fprintf(stderr, "Failed to receive coverage map\n");
            return 1;
        }

        // We're not running under AFL, so no need to report status
        fprintf(stderr, "Test completed with status: %d\n", result_status);
    }

    close(sock);
    free(__afl_area_ptr);
    return 0;
}
