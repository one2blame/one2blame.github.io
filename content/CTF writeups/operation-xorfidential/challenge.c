#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

unsigned char master_key_encoded[] = { 0x16, 0x07, 0x00, 0x0f, 0x01, 0x0d };

struct VulnerablePayload {
    char buffer[128];
    volatile int canary;
    void (*action_ptr)();
};

void execute_priority_override() {
    char master_key_input[100] = {0};
    char decoded_master_key[100] = {0};
    const char* cipher_key_string = "CHIMERA";
    int key_len = strlen(cipher_key_string);

    printf("\a\n\n*** PRIORITY OVERRIDE ACCEPTED. MAINFRAME I/O ACTIVE. ***\n");
    printf("Enter Master Decryption Key: ");
    
    read(0, master_key_input, 99);
    master_key_input[strcspn(master_key_input, "\n")] = 0;

    for (int i = 0; i < sizeof(master_key_encoded); i++) {
        decoded_master_key[i] = master_key_encoded[i] ^ cipher_key_string[i % key_len];
    }

    if (strncmp(master_key_input, decoded_master_key, sizeof(master_key_encoded)) == 0) {
        printf("\n[+] MASTER KEY ACCEPTED. DECRYPTING DATASTORE...\n\n");
        
        FILE *fp;
        char b64_credential[200];
        const char* secret_file_path = "/opt/h3x_data/.creds";
        fp = fopen(secret_file_path, "r");

        if (fp != NULL) {
            if (fgets(b64_credential, sizeof(b64_credential), fp)) {
                b64_credential[strcspn(b64_credential, "\n")] = 0;
                printf("Leaked Datastream (AK): %s\n", b64_credential);
            }

            if (fgets(b64_credential, sizeof(b64_credential), fp)) {
                b64_credential[strcspn(b64_credential, "\n")] = 0;
                printf("Leaked Datastream (SK): %s\n", b64_credential);
            }
            
            fclose(fp);
        } else {
            printf("[FATAL] DATASTORE INACCESSIBLE.\n");
        }

    } else {
        printf("\n[!] INCORRECT KEY. COUNTER-INTELLIGENCE PROTOCOLS ENGAGED.\n");
    }

    printf("\n*** TRANSMISSION TERMINATED ***\n\n");
    exit(0);
}

void check_system_integrity(const char* input) { printf("[+] System integrity check... PASSED.\n"); }
void validate_user_permissions(const char* input) { printf("[+] User permissions... VALID.\n"); }

void process_secure_request(const char* initial_input) {
    struct VulnerablePayload data;

    data.canary = 0xBADBEEF1 ^ (int)initial_input[0];
    data.action_ptr = NULL;

    printf("\n[+] Security Handshake Verified. Awaiting Command...\n");
    printf("Enter Command Payload: ");

    read(0, data.buffer, 136);

    if (data.canary != (0xBADBEEF1 ^ (int)initial_input[0])) {
        printf("\n[!] TAMPERING DETECTED! CONNECTION TERMINATED.\n");
        exit(-1);
    }
    
    if (data.action_ptr != NULL) {
        printf("\n[+] Payload Authenticated. Executing...\n");
        data.action_ptr();
    } else {
        printf("\n[!] Payload Authentication Failed.\n");
    }
}

int main() {
    void (*function_dispatch_table[3])(const char*) = {
        &process_secure_request,
        &check_system_integrity,
        &validate_user_permissions
    };

    char initial_trigger[8];
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("=== H3X N0V4 Secure Kernel Interface v3.0 ===\n");
    printf("Enter Handshake Key: ");

    read(0, initial_trigger, 8);

    if (initial_trigger[0] == 'A') {
        printf("... Handshake Key Accepted. Routing to Secure Channel ...\n");
        function_dispatch_table[0](initial_trigger);
    } else {
        printf("... Invalid Handshake Key ...\n");
    }

    return 0;
}