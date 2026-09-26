/*
 * Harmless test sample for the reverse-engineering tools.
 *
 * It mimics the *shape* of a simple implant so the tools have something
 * realistic to find -- an XOR-obfuscated "C2" string, a config struct, a
 * decode routine and a Run-key path -- but it performs no network or
 * registry access: every "action" only prints what it would have done.
 * The domain uses the reserved .invalid TLD (RFC 2606).
 */
#include <stdio.h>
#include <string.h>

#define XOR_KEY 0x5A

/* "http://c2.example.invalid/beacon" XOR 0x5A */
static const unsigned char enc_url[] = {
    0x32, 0x2e, 0x2e, 0x2a, 0x60, 0x75, 0x75, 0x39, 0x68, 0x74, 0x3f,
    0x22, 0x3b, 0x37, 0x2a, 0x36, 0x3f, 0x74, 0x33, 0x34, 0x2c, 0x3b,
    0x36, 0x33, 0x3e, 0x75, 0x38, 0x3f, 0x3b, 0x39, 0x35, 0x34, 0x00};

struct beacon_config {
    unsigned int sleep_seconds;
    unsigned int jitter_percent;
    const char *run_key;
};

static const struct beacon_config g_config = {
    60, 20, "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\ToyBeacon"};

void xor_decode(const unsigned char *in, char *out, size_t len, unsigned char key)
{
    size_t i;
    for (i = 0; i < len; i++) {
        out[i] = (char)(in[i] ^ key);
    }
    out[len] = '\0';
}

int install_persistence(const struct beacon_config *cfg)
{
    printf("[toy] would write HKCU\\%s\n", cfg->run_key);
    return 0;
}

int send_beacon(const char *url, unsigned int sleep_s)
{
    printf("[toy] would contact %s every %u s\n", url, sleep_s);
    return 0;
}

int main(void)
{
    char url[64];
    xor_decode(enc_url, url, sizeof(enc_url) - 1, XOR_KEY);
    install_persistence(&g_config);
    return send_beacon(url, g_config.sleep_seconds);
}
