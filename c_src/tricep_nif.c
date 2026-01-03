#include <erl_nif.h>
#include <erl_driver.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/if.h>
#else
#include <net/if.h>
#endif

static ERL_NIF_TERM atom_ok;
static ERL_NIF_TERM atom_error;

// Checksum state for tracking pending bytes across iodata fragments
typedef struct {
    uint32_t sum;
    int has_pending;
    unsigned char pending;
} checksum_state_t;

// Process a single byte (used for integer bytes in iodata)
static void process_byte(checksum_state_t *state, unsigned char byte) {
    if (state->has_pending) {
        uint16_t word = ((uint16_t)state->pending << 8) | byte;
        state->sum += word;
        state->has_pending = 0;
    } else {
        state->pending = byte;
        state->has_pending = 1;
    }
}

static ERL_NIF_TERM make_error(ErlNifEnv *env, int err) {
    return enif_make_tuple2(env, atom_error, enif_make_atom(env, erl_errno_id(err)));
}

static int load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info) {
    (void)priv_data;
    (void)load_info;

    atom_ok = enif_make_atom(env, "ok");
    atom_error = enif_make_atom(env, "error");

    return 0;
}

static ERL_NIF_TERM get_mtu_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    ErlNifBinary bin;

    if (argc != 1 || !enif_inspect_binary(env, argv[0], &bin)) {
        return enif_make_badarg(env);
    }

    if (bin.size >= IFNAMSIZ) {
        return make_error(env, ENAMETOOLONG);
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, bin.data, bin.size);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return make_error(env, errno);
    }

    if (ioctl(sock, SIOCGIFMTU, &ifr) < 0) {
        int err = errno;
        close(sock);
        return make_error(env, err);
    }

    close(sock);

    return enif_make_tuple2(env, atom_ok, enif_make_int(env, ifr.ifr_mtu));
}

// Compute one's complement checksum over iodata using graph reduction
static ERL_NIF_TERM checksum_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    if (argc != 1) {
        return enif_make_badarg(env);
    }

    checksum_state_t state = {0, 0, 0};

    // Initialize stack with the iodata argument
    ERL_NIF_TERM stack = enif_make_list1(env, argv[0]);
    ERL_NIF_TERM head, tail;

    while (enif_get_list_cell(env, stack, &head, &tail)) {
        if (enif_is_binary(env, head)) {
            // Process binary - optimized for 16-bit word access
            ErlNifBinary bin;
            enif_inspect_binary(env, head, &bin);
            size_t i = 0;

            // If we have a pending byte, pair it with first byte of this binary
            if (state.has_pending && bin.size > 0) {
                uint16_t word = ((uint16_t)state.pending << 8) | bin.data[0];
                state.sum += word;
                state.has_pending = 0;
                i = 1;
            }

            // Process aligned 16-bit words
            for (; i + 1 < bin.size; i += 2) {
                uint16_t word = ((uint16_t)bin.data[i] << 8) | bin.data[i + 1];
                state.sum += word;
            }

            // Handle trailing odd byte
            if (i < bin.size) {
                state.pending = bin.data[i];
                state.has_pending = 1;
            }

            stack = tail;
        } else if (enif_is_number(env, head)) {
            // Process single byte
            int byte_val;
            if (!enif_get_int(env, head, &byte_val) || byte_val < 0 || byte_val > 255) {
                return enif_make_badarg(env);
            }
            process_byte(&state, (unsigned char)byte_val);
            stack = tail;
        } else if (enif_is_list(env, head)) {
            // Nested list: pop its head, push its tail then head
            ERL_NIF_TERM nested_head, nested_tail;
            if (enif_get_list_cell(env, head, &nested_head, &nested_tail)) {
                // Push nested_tail onto stack, then nested_head on top
                stack = enif_make_list_cell(env, nested_tail, tail);
                stack = enif_make_list_cell(env, nested_head, stack);
            } else {
                // Empty nested list, just continue
                stack = tail;
            }
        } else if (enif_is_empty_list(env, head)) {
            // Skip empty lists
            stack = tail;
        } else {
            return enif_make_badarg(env);
        }
    }

    // Handle final odd byte
    if (state.has_pending) {
        state.sum += ((uint16_t)state.pending << 8);
    }

    // Fold 32-bit sum to 16-bit with carry
    while (state.sum >> 16) {
        state.sum = (state.sum & 0xFFFF) + (state.sum >> 16);
    }

    // Return one's complement
    return enif_make_uint(env, (~state.sum) & 0xFFFF);
}

static ErlNifFunc nif_funcs[] = {
    {"get_mtu", 1, get_mtu_nif, 0},
    {"checksum", 1, checksum_nif, 0}
};

ERL_NIF_INIT(Elixir.Tricep.Nifs, nif_funcs, load, NULL, NULL, NULL)
