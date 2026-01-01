#include <erl_nif.h>
#include <erl_driver.h>
#include <errno.h>
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

static ErlNifFunc nif_funcs[] = {
    {"get_mtu", 1, get_mtu_nif, 0}
};

ERL_NIF_INIT(Elixir.Tricep.Nifs, nif_funcs, load, NULL, NULL, NULL)
