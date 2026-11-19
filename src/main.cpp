#include "core/AccountDeletion.h"
#include "core/Config.h"
#include "core/Logger.h"
#include "core/OperatorCommands.h"
#include "core/IdentityServer.h"
#include "core/PasswordReset.h"
#include "core/Version.h"
#include "store/IdentityStore.h"

#include <csignal>
#include <cstdio>
#include <filesystem>
#include <iostream>
#include <memory>
#include <optional>
#include <string>

#include <termios.h>
#include <unistd.h>

static std::unique_ptr<bsfchat::id::IdentityServer> g_server;

void signal_handler(int) {
    if (g_server) g_server->stop();
}

namespace {

constexpr const char* kUsage =
    "usage: bsfchat-id [--config <file>]\n"
    "       bsfchat-id [--config <file>] --reset-password <username>\n"
    "       bsfchat-id [--config <file>] --delete-account <username>\n"
    "       bsfchat-id [--config <file>] --grant-admin <username>\n"
    "       bsfchat-id [--config <file>] --revoke-admin <username>\n"
    "       bsfchat-id [--config <file>] --disable-2fa <username>\n"
    "\n"
    "  --config <file>              TOML configuration (default: built-in defaults)\n"
    "  --reset-password <username>  set a new password for <username>, read from stdin\n"
    "                               (not echoed on a terminal), sign the account out\n"
    "                               everywhere, and exit. The service may keep running.\n"
    "  --delete-account <username>  delete <username>'s personal data, 2FA, sign-ins and\n"
    "                               server list, keep the name reserved, and exit.\n"
    "                               Irreversible; asks for the username again on a terminal.\n"
    "  --grant-admin <username>     make <username> an administrator (the admin page and the\n"
    "                               admin API). The first account registered on a new\n"
    "                               database is made one automatically.\n"
    "  --revoke-admin <username>    take administrator rights away; refused for the last one.\n"
    "  --disable-2fa <username>     remove <username>'s two-factor authentication (lost\n"
    "                               authenticator AND backup codes) and sign them out\n"
    "                               everywhere. Check it is really them first.\n"
    "  --help                       show this help\n";

struct Options {
    std::optional<std::string> config_path;
    std::optional<std::string> reset_username;
    std::optional<std::string> delete_username;
    std::optional<std::string> grant_admin_username;
    std::optional<std::string> revoke_admin_username;
    std::optional<std::string> disable_2fa_username;
    bool help = false;

    int command_count() const {
        return int(reset_username.has_value()) + int(delete_username.has_value()) +
               int(grant_admin_username.has_value()) + int(revoke_admin_username.has_value()) +
               int(disable_2fa_username.has_value());
    }
};

// Returns nullopt (after printing why) on a malformed command line.
std::optional<Options> parse_args(int argc, char* argv[]) {
    Options opts;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        const auto value = [&](const char* name) -> std::optional<std::string> {
            if (i + 1 >= argc) {
                std::cerr << "bsfchat-id: " << name << " needs a value\n" << kUsage;
                return std::nullopt;
            }
            return std::string(argv[++i]);
        };
        if (arg == "--config") {
            auto v = value("--config");
            if (!v) return std::nullopt;
            opts.config_path = *v;
        } else if (arg == "--reset-password") {
            auto v = value("--reset-password");
            if (!v) return std::nullopt;
            opts.reset_username = *v;
        } else if (arg == "--delete-account") {
            auto v = value("--delete-account");
            if (!v) return std::nullopt;
            opts.delete_username = *v;
        } else if (arg == "--grant-admin" || arg == "--revoke-admin" || arg == "--disable-2fa") {
            auto v = value(arg.c_str());
            if (!v) return std::nullopt;
            (arg == "--grant-admin"    ? opts.grant_admin_username
             : arg == "--revoke-admin" ? opts.revoke_admin_username
                                       : opts.disable_2fa_username) = *v;
        } else if (arg == "--help" || arg == "-h") {
            opts.help = true;
        } else {
            std::cerr << "bsfchat-id: unknown argument '" << arg << "'\n" << kUsage;
            return std::nullopt;
        }
    }
    if (opts.command_count() > 1) {
        std::cerr << "bsfchat-id: give one operator command at a time\n";
        return std::nullopt;
    }
    return opts;
}

// Terminal state to put back if the operator presses Ctrl-C at the prompt,
// so their shell is not left without echo.
termios g_saved_termios{};
volatile std::sig_atomic_t g_echo_disabled = 0;

void restore_echo_and_exit(int) {
    if (g_echo_disabled) tcsetattr(STDIN_FILENO, TCSANOW, &g_saved_termios);
    _exit(130);
}

// Reads one line from stdin. On a terminal the prompt goes to stderr and the
// typed characters are not echoed; piped input is read as-is, so
//   printf '%s\n' "$NEW" | bsfchat-id ... --reset-password alice
// works from a script. A trailing CR (a Windows-edited file) is dropped.
std::optional<std::string> read_secret_line(const char* prompt) {
    const bool tty = isatty(STDIN_FILENO);
    if (tty) {
        std::cerr << prompt << std::flush;
        if (tcgetattr(STDIN_FILENO, &g_saved_termios) == 0) {
            termios quiet = g_saved_termios;
            quiet.c_lflag &= ~static_cast<tcflag_t>(ECHO);
            std::signal(SIGINT, restore_echo_and_exit);
            std::signal(SIGTERM, restore_echo_and_exit);
            if (tcsetattr(STDIN_FILENO, TCSANOW, &quiet) == 0) g_echo_disabled = 1;
        }
    }
    std::string line;
    const bool got = static_cast<bool>(std::getline(std::cin, line));
    if (g_echo_disabled) {
        tcsetattr(STDIN_FILENO, TCSANOW, &g_saved_termios);
        g_echo_disabled = 0;
    }
    if (tty) std::cerr << "\n";
    if (!got) return std::nullopt;
    if (!line.empty() && line.back() == '\r') line.pop_back();
    return line;
}

// Opens the service's existing database for an operator command, or prints
// why not and returns null.
std::unique_ptr<bsfchat::id::IdentityStore> open_existing_store(const bsfchat::id::Config& config) {
    // Refuse rather than create: sqlite would happily make a new, empty
    // database at a mistyped path and report "no such account", which reads
    // like the account is gone.
    std::error_code ec;
    if (!std::filesystem::is_regular_file(config.database_path, ec)) {
        std::cerr << "bsfchat-id: cannot open the database: '" << config.database_path
                  << "' does not exist or is not a file. Pass the service's --config.\n";
        return nullptr;
    }

    std::unique_ptr<bsfchat::id::IdentityStore> store;
    try {
        store = std::make_unique<bsfchat::id::IdentityStore>(config.database_path);
        // Idempotent; a no-op on a database the running service has opened.
        store->initialize();
    } catch (const std::exception& e) {
        std::cerr << "bsfchat-id: cannot open the database '" << config.database_path
                  << "': " << e.what() << "\n";
        return nullptr;
    }
    return store;
}

int run_delete_account(const bsfchat::id::Config& config, const std::string& username) {
    using bsfchat::id::AccountDeletionResult;

    auto store = open_existing_store(config);
    if (!store) return 1;

    auto account = store->get_account_by_username(username);
    if (!account) {
        std::cerr << "bsfchat-id: no account is named '" << username << "'\n";
        return 1;
    }
    // Asked before the confirmation prompt; delete_account() re-checks it.
    if (store->is_last_admin(account->id)) {
        std::cerr << "bsfchat-id: '" << account->username << "' is the only administrator "
                     "left; grant another account with --grant-admin <username> first. "
                     "Nothing was changed\n";
        return 1;
    }
    // On a terminal, the same "type the name" confirmation the web page asks
    // for. Piped (a script), the command line is taken as the decision.
    if (isatty(STDIN_FILENO)) {
        std::cerr << "This permanently deletes '" << account->username << "' (" << account->id
                  << "). Chat servers keep their own accounts and messages.\n"
                  << "Type the username again to confirm: " << std::flush;
        std::string typed;
        if (!std::getline(std::cin, typed) || typed != account->username) {
            std::cerr << "bsfchat-id: not confirmed; nothing was changed\n";
            return 1;
        }
    }

    AccountDeletionResult result;
    try {
        result = bsfchat::id::delete_account_by_username(*store, username);
    } catch (const std::exception& e) {
        std::cerr << "bsfchat-id: account deletion failed: " << e.what() << "\n";
        return 1;
    }
    if (result.status != AccountDeletionResult::Status::Deleted) {
        std::cerr << "bsfchat-id: " << result.message << "; nothing was changed\n";
        return 1;
    }
    std::cout << result.message << ".\n"
              << "Chat servers the user joined still hold their own account and messages; "
                 "deactivate it on each server separately if asked to.\n";
    return 0;
}

int run_reset_password(const bsfchat::id::Config& config, const std::string& username) {
    using bsfchat::id::PasswordResetResult;

    auto store = open_existing_store(config);
    if (!store) return 1;

    // Look the account up before asking for a password, so a typo in the
    // username is reported before anyone types a secret.
    auto account = store->get_account_by_username(username);
    if (!account) {
        std::cerr << "bsfchat-id: no account is named '" << username << "'\n";
        return 1;
    }
    // A tombstone stays without a password (audit I2-4).
    if (account->deleted()) {
        std::cerr << "bsfchat-id: the account '" << username
                  << "' was deleted and cannot be given a password; nothing was changed\n";
        return 1;
    }

    auto password = read_secret_line("New password: ");
    if (!password) {
        std::cerr << "bsfchat-id: no password given on stdin\n";
        return 1;
    }
    if (isatty(STDIN_FILENO)) {
        auto again = read_secret_line("Repeat new password: ");
        if (!again || *again != *password) {
            std::cerr << "bsfchat-id: the passwords do not match; nothing was changed\n";
            return 1;
        }
    }

    PasswordResetResult result;
    try {
        result = bsfchat::id::reset_account_password(*store, username, *password,
                                                     config.password_hash_iterations);
    } catch (const std::exception& e) {
        std::cerr << "bsfchat-id: password reset failed: " << e.what() << "\n";
        return 1;
    }
    if (result.status != PasswordResetResult::Status::Reset) {
        std::cerr << "bsfchat-id: " << result.message << "; nothing was changed\n";
        return 1;
    }
    std::cout << result.message << ".\n"
              << "Give the user the new password over a channel you trust and ask them to "
                 "change it after signing in. A login lockout from earlier failed attempts "
                 "still runs out on its own (login_lockout_seconds) or when the service "
                 "restarts.\n";
    return 0;
}

// --grant-admin, --revoke-admin, --disable-2fa (core/OperatorCommands.h).
int run_operator_command(const bsfchat::id::Config& config, const Options& opts) {
    auto store = open_existing_store(config);
    if (!store) return 1;
    bsfchat::id::OperatorResult result;
    try {
        if (opts.grant_admin_username) {
            result = bsfchat::id::set_admin_by_username(*store, *opts.grant_admin_username, true);
        } else if (opts.revoke_admin_username) {
            result = bsfchat::id::set_admin_by_username(*store, *opts.revoke_admin_username, false);
        } else {
            result = bsfchat::id::disable_2fa_by_username(*store, *opts.disable_2fa_username);
        }
    } catch (const std::exception& e) {
        std::cerr << "bsfchat-id: " << e.what() << "\n";
        return 1;
    }
    if (!result.ok) {
        std::cerr << "bsfchat-id: " << result.message << "; nothing was changed\n";
        return 1;
    }
    std::cout << result.message << ".\n";
    return 0;
}

} // namespace

int main(int argc, char* argv[]) {
    auto opts = parse_args(argc, argv);
    if (!opts) return 2;
    if (opts->help) {
        std::cout << kUsage;
        return 0;
    }
    const bool reset_mode = opts->command_count() > 0;

    // The operator command keeps stdout for its own answer; only warnings
    // and errors from loading the config are logged.
    bsfchat::id::init_logger(reset_mode ? "warn" : "info");
    auto log = bsfchat::id::get_logger();

    // First line in the log, before config loading can fail: the build
    // that produced a log excerpt is the first thing worth knowing, and a
    // config error must not swallow it.
    log->info("BSFChat identity {}", bsfchat::id::build::describe());

    bsfchat::id::Config config;
    if (opts->config_path) {
        try {
            config = bsfchat::id::Config::load(*opts->config_path);
            log->info("Loaded config from {}", *opts->config_path);
        } catch (const std::exception& e) {
            log->error("Failed to load config: {}", e.what());
            return 1;
        }
    } else {
        config = bsfchat::id::Config::defaults();
        log->info("Using default configuration");
    }

    if (opts->delete_username) return run_delete_account(config, *opts->delete_username);
    if (opts->reset_username) return run_reset_password(config, *opts->reset_username);
    if (reset_mode) return run_operator_command(config, *opts);

    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    try {
        g_server = std::make_unique<bsfchat::id::IdentityServer>(std::move(config));
        g_server->start();
    } catch (const std::exception& e) {
        log->error("Server error: {}", e.what());
        return 1;
    }

    return 0;
}
