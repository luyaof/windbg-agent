#include "ws_client.hpp"

#include <easywsclient.hpp>
#include <nlohmann/json.hpp>

#include <chrono>
#include <sstream>
#include <algorithm>

namespace windbg_agent {

using Json = nlohmann::json;

// ---------------------------------------------------------------------------
// Pimpl — hides easywsclient from the header
// ---------------------------------------------------------------------------

class WsClient::Impl {
public:
    easywsclient::WebSocket* ws = nullptr;

    ~Impl() {
        if (ws) {
            delete ws;
            ws = nullptr;
        }
    }
};

// ---------------------------------------------------------------------------
// Construction / Destruction
// ---------------------------------------------------------------------------

WsClient::WsClient() = default;

WsClient::~WsClient() {
    disconnect();
}

// ---------------------------------------------------------------------------
// connect — establish WebSocket connection and start recv thread
// ---------------------------------------------------------------------------

bool WsClient::connect(const std::string& ws_url,
                        ExecCallback exec_cb,
                        BreakCallback break_cb) {
    if (connected_.load()) {
        return false;  // Already connected
    }

    // Validate URL scheme
    if (ws_url.substr(0, 5) != "ws://" && ws_url.substr(0, 6) != "wss://") {
        return false;
    }

    url_ = ws_url;
    exec_cb_ = exec_cb;
    break_cb_ = break_cb;
    should_stop_.store(false);

    // Create WebSocket connection
    impl_ = std::make_unique<Impl>();
    impl_->ws = easywsclient::WebSocket::from_url(url_);

    if (!impl_->ws || impl_->ws->getReadyState() != easywsclient::WebSocket::OPEN) {
        impl_.reset();
        return false;
    }

    connected_.store(true);

    // Start receive thread
    recv_thread_ = std::thread([this]() { receive_loop(); });

    return true;
}

// ---------------------------------------------------------------------------
// disconnect — clean shutdown
// ---------------------------------------------------------------------------

void WsClient::disconnect() {
    should_stop_.store(true);
    connected_.store(false);
    queue_cv_.notify_all();

    // Drain and free heap-allocated pending commands
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        while (!pending_commands_.empty()) {
            delete pending_commands_.front();
            pending_commands_.pop();
        }
    }

    if (impl_ && impl_->ws) {
        std::lock_guard<std::mutex> lock(send_mutex_);
        impl_->ws->close();
        // Poll once to flush the close frame
        impl_->ws->poll(0);
    }

    if (recv_thread_.joinable()) {
        recv_thread_.join();
    }

    impl_.reset();
}

// ---------------------------------------------------------------------------
// set_session_context / set_interrupt_check
// ---------------------------------------------------------------------------

void WsClient::set_session_context(const SessionContext& ctx) {
    std::lock_guard<std::mutex> lock(context_mutex_);
    session_context_ = ctx;
}

void WsClient::set_interrupt_check(std::function<bool()> check) {
    interrupt_check_ = check;
}

// ---------------------------------------------------------------------------
// queue_command — called from recv thread, returns immediately (non-blocking)
// ---------------------------------------------------------------------------

void WsClient::queue_command(WsPendingCommand::Type type, const std::string& input, int request_id) {
    auto* cmd = new WsPendingCommand();
    cmd->type = type;
    cmd->input = input;
    cmd->request_id = request_id;

    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        pending_commands_.push(cmd);
    }
    queue_cv_.notify_one();
}

// ---------------------------------------------------------------------------
// receive_loop — background thread: polls WebSocket, dispatches messages
// ---------------------------------------------------------------------------

void WsClient::receive_loop() {
    while (!should_stop_.load()) {
        // Check connection state
        if (!impl_ || !impl_->ws ||
            impl_->ws->getReadyState() == easywsclient::WebSocket::CLOSED) {
            if (!try_reconnect()) {
                connected_.store(false);
                queue_cv_.notify_all();
                break;
            }
        }

        {
            std::lock_guard<std::mutex> lock(send_mutex_);
            if (impl_ && impl_->ws) {
                impl_->ws->poll(100);
            }
        }

        if (impl_ && impl_->ws) {
            impl_->ws->dispatch([this](const std::string& message) {
                std::string response = handle_jsonrpc_request(message);
                if (!response.empty()) {
                    send_message(response);
                }
            });
        }
    }
}

// ---------------------------------------------------------------------------
// handle_jsonrpc_request — parse and route incoming JSON-RPC 2.0 messages
// ---------------------------------------------------------------------------

std::string WsClient::handle_jsonrpc_request(const std::string& message) {
    Json req;
    try {
        req = Json::parse(message);
    } catch (...) {
        return build_error_response(0, -32700, "Parse error");
    }

    // Validate JSON-RPC 2.0 envelope
    if (!req.contains("jsonrpc") || req["jsonrpc"] != "2.0") {
        int id = req.value("id", 0);
        return build_error_response(id, -32600, "Invalid Request: missing jsonrpc 2.0");
    }

    if (!req.contains("method") || !req["method"].is_string()) {
        int id = req.value("id", 0);
        return build_error_response(id, -32600, "Invalid Request: missing method");
    }

    if (!req.contains("id")) {
        // Notification (no id) — we don't need to respond
        // But we could handle it if needed in the future
        return "";
    }

    int id = 0;
    if (req["id"].is_number()) {
        id = req["id"].get<int>();
    }

    std::string method = req["method"].get<std::string>();
    Json params = req.value("params", Json::object());

    // Route by method
    if (method == "ping") {
        Json response = {
            {"jsonrpc", "2.0"},
            {"id", id},
            {"result", {{"status", "ok"}}}
        };
        return response.dump();
    }
    else if (method == "break") {
        if (!executing_.load()) {
            Json response = {
                {"jsonrpc", "2.0"},
                {"id", id},
                {"result", {{"status", "no_command_running"}, {"success", true}}}
            };
            return response.dump();
        }

        break_requested_.store(true);
        if (break_cb_) {
            break_cb_();
        }

        Json response = {
            {"jsonrpc", "2.0"},
            {"id", id},
            {"result", {{"status", "break_requested"}, {"success", true}}}
        };
        return response.dump();
    }
    else if (method == "exec") {
        std::string command = params.value("command", "");
        if (command.empty()) {
            // Empty command = discovery/help request (used by ws-proxy)
            return build_help_response(id);
        }

        queue_command(WsPendingCommand::Type::Exec, command, id);
        return "";  // Response sent later by main thread
    }
    else {
        return build_error_response(id, -32601,
            "Method not found: " + method);
    }
}

// ---------------------------------------------------------------------------
// build_help_response — capability advertisement
// ---------------------------------------------------------------------------

std::string WsClient::build_help_response(int id) {
    SessionContext ctx;
    {
        std::lock_guard<std::mutex> lock(context_mutex_);
        ctx = session_context_;
    }

    Json commands = Json::array({
        {
            {"name", "exec"},
            {"description", "Execute a WinDbg/CDB debugger command and return its text output"},
            {"params", {
                {"command", {{"type", "string"}, {"required", true},
                    {"description", "Debugger command (e.g., 'kb', '!analyze -v', 'dt ntdll!_PEB @$peb')"}}}
            }}
        },
        {
            {"name", "break"},
            {"description", "Interrupt a currently running debugger command"},
            {"params", Json::object()}
        },
        {
            {"name", "ping"},
            {"description", "Heartbeat / keepalive check"},
            {"params", Json::object()}
        }
    });

    Json session_info = {
        {"target_name", ctx.target_name},
        {"target_arch", ctx.target_arch},
        {"debugger_type", ctx.debugger_type},
        {"target_state", ctx.target_state},
        {"pid", ctx.pid}
    };

    Json response = {
        {"jsonrpc", "2.0"},
        {"id", id},
        {"result", {
            {"agent", "windbg-agent"},
            {"version", ctx.version},
            {"protocol", "jsonrpc-2.0-over-websocket"},
            {"commands", commands},
            {"session_info", session_info}
        }}
    };

    return response.dump();
}

// ---------------------------------------------------------------------------
// build_error_response — JSON-RPC 2.0 error
// ---------------------------------------------------------------------------

std::string WsClient::build_error_response(int id, int code, const std::string& message) {
    Json response = {
        {"jsonrpc", "2.0"},
        {"id", id},
        {"error", {
            {"code", code},
            {"message", message}
        }}
    };
    return response.dump();
}

// ---------------------------------------------------------------------------
// send_message — thread-safe WebSocket send
// ---------------------------------------------------------------------------

void WsClient::send_message(const std::string& message) {
    std::lock_guard<std::mutex> lock(send_mutex_);
    if (impl_ && impl_->ws &&
        impl_->ws->getReadyState() == easywsclient::WebSocket::OPEN) {
        impl_->ws->send(message);
        impl_->ws->poll(0);  // Flush
    }
}

// ---------------------------------------------------------------------------
// wait — main thread event loop (blocks debugger, processes commands)
// ---------------------------------------------------------------------------

void WsClient::wait() {
    while (connected_.load() && !should_stop_.load()) {
        // Check for Ctrl+C interrupt
        if (interrupt_check_ && interrupt_check_()) {
            if (break_requested_.exchange(false)) {
                // Interrupt was caused by break — don't disconnect, just continue
                continue;
            }
            // Real Ctrl+C — disconnect
            disconnect();
            break;
        }

        WsPendingCommand* cmd = nullptr;

        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            if (queue_cv_.wait_for(lock, std::chrono::milliseconds(100),
                                   [this]() { return !pending_commands_.empty() ||
                                              !connected_.load() || should_stop_.load(); })) {
                if (!pending_commands_.empty()) {
                    cmd = pending_commands_.front();
                    pending_commands_.pop();
                }
            }
        }

        if (cmd) {
            std::string output;
            bool success = false;

            try {
                executing_.store(true);
                if (cmd->type == WsPendingCommand::Type::Exec && exec_cb_) {
                    output = exec_cb_(cmd->input);
                    success = true;
                } else {
                    output = "Error: No handler for command type";
                }
                executing_.store(false);
            } catch (const std::exception& e) {
                executing_.store(false);
                output = std::string("Error: ") + e.what();
            }

            Json response = {
                {"jsonrpc", "2.0"},
                {"id", cmd->request_id},
                {"result", {{"output", output}, {"success", success}}}
            };
            send_message(response.dump());
            delete cmd;
        }
    }

    // Ensure recv thread is joined
    if (recv_thread_.joinable()) {
        should_stop_.store(true);
        recv_thread_.join();
    }
}

// ---------------------------------------------------------------------------
// try_reconnect — exponential backoff reconnection
// ---------------------------------------------------------------------------

bool WsClient::try_reconnect() {
    int delay_ms = kInitialReconnectDelayMs;

    for (int attempt = 1; attempt <= kMaxReconnectAttempts; ++attempt) {
        if (should_stop_.load()) return false;

        std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));

        if (should_stop_.load()) return false;

        auto* new_ws = easywsclient::WebSocket::from_url(url_);
        if (new_ws && new_ws->getReadyState() == easywsclient::WebSocket::OPEN) {
            std::lock_guard<std::mutex> lock(send_mutex_);
            if (impl_) {
                delete impl_->ws;
                impl_->ws = new_ws;
            }
            return true;
        }
        delete new_ws;

        // Exponential backoff with cap
        delay_ms = (std::min)(delay_ms * 2, kMaxReconnectDelayMs);
    }

    return false;
}

// ---------------------------------------------------------------------------
// format_ws_info — display information for the user
// ---------------------------------------------------------------------------

std::string format_ws_info(
    const std::string& target_name,
    unsigned long pid,
    const std::string& state,
    const std::string& ws_url
) {
    std::ostringstream ss;
    ss << "WEBSOCKET CLIENT CONNECTED\n";
    ss << "Target: " << target_name << " (PID " << pid << ")\n";
    ss << "State: " << state << "\n";
    ss << "Server: " << ws_url << "\n\n";

    ss << "PROTOCOL: JSON-RPC 2.0 over WebSocket\n";
    ss << "The server can send requests to this client session.\n\n";

    ss << "SUPPORTED METHODS (server -> client):\n";
    ss << "  exec         - Execute a debugger command\n";
    ss << "  break        - Interrupt a running command\n";
    ss << "  ping         - Heartbeat / keepalive\n";

    return ss.str();
}

} // namespace windbg_agent
