#pragma once

#include <string>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <memory>

namespace windbg_agent {

// Callbacks for handling requests (same types as http_server/mcp_server)
using ExecCallback = std::function<std::string(const std::string& command)>;
using BreakCallback = std::function<void()>;

// Internal command structure for cross-thread execution
struct WsPendingCommand {
    enum class Type { Exec };
    Type type;
    std::string input;
    int request_id = 0;
};

// Context info sent in help/get_context responses
struct SessionContext {
    std::string target_name;
    std::string target_arch;
    std::string debugger_type;
    std::string target_state;
    unsigned long pid = 0;
    std::string version;
};

class WsClient {
public:
    WsClient();
    ~WsClient();

    // Non-copyable
    WsClient(const WsClient&) = delete;
    WsClient& operator=(const WsClient&) = delete;

    // Connect to WebSocket server and start receiving messages
    // Returns true if connection established successfully
    bool connect(const std::string& ws_url,
                 ExecCallback exec_cb,
                 BreakCallback break_cb = nullptr);

    // Block until disconnected, processing commands on the calling thread
    // This is where exec_cb gets called (on the debugger thread)
    void wait();

    // Disconnect from server
    void disconnect();

    // Check if connected
    bool is_connected() const { return connected_.load(); }

    // Get the WebSocket URL
    const std::string& url() const { return url_; }

    // Set session context for help/get_context responses
    void set_session_context(const SessionContext& ctx);

    // Set interrupt check function (called during wait loop)
    void set_interrupt_check(std::function<bool()> check);

private:
    // Queue a command for execution on the main thread (called from recv thread)
    void queue_command(WsPendingCommand::Type type, const std::string& input, int request_id);

    // WebSocket receive thread
    void receive_loop();

    // Handle a single incoming JSON-RPC 2.0 request, return response JSON string
    std::string handle_jsonrpc_request(const std::string& message);

    // Build help/capability response JSON
    std::string build_help_response(int id);

    // Build JSON-RPC error response
    std::string build_error_response(int id, int code, const std::string& message);

    // Send a message over WebSocket (thread-safe)
    void send_message(const std::string& message);

    // Attempt reconnection with exponential backoff
    bool try_reconnect();

    std::function<bool()> interrupt_check_;
    std::string url_;
    std::atomic<bool> connected_{false};
    std::atomic<bool> should_stop_{false};

    // Session context (protected by mutex for thread-safe reads)
    mutable std::mutex context_mutex_;
    SessionContext session_context_;

    // Command queue for cross-thread execution
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    std::queue<WsPendingCommand*> pending_commands_;

    // Callbacks stored for main thread execution
    ExecCallback exec_cb_;
    BreakCallback break_cb_;

    // Break support
    std::atomic<bool> break_requested_{false};
    std::atomic<bool> executing_{false};

    // Forward declaration - impl hides easywsclient
    class Impl;
    std::unique_ptr<Impl> impl_;

    // Receive thread
    std::thread recv_thread_;

    // Send serialization (easywsclient::send is not thread-safe)
    std::mutex send_mutex_;

    // Reconnection settings
    static constexpr int kMaxReconnectAttempts = 5;
    static constexpr int kInitialReconnectDelayMs = 2000;
    static constexpr int kMaxReconnectDelayMs = 60000;
};

// Format WebSocket connection info for display
std::string format_ws_info(
    const std::string& target_name,
    unsigned long pid,
    const std::string& state,
    const std::string& ws_url
);

} // namespace windbg_agent
