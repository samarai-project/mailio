/*

dialog.cpp
----------

Copyright (C) 2016, Tomislav Karastojkovic (http://www.alepho.com).

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

*/


#include <string>
#include <algorithm>
#include <cstdlib>
#include <cstdio>
#include <limits>
#include <boost/algorithm/string/trim.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <mailio/dialog.hpp>
#include <mailio/base64.hpp>
#include <mutex>
#include <openssl/ssl.h>


using std::string;
using std::to_string;
using std::move;
using std::istream;
using std::make_shared;
using std::shared_ptr;
using std::bind;
using std::chrono::milliseconds;
using boost::asio::ip::tcp;
using boost::asio::buffer;
using boost::asio::streambuf;
using boost::asio::io_context;
using boost::asio::steady_timer;
using boost::asio::ssl::context;
using boost::system::system_error;
using boost::system::error_code;
using boost::algorithm::trim_if;
using boost::algorithm::is_any_of;

// #define DANGEROUSELY_LOG_SSL_KEYS
#ifdef DANGEROUSELY_LOG_SSL_KEYS
    #if defined(_MSC_VER)
        #pragma message("Warning: DANGEROUSELY_LOG_SSL_KEYS is defined. SSL keys will be logged if the SSLKEYLOGFILE environment variable is set. This is a security risk and should not be used in production.")
    #else
        #warning "DANGEROUSELY_LOG_SSL_KEYS is defined. SSL keys will be logged if the SSLKEYLOGFILE environment variable is set. This is a security risk and should not be used in production."
    #endif
#endif

namespace mailio
{


// No global io_context; each dialog owns its own to avoid cross-thread interference.

// Global log callback storage and synchronization.
namespace {
    std::mutex g_log_mutex;
    log_callback_t g_log_callback; // empty when no callback installed
}

void set_log_callback(log_callback_t cb)
{
    std::lock_guard<std::mutex> lock(g_log_mutex);
    g_log_callback = std::move(cb);
}

bool is_log_callback_installed()
{
    std::lock_guard<std::mutex> lock(g_log_mutex);
    return static_cast<bool>(g_log_callback);
}

void call_log_callback_or_fallback(const std::string& text)
{
    // Copy the callback under lock, then call without holding the mutex.
    log_callback_t cb_copy;
    {
        std::lock_guard<std::mutex> lock(g_log_mutex);
        cb_copy = g_log_callback;
    }
    if (cb_copy)
    {
        cb_copy(text);
        return;
    }
    // Fallback to stdout with a simple tag; avoid ANSI styling to keep portability.
    std::cout << "[MAILIO] [BUGFIX] " << text << "\n";
}

std::string b64_encode(const std::string& value, std::string::size_type line_policy)
{
    // SASL initial responses (e.g., XOAUTH2) must not be line-wrapped. Use a large line policy to keep the encoded value on one line.
    base64 b64(line_policy, line_policy);
    auto enc_v = b64.encode(value);
    std::stringstream res{};
    for (size_t i = 0; i < enc_v.size(); ++i)
        res << enc_v[i];
    return res.str();
}

dialog::dialog(const string& hostname, unsigned port, milliseconds timeout) : std::enable_shared_from_this<dialog>(),
    hostname_(hostname), port_(port), ios_(std::make_shared<io_context>()), socket_(make_shared<tcp::socket>(*ios_)), timer_(make_shared<steady_timer>(*ios_)),
    timeout_(timeout), timer_expired_(false), strmbuf_(make_shared<streambuf>()), istrm_(make_shared<istream>(strmbuf_.get()))
{
}


dialog::dialog(const dialog& other) : std::enable_shared_from_this<dialog>(),
    hostname_(move(other.hostname_)), port_(other.port_), ios_(other.ios_), socket_(other.socket_), timer_(other.timer_),
    timeout_(other.timeout_), timer_expired_(other.timer_expired_.load()), strmbuf_(other.strmbuf_), istrm_(other.istrm_),
    closed_(other.closed_), aborted_(other.aborted_.load()), session_name_(other.session_name_)
{
}
 
void dialog::connect()
{
    try
    {
        if (timeout_.count() == 0)
        {
            tcp::resolver res(*ios_);
            boost::asio::connect(*socket_, res.resolve(hostname_, to_string(port_)));
        }
        else
            connect_async();
    }
    catch (const system_error& exc)
    {
        throw dialog_error("Server connecting failed.", exc.code().message());
    }
}

void dialog::send(const string &line)
{
    debug_bugfix(session_name_, "SEND", line);
    if (aborted_.load(std::memory_order_acquire))
        throw dialog_planned_disconnect("Operation aborted.", "Planned disconnect");
#ifdef MAILIO_TEST_HOOKS
    if (sim_error_count_ > 0 && (sim_error_ == simulated_error_t::SEND_FAIL || sim_error_ == simulated_error_t::TIMEOUT_SEND))
    {
        --sim_error_count_;
        if (sim_error_ == simulated_error_t::SEND_FAIL)
            throw dialog_error("Network sending error.", "Simulated failure");
        if (sim_error_ == simulated_error_t::TIMEOUT_SEND)
            throw dialog_error("Network sending timed out.", "Simulated timeout");
    }
#endif
    try
    {
        if (timeout_.count() == 0)
            send_sync(*socket_, line);
        else
            send_async(*socket_, line);
    }
    catch (...)
    {
        if (aborted_.load(std::memory_order_acquire))
            throw dialog_planned_disconnect("Operation aborted.", "Planned disconnect");
        throw;
    }
}

// TODO: perhaps the implementation should be common with `receive_raw()`
string dialog::receive(bool raw)
{
    if (aborted_.load(std::memory_order_acquire))
        throw dialog_planned_disconnect("Operation aborted.", "Planned disconnect");
#ifdef MAILIO_TEST_HOOKS
    if (sim_error_count_ > 0 && (sim_error_ == simulated_error_t::RECV_FAIL || sim_error_ == simulated_error_t::TIMEOUT_RECV))
    {
        --sim_error_count_;
        if (sim_error_ == simulated_error_t::RECV_FAIL)
            throw dialog_error("Network receiving error.", "Simulated failure");
        if (sim_error_ == simulated_error_t::TIMEOUT_RECV)
            throw dialog_error("Network receiving timed out.", "Simulated timeout");
    }
#endif
    try
    {
        string res{};
        if (timeout_.count() == 0)
            res = receive_sync(*socket_, raw);
        else
            res = receive_async(*socket_, raw);
        debug_bugfix(session_name_, "RECEIVE", res);
        return res;
    }
    catch (...)
    {
        if (aborted_.load(std::memory_order_acquire))
            throw dialog_planned_disconnect("Operation aborted.", "Planned disconnect");
        throw;
    }
}

string dialog::receive_bytes(std::size_t total_bytes, std::size_t chunk_size)
{
    if (aborted_.load(std::memory_order_acquire))
        throw dialog_planned_disconnect("Operation aborted.", "Planned disconnect");
#ifdef MAILIO_TEST_HOOKS
    if (sim_error_count_ > 0 && (sim_error_ == simulated_error_t::RECV_FAIL || sim_error_ == simulated_error_t::TIMEOUT_RECV))
    {
        --sim_error_count_;
        if (sim_error_ == simulated_error_t::RECV_FAIL)
            throw dialog_error("Network receiving error.", "Simulated failure");
        if (sim_error_ == simulated_error_t::TIMEOUT_RECV)
            throw dialog_error("Network receiving timed out.", "Simulated timeout");
    }
#endif
    try
    {
        string res{};
        if (timeout_.count() == 0)
            res =  receive_exact_sync(*socket_, total_bytes);
        else
            res =  receive_exact_async(*socket_, total_bytes, chunk_size);
        debug_bugfix(session_name_, "RECEIVE", "[bin:" + std::to_string(res.size()) + "]");
        return res;
    }
    catch (...)
    {
        if (aborted_.load(std::memory_order_acquire))
            throw dialog_planned_disconnect("Operation aborted.", "Planned disconnect");
        throw;
    }
}

void dialog::close() noexcept
{
    try
    {
        if (closed_)
            return;
        closed_ = true;
        aborted_.store(true, std::memory_order_release);
        // Cancel timer if present to avoid any future callbacks.
        if (timer_ && timer_armed_.load())
        {
            try { timer_->cancel(); } catch (...) {}
            timer_armed_.store(false, std::memory_order_release);
        }

        // Shutdown and close the socket best-effort.
        if (socket_)
        {
            boost::system::error_code ec_ignore;
            socket_->shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec_ignore);
            socket_->close(ec_ignore);
        }
    }
    catch (...)
    {
        // Never throw from cleanup.
    }
}

void dialog::request_planned_interrupt()
{
    planned_interrupt_.store(true, std::memory_order_release);
    // If currently waiting, poke the socket so wait loop wakes promptly.
    if (in_wait_async_.load(std::memory_order_acquire) && socket_)
    {
        boost::system::error_code ec;
        socket_->cancel(ec);
    }
}

bool dialog::is_in_wait() const { 
    return in_wait_async_.load(std::memory_order_acquire); 
}

void dialog::abort_now() noexcept
{
    // Mark as aborted and close transport immediately to wake any blocking ops.
    aborted_.store(true, std::memory_order_release);
    try
    {
        // Best-effort cancel timer
        if (timer_ && timer_armed_.load())
        {
            try { timer_->cancel(); } catch (...) {}
            timer_armed_.store(false, std::memory_order_release);
        }
        if (socket_)
        {
            boost::system::error_code ec_ignore;
            socket_->cancel(ec_ignore);
            socket_->shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec_ignore);
            socket_->close(ec_ignore);
        }
        closed_ = true;
    }
    catch (...)
    {
        // swallow
    }
}


template<typename Socket>
void dialog::send_sync(Socket& socket, const string& line)
{
    try
    {
        string l = line + "\r\n";
        write(socket, buffer(l, l.size()));
    }
    catch (const system_error& exc)
    {
        throw dialog_error("Network sending error.", exc.code().message());
    }
}


template<typename Socket>
string dialog::receive_sync(Socket& socket, bool raw)
{
    try
    {
        read_until(socket, *strmbuf_, "\n");
        string line;
        getline(*istrm_, line, '\n');
        if (!raw)
            trim_if(line, is_any_of("\r\n"));
        return line;
    }
    catch (const system_error& exc)
    {
        throw dialog_error("Network receiving error.", exc.code().message());
    }
}


void dialog::connect_async()
{
    tcp::resolver res(*ios_);
    check_timeout();
    struct op_state { bool done{false}; bool error{false}; error_code ec; };
    auto st = std::make_shared<op_state>();
    auto self = shared_from_this();
    async_connect(*socket_, res.resolve(hostname_, to_string(port_)),
        [st, self](const error_code& error, const boost::asio::ip::tcp::endpoint&)
        {
            st->done  = !error;
            st->error = !!error;
            st->ec    = error;
        });
    wait_async(st->done, st->error, "Network connecting timed out.", "Network connecting failed.", st->ec);
}

template <typename Socket>
void dialog::send_async(Socket &socket, string line)
{
    try
    {
        check_timeout();
        // Keep the write buffer alive for the lifetime of the async operation.
        auto buf = std::make_shared<string>(move(line));
        buf->append("\r\n");
        struct op_state
        {
            bool done{false};
            bool error{false};
            error_code ec;
        };
        auto st = std::make_shared<op_state>();
        auto self = this->shared_from_this();
        async_write(socket, buffer(*buf),
                    [st, buf, self](const error_code &error, size_t)
                    {
                        st->done = !error;
                        st->error = !!error;
                        st->ec = error;
                    });
        wait_async(st->done, st->error, "Network sending timed out.", "Network sending failed.", st->ec);
    }
    catch (const dialog_error) {
        throw;
    }
    catch (const system_error &exc)
    {
        throw dialog_error("Network sending error.", exc.code().message());
    }
    catch (const std::exception &exc)
    {
        throw dialog_error("Network sending error.", exc.what());
    }
}

template <typename Socket>
string dialog::receive_async(Socket &socket, bool raw)
{
    try
    {
        check_timeout();
        struct op_state
        {
            bool done{false};
            bool error{false};
            error_code ec;
        };
        auto st = std::make_shared<op_state>();
        auto self = this->shared_from_this();
        async_read_until(socket, *strmbuf_, "\n",
                         [st, self](const error_code &error, size_t)
                         {
                             if (!error)
                                 st->done = true;
                             else
                                 st->error = true;
                             st->ec = error;
                         });
        wait_async(st->done, st->error, "Network receiving timed out.", "Network receiving failed.", st->ec);
        string line;
        getline(*istrm_, line, '\n');
        if (!raw)
            trim_if(line, is_any_of("\r\n"));
        return line;
    }
    catch (const dialog_error)
    {
        throw;
    }
    catch (const system_error &exc)
    {
        throw dialog_error("Network receiving error.", exc.code().message());
    }
    catch (const std::exception &exc)
    {
        throw dialog_error("Network receiving error.", exc.what());
    }
}

template<typename Socket>
string dialog::receive_exact_sync(Socket& socket, std::size_t total_bytes)
{
    try
    {
        if (total_bytes == 0)
            return std::string();
        std::string out;
        out.resize(total_bytes);
        std::size_t copied = 0;

        // 1) Drain any bytes already buffered by previous read_until into streambuf_.
        while (copied < total_bytes && strmbuf_ && strmbuf_->size() > 0)
        {
            std::size_t avail = strmbuf_->size();
            std::size_t to_copy = std::min(total_bytes - copied, avail);
            istrm_->read(&out[copied], static_cast<std::streamsize>(to_copy));
            copied += to_copy;
        }

        // 2) Read the remainder directly from the socket.
        while (copied < total_bytes)
        {
            auto n = socket.read_some(buffer(&out[copied], total_bytes - copied));
            if (n == 0)
                throw dialog_error("Network receiving error.", "Unexpected EOF");
            copied += n;
        }
        return out;
    }
    catch (const system_error& exc)
    {
        throw dialog_error("Network receiving error.", exc.code().message());
    }
}


template<typename Socket>
string dialog::receive_exact_async(Socket& socket, std::size_t total_bytes, std::size_t chunk_size)
{
    if (chunk_size == 0)
        chunk_size = 32 * 1024;
    if (total_bytes == 0)
        return std::string();
    auto out = std::make_shared<std::string>();
    out->resize(total_bytes);
    std::size_t copied = 0;

    // 1) Drain any bytes already buffered by previous read_until into streambuf_.
    while (copied < total_bytes && strmbuf_ && strmbuf_->size() > 0)
    {
        std::size_t avail = strmbuf_->size();
        std::size_t to_copy = std::min(total_bytes - copied, avail);
        istrm_->read(&(*out)[copied], static_cast<std::streamsize>(to_copy));
        copied += to_copy;
    }

    // 2) Read the remainder from the socket in timed chunks.
    while (copied < total_bytes)
    {
        check_timeout();
        struct op_state { bool done{false}; bool error{false}; error_code ec; };
        auto st = std::make_shared<op_state>();
        std::size_t to_read = std::min(chunk_size, total_bytes - copied);
        auto buf = buffer(&(*out)[copied], to_read);
        auto self = this->shared_from_this();
        async_read(socket, buf, boost::asio::transfer_exactly(to_read),
            [st, out, self](const error_code& error, size_t /*bytes*/)
            {
                if (!error)
                    st->done = true;
                else
                    st->error = true;
                st->ec = error;
            });
        wait_async(st->done, st->error, "Network receiving timed out.", "Network receiving failed.", st->ec);
        // If we reached here, we consumed 'to_read' bytes successfully.
        copied += to_read;
    }
    return *out;
}


void dialog::wait_async(const bool& has_op, const bool& op_error, const char* expired_msg, const char* op_msg, const error_code& error)
{
    in_wait_async_.store(true, std::memory_order_release);
    bool observed_timeout = false;
    for (;;)
    {
        ios_->run_one();
        if (has_op || op_error)
            break;
        // Planned graceful interrupt takes precedence; cancel outstanding op to force handler.
        if (planned_interrupt_.load(std::memory_order_acquire))
        {
            if (socket_)
            {
                boost::system::error_code ec_ignore; socket_->cancel(ec_ignore);
            }
            continue; // loop until handler runs
        }
        if (timer_expired_.load(std::memory_order_acquire))
        {
            observed_timeout = true;
            if (socket_)
            {
                boost::system::error_code ec_ignore; socket_->cancel(ec_ignore);
            }
            continue;
        }
    }
    if (timer_ && timer_armed_.load())
    {
        try { timer_->cancel(); } catch (...) {}
        timer_armed_.store(false, std::memory_order_release);
    }
    // Outcome
    if (op_error)
    {
        if (planned_interrupt_.load(std::memory_order_acquire))
        {
            planned_interrupt_.store(false, std::memory_order_release);
            in_wait_async_.store(false, std::memory_order_release);
            throw dialog_planned_disconnect("Operation aborted.", "Planned disconnect");
        }
        if (observed_timeout || timer_expired_.load(std::memory_order_acquire))
        {
            in_wait_async_.store(false, std::memory_order_release);
            throw dialog_error(expired_msg, error.message());
        }
        in_wait_async_.store(false, std::memory_order_release);
        throw dialog_error(op_msg, error.message());
    }
    in_wait_async_.store(false, std::memory_order_release);
}


void dialog::check_timeout()
{
    // Expiring automatically cancels the timer, per documentation.
    timer_->expires_after(timeout_);
    timer_expired_.store(false, std::memory_order_release);
    // Use weak capture to avoid extending lifetime and to prevent callbacks touching
    // a destroyed object during teardown.
    std::weak_ptr<dialog> self_w = weak_from_this();
    timer_armed_.store(true, std::memory_order_release);
    timer_->async_wait([self_w](const error_code& ec)
    {
        if (auto self = self_w.lock())
        {
            // If close() ran and disarmed the timer, ignore late callbacks.
            if (!self->timer_armed_.load())
                return;
            self->timeout_handler(ec);
        }
    });
}


void dialog::timeout_handler(const error_code& error)
{
    if (!error)
        timer_expired_.store(true, std::memory_order_release); 
}


dialog_ssl::dialog_ssl(const string& hostname, unsigned port, milliseconds timeout, const ssl_options_t& options) :
    dialog(hostname, port, timeout), ssl_(false), context_(make_shared<context>(options.method)),
    ssl_socket_(make_shared<boost::asio::ssl::stream<tcp::socket&>>(*socket_, *context_))
{
#ifdef DANGEROUSELY_LOG_SSL_KEYS
    // if enabled, log ssl keys, this can be used to analyze ssl traffic with wireshark
    setup_keylog_callback();
#endif
}


dialog_ssl::dialog_ssl(const dialog& other, const ssl_options_t& options) : dialog(other), context_(make_shared<context>(options.method)),
    ssl_socket_(make_shared<boost::asio::ssl::stream<tcp::socket&>>(*socket_, *context_))
{
#ifdef DANGEROUSELY_LOG_SSL_KEYS
    // if enabled, log ssl keys, this can be used to analyze ssl traffic with wireshark
    setup_keylog_callback();
#endif
    try
    {
        ssl_socket_->set_verify_mode(options.verify_mode);
        ssl_socket_->handshake(boost::asio::ssl::stream_base::client);
        ssl_ = true;
    }
    catch (const system_error& exc)
    {
        // TODO: perhaps the message is confusing
        throw dialog_error("Switching to SSL failed.", exc.code().message());
    }
}

void dialog_ssl::send(const string &line)
{
    if (aborted_.load(std::memory_order_acquire))
    throw dialog_planned_disconnect("Operation aborted.", "Planned disconnect");
    debug_bugfix(session_name_, "SEND", line);
    if (!ssl_)
    {
        dialog::send(line);
        return;
    }
    try
    {
        if (timeout_.count() == 0)
            send_sync(*ssl_socket_, line);
        else
            send_async(*ssl_socket_, line);
    }
    catch (...)
    {
        if (aborted_.load(std::memory_order_acquire))
            throw dialog_planned_disconnect("Operation aborted.", "Planned disconnect");
        throw;
    }
}

string dialog_ssl::receive(bool raw)
{
    if (aborted_.load(std::memory_order_acquire))
        throw dialog_planned_disconnect("Operation aborted.", "Planned disconnect");
    if (!ssl_)
        return dialog::receive(raw);
    try
    {
        string res{};
        if (timeout_.count() == 0)
            res = receive_sync(*ssl_socket_, raw);
        else
            res = receive_async(*ssl_socket_, raw);
        debug_bugfix(session_name_, "RECEIVE", res);
        return res;
    }
    catch (...)
    {
        if (aborted_.load(std::memory_order_acquire))
            throw dialog_planned_disconnect("Operation aborted.", "Planned disconnect");
        throw;
    }
}

string dialog_ssl::receive_bytes(std::size_t total_bytes, std::size_t chunk_size)
{
    if (aborted_.load(std::memory_order_acquire))
        throw dialog_planned_disconnect("Operation aborted.", "Planned disconnect");
    if (!ssl_)
        return dialog::receive_bytes(total_bytes, chunk_size);
    try
    {
        string res{};
        if (timeout_.count() == 0)
            res = receive_exact_sync(*ssl_socket_, total_bytes);
        else
            res = receive_exact_async(*ssl_socket_, total_bytes, chunk_size);
        debug_bugfix(session_name_, "RECEIVE", "[bin:" + std::to_string(res.size()) + "]");
        return res;
    }
    catch (const system_error& exc)
    {
        if (aborted_.load(std::memory_order_acquire))
            throw dialog_planned_disconnect("Operation aborted.", "Planned disconnect");
        throw dialog_error("Network byte receiving error.", exc.code().message());
    }
}

shared_ptr<dialog_ssl> dialog_ssl::to_ssl(const shared_ptr<dialog> dlg, const dialog_ssl::ssl_options_t& options)
{
    return make_shared<dialog_ssl>(*dlg, options);
}


string dialog_error::details() const
{
    return details_;
}

#ifdef MAILIO_TEST_HOOKS
void dialog::simulate_disconnect()
{
    error_code ec;
    if (socket_)
        socket_->shutdown(tcp::socket::shutdown_both, ec);
    if (socket_)
        socket_->close(ec);
}

void dialog::set_simulated_error(simulated_error_t err, int count)
{
    sim_error_ = err;
    sim_error_count_ = count;
}
#endif

void dialog_ssl::setup_keylog_callback()
{
#if defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x10101000L
    // OpenSSL 1.1.1+ supports SSL_CTX_set_keylog_callback for TLS 1.3 and earlier
    const char* keylog_file = std::getenv("SSLKEYLOGFILE");
    //const char *keylog_file = std::getenv("SSLKEYLOGFILE");
    if (keylog_file && keylog_file[0] != '\0')
    {
        // Get the native OpenSSL SSL_CTX* from Boost.Asio context
        SSL_CTX *native_ctx = context_->native_handle();
        if (native_ctx)
        {
            SSL_CTX_set_keylog_callback(native_ctx, [](const SSL * /*ssl*/, const char *line)
            {
                const char* keylog_file = std::getenv("SSLKEYLOGFILE");
                if (!keylog_file || keylog_file[0] == '\0') {
                    return;
                }
                // Append the key line to the file (format: "CLIENT_RANDOM <hex> <hex>")
                // Thread-safe on most platforms for small writes with append mode
                FILE* f = fopen(keylog_file, "a");
                if (f)
                {
                    fprintf(f, "%s\n", line);
                    fclose(f);
                } 
            });
        }
    }
#endif
}

} // namespace mailio
