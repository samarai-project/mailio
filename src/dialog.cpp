/*

dialog.cpp
----------

Copyright (C) 2016, Tomislav Karastojkovic (http://www.alepho.com).

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

*/


#include <string>
#include <algorithm>
#include <boost/algorithm/string/trim.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <mailio/dialog.hpp>
#include <mailio/base64.hpp>


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


namespace mailio
{


boost::asio::io_context dialog::ios_;

std::string b64_encode(const std::string& value)
{
    base64 b64(
        static_cast<string::size_type>(codec::line_len_policy_t::RECOMMENDED),
        static_cast<string::size_type>(codec::line_len_policy_t::RECOMMENDED)
    );
    auto enc_v = b64.encode(value);
    std::stringstream res{};
    for (size_t i = 0; i < enc_v.size(); ++i)
        res << enc_v[i];
    return res.str();
}

dialog::dialog(const string& hostname, unsigned port, milliseconds timeout) : std::enable_shared_from_this<dialog>(),
    hostname_(hostname), port_(port), socket_(make_shared<tcp::socket>(ios_)), timer_(make_shared<steady_timer>(ios_)),
    timeout_(timeout), timer_expired_(false), strmbuf_(make_shared<streambuf>()), istrm_(make_shared<istream>(strmbuf_.get()))
{
}


dialog::dialog(const dialog& other) : std::enable_shared_from_this<dialog>(),
    hostname_(move(other.hostname_)), port_(other.port_), socket_(other.socket_), timer_(other.timer_),
    timeout_(other.timeout_), timer_expired_(other.timer_expired_), strmbuf_(other.strmbuf_), istrm_(other.istrm_)
{
}


void dialog::connect()
{
    try
    {
        if (timeout_.count() == 0)
        {
            tcp::resolver res(ios_);
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


void dialog::send(const string& line)
{
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
    if (timeout_.count() == 0)
        send_sync(*socket_, line);
    else
        send_async(*socket_, line);
}


// TODO: perhaps the implementation should be common with `receive_raw()`
string dialog::receive(bool raw)
{
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
    if (timeout_.count() == 0)
        return receive_sync(*socket_, raw);
    else
        return receive_async(*socket_, raw);
}


string dialog::receive_bytes(std::size_t total_bytes, std::size_t chunk_size)
{
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
    if (timeout_.count() == 0)
        return receive_exact_sync(*socket_, total_bytes);
    else
        return receive_exact_async(*socket_, total_bytes, chunk_size);
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
    tcp::resolver res(ios_);
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


template<typename Socket>
void dialog::send_async(Socket& socket, string line)
{
    check_timeout();
    // Keep the write buffer alive for the lifetime of the async operation.
    auto buf = std::make_shared<string>(move(line));
    buf->append("\r\n");
    struct op_state { bool done{false}; bool error{false}; error_code ec; };
    auto st = std::make_shared<op_state>();
    auto self = this->shared_from_this();
    async_write(socket, buffer(*buf),
        [st, buf, self](const error_code& error, size_t)
        {
            st->done  = !error;
            st->error = !!error;
            st->ec    = error;
        });
    wait_async(st->done, st->error, "Network sending timed out.", "Network sending failed.", st->ec);
}


template<typename Socket>
string dialog::receive_async(Socket& socket, bool raw)
{
    check_timeout();
    struct op_state { bool done{false}; bool error{false}; error_code ec; };
    auto st = std::make_shared<op_state>();
    auto self = this->shared_from_this();
    async_read_until(socket, *strmbuf_, "\n",
        [st, self](const error_code& error, size_t)
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
    do
    {
        if (timer_expired_)
            throw dialog_error(expired_msg, error.message());
        if (op_error)
            throw dialog_error(op_msg, error.message());
        ios_.run_one();
    }
    while (!has_op);
    // Cancel any pending timer to avoid stray callbacks after the operation completed.
    if (timer_)
        timer_->cancel();
}


void dialog::check_timeout()
{
    // Expiring automatically cancels the timer, per documentation.
    timer_->expires_after(timeout_);
    timer_expired_ = false;
    timer_->async_wait(bind(&dialog::timeout_handler, shared_from_this(), std::placeholders::_1));
}


void dialog::timeout_handler(const error_code& error)
{
    if (!error)
        timer_expired_ = true;
}


dialog_ssl::dialog_ssl(const string& hostname, unsigned port, milliseconds timeout, const ssl_options_t& options) :
    dialog(hostname, port, timeout), ssl_(false), context_(make_shared<context>(options.method)),
    ssl_socket_(make_shared<boost::asio::ssl::stream<tcp::socket&>>(*socket_, *context_))
{
}


dialog_ssl::dialog_ssl(const dialog& other, const ssl_options_t& options) : dialog(other), context_(make_shared<context>(options.method)),
    ssl_socket_(make_shared<boost::asio::ssl::stream<tcp::socket&>>(*socket_, *context_))
{
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


void dialog_ssl::send(const string& line)
{
    if (!ssl_)
    {
        dialog::send(line);
        return;
    }

    if (timeout_.count() == 0)
        send_sync(*ssl_socket_, line);
    else
        send_async(*ssl_socket_, line);
}


string dialog_ssl::receive(bool raw)
{
    if (!ssl_)
        return dialog::receive(raw);

    try
    {
        if (timeout_.count() == 0)
            return receive_sync(*ssl_socket_, raw);
        else
            return receive_async(*ssl_socket_, raw);
    }
    catch (const system_error& exc)
    {
        throw dialog_error("Network receiving error.", exc.code().message());
    }
}


string dialog_ssl::receive_bytes(std::size_t total_bytes, std::size_t chunk_size)
{
    if (!ssl_)
        return dialog::receive_bytes(total_bytes, chunk_size);

    try
    {
        if (timeout_.count() == 0)
            return receive_exact_sync(*ssl_socket_, total_bytes);
        else
            return receive_exact_async(*ssl_socket_, total_bytes, chunk_size);
    }
    catch (const system_error& exc)
    {
        throw dialog_error("Network receiving error.", exc.code().message());
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

} // namespace mailio
