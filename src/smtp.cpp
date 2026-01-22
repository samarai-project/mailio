/*

smtp.cpp
---------------

Copyright (C) 2016, Tomislav Karastojkovic (http://www.alepho.com).

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

*/


#include <vector>
#include <string>
#include <stdexcept>
#include <tuple>
#include <algorithm>
#include <cctype>
#include <thread>
#include <boost/asio/ip/host_name.hpp>
#include <mailio/base64.hpp>
#include <mailio/smtp.hpp>


using std::ostream;
using std::istream;
using std::vector;
using std::string;
using std::to_string;
using std::tuple;
using std::stoi;
using std::move;
using std::make_shared;
using std::runtime_error;
using std::out_of_range;
using std::invalid_argument;
using std::chrono::milliseconds;
using boost::asio::ip::host_name;
using boost::system::system_error;


namespace mailio
{


smtp::smtp(const string& hostname, unsigned port, milliseconds timeout) :
    dlg_(make_shared<dialog>(hostname, port, timeout)), is_start_tls_(true)
{
    ssl_options_ =
        {
            boost::asio::ssl::context::sslv23,
            boost::asio::ssl::verify_none
        };
    src_host_ = read_hostname();
    dlg_->connect();
}


smtp::~smtp()
{
    try
    {
        if (dlg_)
            dlg_->close();
    }
    catch (...)
    {
    }
}


void smtp::disconnect(milliseconds timeout)
{
    if (!dlg_)
        return;

    // Request a graceful planned interrupt of in-flight I/O.
    try { dlg_->request_planned_interrupt(); } catch (...) { }

    // Optionally wait a short grace period for the current operation to unwind.
    auto deadline = std::chrono::steady_clock::now() + timeout;
    while (dlg_->is_in_wait() && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(25));

    // If still in wait after grace, perform hard abort.
    if (dlg_->is_in_wait())
        try { dlg_->abort_now(); } catch (...) { }

    // Ensure socket/timers are closed regardless.
    try { dlg_->close(); } catch (...) { }
}


void smtp::set_session_name(const std::string& name)
{
    // Store on the underlying dialog so low-level SEND/RECEIVE logs carry the label.
    if (dlg_)
        dlg_->set_session_name(name);
}


std::string smtp::session_name() const
{
    if (dlg_)
        return dlg_->session_name();
    return std::string();
}


string smtp::authenticate(const string& username, const string& password, auth_method_t method)
{
    if (ssl_options_.has_value() && !is_start_tls_)
        dlg_ = dialog_ssl::to_ssl(dlg_, *ssl_options_);

    string greeting = connect();
    ehlo();
    if (is_start_tls_)
        switch_tls();

    if (method == auth_method_t::NONE)
        ;
    else if (method == auth_method_t::LOGIN)
        auth_login(username, password);
    else if (method == auth_method_t::XOAUTH2)
        auth_login_xoauth2(username, password);
    return greeting;
}


string smtp::submit(const message& msg)
{
    if (!msg.sender().address.empty())
        dlg_->send("MAIL FROM: " + message::ADDRESS_BEGIN_STR + msg.sender().address + message::ADDRESS_END_STR);
    else
        dlg_->send("MAIL FROM: " + message::ADDRESS_BEGIN_STR + msg.from().addresses.at(0).address + message::ADDRESS_END_STR);
    string line = dlg_->receive();
    tuple<int, bool, string> tokens = parse_line(line);
    if (std::get<1>(tokens) && !positive_completion(std::get<0>(tokens)))
        throw smtp_error("Mail sender rejection.", std::get<2>(tokens));

    for (const auto& rcpt : msg.recipients().addresses)
    {
        dlg_->send("RCPT TO: " + message::ADDRESS_BEGIN_STR + rcpt.address + message::ADDRESS_END_STR);
        line = dlg_->receive();
        tokens = parse_line(line);
        if (!positive_completion(std::get<0>(tokens)))
            throw smtp_error("Mail recipient rejection.", std::get<2>(tokens));
    }

    for (const auto& rcpt : msg.recipients().groups)
    {
        dlg_->send("RCPT TO: " + message::ADDRESS_BEGIN_STR + rcpt.name + message::ADDRESS_END_STR);
        line = dlg_->receive();
        tokens = parse_line(line);
        if (!positive_completion(std::get<0>(tokens)))
            throw smtp_error("Mail group recipient rejection.", std::get<2>(tokens));
    }

    for (const auto& rcpt : msg.cc_recipients().addresses)
    {
        dlg_->send("RCPT TO: " + message::ADDRESS_BEGIN_STR + rcpt.address + message::ADDRESS_END_STR);
        line = dlg_->receive();
        tokens = parse_line(line);
        if (!positive_completion(std::get<0>(tokens)))
            throw smtp_error("Mail cc recipient rejection.", std::get<2>(tokens));
    }

    for (const auto& rcpt : msg.cc_recipients().groups)
    {
        dlg_->send("RCPT TO: " + message::ADDRESS_BEGIN_STR + rcpt.name + message::ADDRESS_END_STR);
        line = dlg_->receive();
        tokens = parse_line(line);
        if (!positive_completion(std::get<0>(tokens)))
            throw smtp_error("Mail group cc recipient rejection.", std::get<2>(tokens));
    }

    for (const auto& rcpt : msg.bcc_recipients().addresses)
    {
        dlg_->send("RCPT TO: " + message::ADDRESS_BEGIN_STR + rcpt.address + message::ADDRESS_END_STR);
        line = dlg_->receive();
        tokens = parse_line(line);
        if (!positive_completion(std::get<0>(tokens)))
            throw smtp_error("Mail bcc recipient rejection.", std::get<2>(tokens));
    }

    for (const auto& rcpt : msg.bcc_recipients().groups)
    {
        dlg_->send("RCPT TO: " + message::ADDRESS_BEGIN_STR + rcpt.name + message::ADDRESS_END_STR);
        line = dlg_->receive();
        tokens = parse_line(line);
        if (!positive_completion(std::get<0>(tokens)))
            throw smtp_error("Mail group bcc recipient rejection.", std::get<2>(tokens));
    }

    dlg_->send("DATA");
    line = dlg_->receive();
    tokens = parse_line(line);
    if (!positive_intermediate(std::get<0>(tokens)))
        throw smtp_error("Mail message rejection.", std::get<2>(tokens));

    string msg_str;
    msg.format(msg_str, {/*dot_escape*/true});
    dlg_->send(msg_str + codec::END_OF_LINE + codec::END_OF_MESSAGE);
    line = dlg_->receive();
    tokens = parse_line(line);
    if (!positive_completion(std::get<0>(tokens)))
        throw smtp_error("Mail message rejection.", std::get<2>(tokens));
    return std::get<2>(tokens);
    
}


void smtp::source_hostname(const string& src_host)
{
    src_host_ = src_host;
}


string smtp::source_hostname() const
{
    return src_host_;
}


void smtp::start_tls(bool is_tls)
{
    is_start_tls_ = is_tls;
}


void smtp::ssl_options(const std::optional<dialog_ssl::ssl_options_t> options)
{
    ssl_options_ = options;
}


string smtp::connect()
{
    string greeting;
    string line = dlg_->receive();
    tuple<int, bool, string> tokens = parse_line(line);
    while (!std::get<1>(tokens))
    {
        greeting += std::get<2>(tokens) + to_string(codec::CR_CHAR) + to_string(codec::LF_CHAR);
        line = dlg_->receive();
        tokens = parse_line(line);
    }
    if (std::get<0>(tokens) != SERVICE_READY_STATUS)
        throw smtp_error("Connection rejection.", std::get<2>(tokens));
    greeting += std::get<2>(tokens);
    return greeting;
}


void smtp::auth_login(const string& username, const string& password)
{
    dlg_->send("AUTH LOGIN");
    string line = dlg_->receive();
    tuple<int, bool, string> tokens = parse_line(line);
    if (std::get<1>(tokens) && !positive_intermediate(std::get<0>(tokens)))
        throw smtp_error("Authentication rejection.", std::get<2>(tokens));

    // TODO: Use static encode from the Base64 codec.
    base64 b64(static_cast<string::size_type>(codec::line_len_policy_t::RECOMMENDED), static_cast<string::size_type>(codec::line_len_policy_t::RECOMMENDED));
    auto user_v = b64.encode(username);
    string cmd = user_v.empty() ? "" : user_v[0];
    dlg_->send(cmd);
    line = dlg_->receive();
    tokens = parse_line(line);
    if (std::get<1>(tokens) && !positive_intermediate(std::get<0>(tokens)))
        throw smtp_error("Username rejection.", std::get<2>(tokens));

    auto pass_v = b64.encode(password);
    cmd = pass_v.empty() ? "" : pass_v[0];
    dlg_->send(cmd);
    line = dlg_->receive();
    tokens = parse_line(line);
    if (std::get<1>(tokens) && !positive_completion(std::get<0>(tokens)))
        throw smtp_error("Password rejection.", std::get<2>(tokens));
}

void smtp::auth_login_xoauth2(const std::string &username, const std::string &access_token)
{
    
    // XOAUTH2 SASL initial client response as per RFC 7628:
    // base64("user=" user "\x01auth=Bearer " access_token "\x01\x01")
    std::string sasl = "user=" + username + "\x01" + "auth=Bearer " + access_token + "\x01\x01";
    std::string sasl_b64 = b64_encode(sasl, static_cast<string::size_type>(codec::line_len_policy_t::NONE));

    // Local sanity checks and helpful debug breadcrumbs.
    auto has_crlf = (sasl.find('\r') != std::string::npos) || (sasl.find('\n') != std::string::npos);
    auto has_other_ctrl = std::any_of(sasl.begin(), sasl.end(), [](unsigned char ch)
    {
        return (ch < 0x20) && (ch != 0x01) && (ch != 0x09); // allow HT and the SASL \x01 separators
    });

    auto evaluate = [this](const tuple<int, bool, string>& tokens)
    {
        if (positive_completion(std::get<0>(tokens)))
            return;

        auto code = std::get<0>(tokens);
        auto error_b64 = std::get<2>(tokens);
        int final_code{0};
        std::string final_error_b64{};

        // Some servers (e.g., Gmail on failure) respond with 334 and a base64 encoded JSON error.
        if (positive_intermediate(std::get<0>(tokens)))
        {
            // Abort per RFC by sending an empty line – server should respond with final 5XX (e.g., 535).
            try
            {
                dlg_->send("");
                auto line = dlg_->receive();
                auto final_tokens = parse_line(line);
                final_code = std::get<0>(final_tokens);
                final_error_b64 = std::get<2>(final_tokens);
            }
            catch (...)
            {
                // ignore
            }
        }

        std::string details = std::string{"JSON={"}
            + "\"code\": " + std::to_string(code) + ","
            + "\"error\": \"" + error_b64 + "\","
            + "\"finalCode\": " + std::to_string(final_code) + ","
            + "\"final\": \"" + final_error_b64 + "\""
            + "}";
        throw smtp_error("Authentication rejection.", details);
    };

    // If the full command would exceed the RFC 5321 line length (512 incl. CRLF), fall back to a two-step SASL flow:
    //   AUTH XOAUTH2\r\n
    //   <334 prompt>\r\n
    //   <base64 payload>\r\n
    // This avoids server-side truncation of long access tokens.
    const std::size_t smtp_line_limit = 500; // keep margin for CRLF and status text
    const bool use_challenge_response = ("AUTH XOAUTH2 " + sasl_b64).size() > smtp_line_limit;

    if (use_challenge_response)
    {
        dlg_->send("AUTH XOAUTH2");
        auto line = dlg_->receive();
        auto tokens = parse_line(line);
        if (!positive_intermediate(std::get<0>(tokens)))
            evaluate(tokens); // will throw

        dlg_->send(sasl_b64);
        line = dlg_->receive();
        tokens = parse_line(line);
        evaluate(tokens); // success returns, otherwise throws
    }
    else
    {
        // Send AUTH XOAUTH2 with the initial client response.
        dlg_->send("AUTH XOAUTH2 " + sasl_b64);
        auto line = dlg_->receive();
        auto tokens = parse_line(line);
        evaluate(tokens);
    }
    
}

void smtp::ehlo()
{
    dlg_->send("EHLO " + src_host_);
    string line = dlg_->receive();
    tuple<int, bool, string> tokens = parse_line(line);
    while (!std::get<1>(tokens))
    {
        line = dlg_->receive();
        tokens = parse_line(line);
    }

    if (!positive_completion(std::get<0>(tokens)))
    {
        dlg_->send("HELO " + src_host_);

        line = dlg_->receive();
        tokens = parse_line(line);
        while (!std::get<1>(tokens))
        {
            line = dlg_->receive();
            tokens = parse_line(line);
        }
        if (!positive_completion(std::get<0>(tokens)))
            throw smtp_error("Initial message rejection.", std::get<2>(tokens));
    }
}


string smtp::read_hostname()
{
    try
    {
        return host_name();
    }
    catch (system_error&)
    {
        throw smtp_error("Reading hostname failure.", "");
    }
}


void smtp::switch_tls()
{
    dlg_->send("STARTTLS");
    string line = dlg_->receive();
    tuple<int, bool, string> tokens = parse_line(line);
    if (std::get<1>(tokens) && std::get<0>(tokens) != SERVICE_READY_STATUS)
        throw smtp_error("Start tls refused by server.", std::get<2>(tokens));

    dlg_ = dialog_ssl::to_ssl(dlg_, *ssl_options_);
}


tuple<int, bool, string> smtp::parse_line(const string& line)
{
    try
    {
        return make_tuple(stoi(line.substr(0, 3)), (line.at(3) == '-' ? false : true), line.substr(4));
    }
    catch (out_of_range&)
    {
        throw smtp_error("Parsing server failure.", "");
    }
    catch (invalid_argument&)
    {
        throw smtp_error("Parsing server failure.", "");
    }
}


inline bool smtp::positive_completion(int status)
{
    return status / 100 == smtp_status_t::POSITIVE_COMPLETION;
}


inline bool smtp::positive_intermediate(int status)
{
    return status / 100 == smtp_status_t::POSITIVE_INTERMEDIATE;
}


inline bool smtp::transient_negative(int status)
{
    return status / 100 == smtp_status_t::TRANSIENT_NEGATIVE;
}


inline bool smtp::permanent_negative(int status)
{
    return status / 100 == smtp_status_t::PERMANENT_NEGATIVE;
}


smtps::smtps(const string& hostname, unsigned port, milliseconds timeout) :
    smtp(hostname, port, timeout)
{
    ssl_options_ =
        {
            boost::asio::ssl::context::sslv23,
            boost::asio::ssl::verify_none
        };
    is_start_tls_ = false;
}


string smtps::authenticate(const string& username, const string& password, auth_method_t method)
{
    string greeting;
    if (method == auth_method_t::NONE)
    {
        is_start_tls_ = false;
        greeting = smtp::authenticate(username, password, smtp::auth_method_t::NONE);
    }
    else if (method == auth_method_t::LOGIN)
    {
        is_start_tls_ = false;
        greeting = smtp::authenticate(username, password, smtp::auth_method_t::LOGIN);
    }
    else if (method == auth_method_t::START_TLS)
    {
        is_start_tls_ = true;
        greeting = smtp::authenticate(username, password, smtp::auth_method_t::LOGIN);
    }
    else if (method == auth_method_t::XOAUTH2)
    {
        is_start_tls_ = false;
        greeting = smtp::authenticate(username, password, smtp::auth_method_t::XOAUTH2);
    }
    else if (method == auth_method_t::XOAUTH2_START_TLS)
    {
        is_start_tls_ = true;
        greeting = smtp::authenticate(username, password, smtp::auth_method_t::XOAUTH2);
    }
    return greeting;
}


void smtps::ssl_options(const dialog_ssl::ssl_options_t& options)
{
    ssl_options_ = options;
}


smtp_error::smtp_error(const string& msg, const string& details) : dialog_error(msg, details)
{
}


smtp_error::smtp_error(const char* msg, const string& details) : dialog_error(msg, details)
{
}


} // namespace mailio
