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
        dlg_->send("QUIT");
    }
    catch (...)
    {
    }
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
    std::string sasl_b64 = b64_encode(sasl);

    // Send AUTH XOAUTH2 with the initial client response.
    dlg_->send("AUTH XOAUTH2 " + sasl_b64);
    string line = dlg_->receive();
    tuple<int, bool, string> tokens = parse_line(line);

    // Success path: server replies with 235 (2XX - positive completion)
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
            line = dlg_->receive();
            tokens = parse_line(line);
            final_code = std::get<0>(tokens);
            final_error_b64 = std::get<2>(tokens);
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
    else if (method == auth_method_t::START_TLS_XOAUTH2)
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
