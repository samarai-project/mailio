/*

imap.cpp
--------

Copyright (C) 2016, Tomislav Karastojkovic (http://www.alepho.com).

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

*/


#include <algorithm>
#include <locale>
#include <memory>
#include <sstream>
#include <string>
#include <tuple>
#include <functional>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/compare.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include <boost/regex.hpp>
#include "mailio/imap.hpp"
#include "mailio/base64.hpp"
#include "mailio/sha256.hpp"


using std::find_if;
using std::invalid_argument;
using std::list;
using std::make_optional;
using std::make_shared;
using std::make_tuple;
using std::map;
using std::move;
using std::out_of_range;
using std::pair;
using std::shared_ptr;
using std::stoul;
using std::string;
using std::stringstream;
using std::to_string;
using std::tuple;
using std::vector;
using std::chrono::milliseconds;
using std::chrono::steady_clock;
using std::chrono::duration_cast;
using boost::system::system_error;
using boost::iequals;
using boost::istarts_with;
using boost::regex;
using boost::regex_match;
using boost::smatch;
using boost::split;
using boost::trim;
using boost::algorithm::trim_copy_if;
using boost::algorithm::trim_if;
using boost::algorithm::is_any_of;
 


namespace mailio
{

const string imap::UNTAGGED_RESPONSE{"*"};
const string imap::CONTINUE_RESPONSE{"+"};
const string imap::RANGE_SEPARATOR{":"};
const string imap::RANGE_ALL{"*"};
const string imap::LIST_SEPARATOR{","};
const string imap::TOKEN_SEPARATOR_STR{" "};
const string imap::QUOTED_STRING_SEPARATOR{"\""};

string imap::messages_range_to_string(imap::messages_range_t id_pair)
{
    return to_string(id_pair.first) + (id_pair.second.has_value() ? RANGE_SEPARATOR + to_string(id_pair.second.value()) : RANGE_SEPARATOR + RANGE_ALL);
}


string imap::messages_range_list_to_string(list<messages_range_t> ranges)
{
    return boost::join(ranges | boost::adaptors::transformed(static_cast<string(*)(messages_range_t)>(messages_range_to_string)), LIST_SEPARATOR);
}


string imap::to_astring(const string& text)
{
    return codec::surround_string(codec::escape_string(text, "\"\\"));
}


imap::search_condition_t::search_condition_t(imap::search_condition_t::key_type condition_key, imap::search_condition_t::value_type condition_value) :
    key(condition_key), value(condition_value)
{
    try
    {
        switch (key)
        {
            case ALL:
                imap_string = "ALL";
                break;

            case SID_LIST:
            {
                imap_string = messages_range_list_to_string(std::get<list<messages_range_t>>(value));
                break;
            }

            case UID_LIST:
            {
                imap_string = "UID " + messages_range_list_to_string(std::get<list<messages_range_t>>(value));
                break;
            }

            case SUBJECT:
                imap_string = "SUBJECT " + QUOTED_STRING_SEPARATOR + std::get<string>(value) + QUOTED_STRING_SEPARATOR;
                break;

            case BODY:
                imap_string = "BODY " + QUOTED_STRING_SEPARATOR + std::get<string>(value) + QUOTED_STRING_SEPARATOR;
                break;

            case FROM:
                imap_string = "FROM " + QUOTED_STRING_SEPARATOR + std::get<string>(value) + QUOTED_STRING_SEPARATOR;
                break;

            case TO:
                imap_string = "TO " + QUOTED_STRING_SEPARATOR + std::get<string>(value) + QUOTED_STRING_SEPARATOR;
                break;

            case BEFORE_DATE:
                imap_string = "BEFORE " + imap_date_to_string(std::get<boost::gregorian::date>(value));
                break;

            case ON_DATE:
                imap_string = "ON " + imap_date_to_string(std::get<boost::gregorian::date>(value));
                break;

            case SINCE_DATE:
                imap_string = "SINCE " + imap_date_to_string(std::get<boost::gregorian::date>(value));
                break;

            case NEW:
                imap_string = "NEW";
                break;

            case RECENT:
                imap_string = "RECENT";
                break;

            case SEEN:
                imap_string = "SEEN";
                break;

            case UNSEEN:
                imap_string = "UNSEEN";
                break;

            default:
                break;
        }
    }
    catch (std::bad_variant_access& exc)
    {
        throw imap_error("Invaid search condition.", exc.what());
    }
}


string imap::tag_result_response_t::to_string() const
{
    string result_s;
    if (result.has_value())
    {
        switch (result.value())
        {
        case OK:
            result_s = "OK";
            break;

        case NO:
            result_s = "NO";
            break;

        case BAD:
            result_s = "BAD";
            break;

        default:
            break;
        }
    }
    else
        result_s = "<null>";
    return tag + " " + result_s + " " + response;
}


imap::imap(const string& hostname, unsigned port, milliseconds timeout) :
    dlg_(make_shared<dialog>(hostname, port, timeout)), is_start_tls_(true), tag_(0), optional_part_state_(false), atom_state_(atom_state_t::NONE),
    parenthesis_list_counter_(0), literal_state_(string_literal_state_t::NONE), literal_bytes_read_(0), eols_no_(2)
{
    ssl_options_ =
        {
            boost::asio::ssl::context::sslv23,
            boost::asio::ssl::verify_none
        };
    dlg_->connect();
}


imap::~imap()
{
    try
    {
        // Best-effort cleanup only: do not perform protocol I/O here.
        if (dlg_)
            dlg_->close();
    }
    catch (...)
    {
    }
}


string imap::authenticate(const string& username, const string& password, auth_method_t method)
{
    if (ssl_options_.has_value() && !is_start_tls_)
        dlg_ = dialog_ssl::to_ssl(dlg_, *ssl_options_);

    string greeting = connect();
    if (is_start_tls_)
        switch_tls();

    if (method == auth_method_t::LOGIN)
        auth_login(username, password);
    else if (method == auth_method_t::XOAUTH2)
        auth_login_xoauth2(username, password);
    return greeting;
}

void imap::set_session_name(const std::string& name)
{
    // Store on the underlying dialog so low-level SEND/RECEIVE logs carry the label.
    if (dlg_)
        dlg_->set_session_name(name);
}

std::string imap::session_name() const
{
    if (dlg_)
        return dlg_->session_name();
    return std::string();
}


auto imap::select(const list<string>& folder_name, bool /*read_only*/) -> mailbox_stat_t
{
    string delim = folder_delimiter();
    string folder_name_s = folder_tree_to_string(folder_name, delim);
    return select(folder_name_s);
}


auto imap::select(const string& mailbox, bool read_only) -> mailbox_stat_t
{
    string cmd;
    if (read_only)
        cmd = format("EXAMINE " + to_astring(mailbox));
    else
        cmd = format("SELECT " + to_astring(mailbox));
    dlg_->send(cmd);

    mailbox_stat_t stat;
    bool exists_found = false;
    bool recent_found = false;
    bool has_more = true;

    try
    {
        while (has_more)
        {
            reset_response_parser();
            string line = dlg_->receive();
            tag_result_response_t parsed_line = parse_tag_result(line);
            parse_response(parsed_line.response);

            if (parsed_line.tag == UNTAGGED_RESPONSE)
            {
                const auto result = parsed_line.result;
                if (result.has_value() && result.value() == tag_result_response_t::OK)
                {
                    if (optional_part_.size() != 2)
                        continue;

                    auto key = optional_part_.front();
                    optional_part_.pop_front();
                    if (key->token_type == response_token_t::token_type_t::ATOM)
                    {
                        auto value = optional_part_.front();
                        if (iequals(key->atom, "UNSEEN"))
                        {
                            if (value->token_type != response_token_t::token_type_t::ATOM)
                                throw imap_error("Number expected for unseen.", "Line=`" + line + "`.");
                            stat.messages_first_unseen = stoul(value->atom);
                        }
                        else if (iequals(key->atom, "UIDNEXT"))
                        {
                            if (value->token_type != response_token_t::token_type_t::ATOM)
                                throw imap_error("Number expected for uidnext.", "Line=`" + line + "`.");
                            stat.uid_next = stoul(value->atom);
                        }
                        else if (iequals(key->atom, "UIDVALIDITY"))
                        {
                            if (value->token_type != response_token_t::token_type_t::ATOM)
                                throw imap_error("Number expected for uidvalidity.", "Line=`" + line + "`.");
                            stat.uid_validity = stoul(value->atom);
                        }
                        else if (iequals(key->atom, "HIGHESTMODSEQ"))
                        {
                            if (value->token_type != response_token_t::token_type_t::ATOM)
                                throw imap_error("Number expected for highestmodseq.", "Line=`" + line + "`.");
                            // RFC 7162 specifies a 64-bit mod-sequence.
                            stat.highest_modseq = std::stoull(value->atom);
                        }
                    }
                }
                else
                {
                    if (mandatory_part_.size() == 2 && mandatory_part_.front()->token_type == response_token_t::token_type_t::ATOM)
                    {
                        auto value = mandatory_part_.front();
                        mandatory_part_.pop_front();
                        auto key = mandatory_part_.front();
                        mandatory_part_.pop_front();
                        if (iequals(key->atom, "EXISTS"))
                        {
                            stat.messages_no = stoul(value->atom);
                            exists_found = true;
                        }
                        else if (iequals(key->atom, "RECENT"))
                        {
                            stat.messages_recent = stoul(value->atom);
                            recent_found = true;
                        }
                    }
                }
            }
            else if (parsed_line.tag == to_string(tag_))
            {
                if (!parsed_line.result.has_value() || parsed_line.result.value() != tag_result_response_t::OK)
                    throw imap_error("Select or examine mailbox failure.", "Response=`" + parsed_line.response + "`.");

                has_more = false;
            }
            else
                throw imap_error("Parsing failure.", "Line=`" + line + "`.");
        }
    }
    catch (const invalid_argument& exc)
    {
        throw imap_error("Integer expected.", exc.what());
    }
    catch (const out_of_range& exc)
    {
        throw imap_error("Integer expected.", exc.what());
    }

    // The EXISTS and RECENT are required, the others may be missing in earlier protocol versions.
    if (!exists_found || !recent_found)
        throw imap_error("No number of existing or recent messages.", "");

    reset_response_parser();
    return stat;
}


void imap::fetch(const string& mailbox, unsigned long message_no, bool is_uid, message& msg, bool header_only,
                 bool dont_set_seen)
{
    select(mailbox);
    fetch(message_no, msg, is_uid, header_only, dont_set_seen);
}

void imap::fetch(unsigned long message_no, message& msg, bool is_uid, bool header_only,
                 bool dont_set_seen)
{
    list<messages_range_t> messages_range;
    messages_range.push_back(imap::messages_range_t(message_no, message_no));
    map<unsigned long, message> found_messages;
    fetch(messages_range, found_messages, is_uid, header_only, msg.line_policy(), dont_set_seen);
    if (!found_messages.empty())
        msg = std::move(found_messages.begin()->second);
}


/*
Although the RFC mandates MIME messages to have lines ending with CRLF, some email clients put LF only. For that reason, the method `dialog::receive(true)`
is being used for fetching a literal. That way, the EOL counting is properly performed. This is probably the case for the strict mode policy.

According to the RFC 3501 section 6.4.5, the untagged response of the fetch command is not mandatory. Thus, some servers return just the tagged response if
no message is found.

The fetch untagged responses provide messages. In the last tagged response the status is obtained. Then, string literals can be parsed to validate the MIME
format.
*/
void imap::fetch(const list<messages_range_t>& messages_range, map<unsigned long, message>& found_messages, bool is_uids, bool header_only,
    codec::line_len_policy_t line_policy, bool dont_set_seen)
{
    if (messages_range.empty())
        throw imap_error("Empty messages range.", "");

    // Choose token that preserves raw bytes but avoids setting \\Seen when requested.
    // RFC822 and BODY[] return identical octets for the full message; HEADER variants align similarly.
    const string RFC822_TOKEN = string("RFC822") + (header_only ? ".HEADER" : "");
    const string BODY_TOKEN = string("BODY") + (header_only ? ".PEEK[HEADER]" : ".PEEK[]");
    const string FETCH_TOKEN = dont_set_seen ? BODY_TOKEN : RFC822_TOKEN;
    
    // Prefer explicit ID list when callers provided only singleton ranges (e.g., a single message).
    // This avoids needlessly sending start:end syntax like "120:120" and improves interoperability
    // with servers that behave poorly with range forms for singletons.
    bool all_singletons = true;
    for (const auto &rng : messages_range)
    {
        if (!rng.second.has_value() || rng.second.value() != rng.first)
        {
            all_singletons = false;
            break;
        }
    }

    string message_ids;
    if (all_singletons)
    {
        // Build a comma-separated list of explicit IDs (no range syntax).
        bool first = true;
        for (const auto &rng : messages_range)
        {
            if (!first) message_ids += LIST_SEPARATOR; else first = false;
            message_ids += to_string(rng.first);
        }
    }
    else
    {
        // Fall back to the standard range formatter, including open-ended ranges if any.
        message_ids = messages_range_list_to_string(messages_range);
    }

    string cmd;
    if (is_uids)
        cmd.append("UID ");
    // Request UID/FLAGS along with the chosen body token to preserve behavior and avoid marking seen when requested.
    cmd.append("FETCH " + message_ids + TOKEN_SEPARATOR_STR + "(UID FLAGS " + FETCH_TOKEN + ")");
    dlg_->send(format(cmd));

    // stores [msg_str, uid_no, sequence_no, hash, flags] indexed by sequence_no or uid_no
    map<unsigned long, tuple<string, unsigned long, unsigned long, string, vector<string>>> msg_str;

    // Helper to parse and move all collected raw messages into found_messages.
    auto finalize_collected = [&]() {
        for (const auto &ms : msg_str)
        {
            message msg;
            try
            {
                msg.strict_mode(strict_mode_);
                msg.strict_codec_mode(strict_codec_mode_);
                msg.uid(std::get<1>(ms.second));
                msg.sequence_no(std::get<2>(ms.second));
                msg.dedupe_hash(std::get<3>(ms.second));
                msg.flags(std::get<4>(ms.second));
                msg.line_policy(line_policy);
                msg.parse(std::get<0>(ms.second));

                // Conservative no-reply/auto-generated detection
                auto is_obvious_noreply_local = [](const std::string& addr) -> bool {
                    if (addr.empty()) return false;
                    std::string a = boost::to_lower_copy(addr);
                    // Check local part (before '@') for clear patterns
                    auto at = a.find('@');
                    std::string local = (at != std::string::npos) ? a.substr(0, at) : a;
                    if (local.find("noreply") != std::string::npos) return true;
                    if (local.find("no-reply") != std::string::npos) return true;
                    if (local.find("do-not-reply") != std::string::npos) return true;
                    if (local.find("donotreply") != std::string::npos) return true;
                    if (local.find("auto-reply") != std::string::npos) return true;
                    return false;
                };

                auto& headers = msg.headers();
                auto header_has = [&](const std::string& name, const std::string& contains) -> bool {
                    auto range = headers.equal_range(name);
                    for (auto it = range.first; it != range.second; ++it)
                    {
                        std::string v = boost::to_lower_copy(it->second);
                        if (v.find(boost::to_lower_copy(contains)) != std::string::npos)
                            return true;
                    }
                    return false;
                };

                bool mark_no_reply = false;
                // Check Reply-To (primary signal for no-reply mailboxes)
                {
                    auto ra = msg.reply_address();
                    if (!ra.address.empty() && is_obvious_noreply_local(ra.address))
                        mark_no_reply = true;
                }
                // Check Sender
                if (!mark_no_reply)
                {
                    auto se = msg.sender();
                    if (!se.address.empty() && is_obvious_noreply_local(se.address))
                        mark_no_reply = true;
                }
                // Check From addresses
                if (!mark_no_reply)
                {
                    auto froms = msg.from();
                    for (const auto& ma : froms.addresses)
                    {
                        if (!ma.address.empty() && is_obvious_noreply_local(ma.address))
                        {
                            mark_no_reply = true;
                            break;
                        }
                    }
                }
                // Check clear headers indicating auto-generation
                if (!mark_no_reply)
                {
                    if (header_has("Auto-Submitted", "auto-generated") ||
                        header_has("Auto-Submitted", "auto-replied"))
                    {
                        mark_no_reply = true;
                    }
                    else if (header_has("X-Auto-Response-Suppress", "all") ||
                             header_has("X-Auto-Response-Suppress", "dr;rn;autoreply"))
                    {
                        mark_no_reply = true;
                    }
                    else if (header_has("Precedence", "bulk") ||
                             header_has("Precedence", "list"))
                    {
                        // Bulk/list often are mailshot notifications; still conservative.
                        mark_no_reply = true;
                    }
                }
                if (mark_no_reply)
                    msg.no_reply(true);
                    
            }
            catch (const dialog_error &ex)
            {
                if (!strict_mode_)
                {
                    msg.error_state(true);
                    msg.error(std::string("Error pasing message: ") + ex.what() + "\nDetails: " + ex.details());
                }
                else
                    throw;
            }
            catch (const mime_error &ex)
            {
                if (!strict_mode_)
                {
                    msg.error_state(true);
                    msg.error(std::string("Error pasing message: ") + ex.what() + "\nDetails: " + ex.details());
                }
                else
                    throw;
            }
            catch (const std::exception &ex)
            {
                if (!strict_mode_)
                {
                    msg.error_state(true);
                    msg.error(std::string("Error pasing message: ") + ex.what());
                }
                else
                    throw;
            }
            found_messages.emplace(ms.first, move(msg));
        }
    };
    
    // Flag whether the response line is the last one i.e. the tagged response.
    bool has_more = true;
    // Determine if the caller asked for exactly one message id (seq or uid), not a range/open-ended.
    const bool is_single_fetch = (messages_range.size() == 1) &&
        (messages_range.front().second.has_value()) &&
        (messages_range.front().first == messages_range.front().second.value());
    try
    {
        while (has_more)
        {
            reset_response_parser();
            string line = dlg_->receive();
            tag_result_response_t parsed_line = parse_tag_result(line);

            // The untagged response collects all messages.
            if (parsed_line.tag == UNTAGGED_RESPONSE)
            {
                parse_response(parsed_line.response);

                // Tolerate unrelated untagged responses (e.g., EXISTS/RECENT/EXPUNGE/OK CAPABILITY).
                if (mandatory_part_.empty() || mandatory_part_.front()->token_type != response_token_t::token_type_t::ATOM)
                    continue;

                unsigned long sequence_no = 0;
                try {
                    sequence_no = stoul(mandatory_part_.front()->atom);
                } catch (...) {
                    // Not a numeric leading atom -> unsolicited untagged; skip.
                    continue;
                }
                mandatory_part_.pop_front();
                if (sequence_no == 0)
                    continue; // invalid seq, ignore rather than fail

                if (mandatory_part_.empty() || mandatory_part_.front()->token_type != response_token_t::token_type_t::ATOM ||
                    !iequals(mandatory_part_.front()->atom, "FETCH"))
                    continue; // unsolicited untagged, not a FETCH line

                unsigned long uid_no = 0;
                vector<string> message_flags;
                shared_ptr<response_token_t> literal_token = nullptr;
                // Keep a reference to the FETCH data list to allow rescanning after reading a literal
                shared_ptr<response_token_t> fetch_list_token = nullptr;
                auto parse_fetch_metadata = [&]() {
                    if (fetch_list_token == nullptr)
                        return;
                    message_flags.clear();
                    for (auto token = fetch_list_token->parenthesized_list.begin(); token != fetch_list_token->parenthesized_list.end(); ++token)
                    {
                        const auto& current = *token;
                        if (current->token_type != response_token_t::token_type_t::ATOM)
                            continue;

                        if (iequals(current->atom, "UID"))
                        {
                            auto next = token;
                            ++next;
                            if (next == fetch_list_token->parenthesized_list.end() ||
                                (*next)->token_type != response_token_t::token_type_t::ATOM)
                                throw imap_error("No uid number when fetching a message.", "");
                            uid_no = stoul((*next)->atom);
                        }
                        else if (iequals(current->atom, "FLAGS"))
                        {
                            auto next = token;
                            ++next;
                            if (next == fetch_list_token->parenthesized_list.end())
                                continue;
                            const auto& flags_token = *next;
                            auto add_flag = [&](const shared_ptr<response_token_t>& flag_token) {
                                if (flag_token != nullptr &&
                                    flag_token->token_type == response_token_t::token_type_t::ATOM &&
                                    !flag_token->atom.empty())
                                {
                                    message_flags.push_back(flag_token->atom);
                                }
                            };
                            if (flags_token->token_type == response_token_t::token_type_t::LIST)
                            {
                                for (const auto& flag_token : flags_token->parenthesized_list)
                                    add_flag(flag_token);
                            }
                            else if (flags_token->token_type == response_token_t::token_type_t::ATOM)
                            {
                                add_flag(flags_token);
                            }
                        }
                    }
                };
                for (auto part : mandatory_part_)
                    if (part->token_type == response_token_t::token_type_t::LIST)
                    {
                        fetch_list_token = part;
                        for (auto token = part->parenthesized_list.begin(); token != part->parenthesized_list.end(); token++)
                        {
                            if ((*token)->token_type == response_token_t::token_type_t::ATOM)
                            {
                                if (iequals((*token)->atom, RFC822_TOKEN)
                                         || iequals((*token)->atom, "BODY[]")
                                         || iequals((*token)->atom, "BODY.PEEK[]")
                                         || iequals((*token)->atom, "RFC822.HEADER")
                                         || iequals((*token)->atom, "BODY[HEADER]")
                                         || iequals((*token)->atom, "BODY.PEEK[HEADER]"))
                                {
                                    token++;
                                    if (token == part->parenthesized_list.end() || (*token)->token_type != response_token_t::token_type_t::LITERAL)
                                        throw imap_error("No literal when fetching a message.", "");
                                    literal_token = *token;
                                    // Do not break here; keep scanning existing tokens for UID as well.
                                }
                            }
                            else if ((*token)->token_type == response_token_t::token_type_t::LITERAL && literal_token == nullptr)
                            {
                                // Be permissive: when only UID and BODY were requested, the first literal in the FETCH data is the message payload.
                                literal_token = *token;
                            }
                        }
                    }

                if (literal_token != nullptr)
                {
                    // Read the literal payload exactly. The CRLF after the size marker was already consumed by the
                    // line-based receive that delivered the '{N}' line to the parser.
                    try
                    {
                        const auto literal_size = stoul(literal_token->literal_size);
                        literal_token->literal = dlg_->receive_bytes(literal_size);
                        // Mark literal parsing done for the internal state machine.
                        literal_bytes_read_ = literal_size;
                        literal_state_ = string_literal_state_t::DONE;
                    }
                    catch (const dialog_error&)
                    {
                        throw; // rethrow as dialog_error -> imap_error caught later
                    }

                    // After the literal payload, the server continues the same response line (e.g., ")" or " UID <n>)").
                    // Read the remainder of that line and parse it to close lists and capture any trailing atoms.
                    if (parenthesis_list_counter_ > 0 || literal_state_ == string_literal_state_t::DONE)
                    {
                        string tail = dlg_->receive(true);
                        if (!tail.empty())
                            trim_eol(tail);
                        parse_response(tail);
                    }
                    // After reading the literal, parse UID/FLAGS data (best-effort for flags).
                    parse_fetch_metadata();
                    // If no UID was found but we used UID FETCH, signal an error now that the full response was parsed.
                    if (is_uids && uid_no == 0)
                        throw imap_error("No UID when fetching a message.", "");

                    // Ignore unsolicited FETCH responses outside the requested range.
                    auto in_requested_range = [&](unsigned long id) -> bool {
                        for (const auto &rng : messages_range)
                        {
                            const unsigned long start = rng.first;
                            if (id < start)
                                continue;
                            if (rng.second.has_value())
                            {
                                if (id <= rng.second.value())
                                    return true;
                            }
                            else
                            {
                                // Open-ended range start:* matches any id >= start
                                return true;
                            }
                        }
                        return false;
                    };
                    const unsigned long id_for_range = is_uids ? uid_no : sequence_no;
                    if (!in_requested_range(id_for_range))
                    {
                        // Message not requested by the current FETCH range; treat as unsolicited and skip.
                        debug_bugfix("Fetch skipped unsolicited message #" + to_string(id_for_range));
                        continue;
                    }
                    // Capture the raw RFC 822 bytes of the message.
                    string raw = move(literal_token->literal);
                    // Compute a SHA-256 dedupe hash of the raw content, if openssl is available.
                    string dedupe_hash{};
#if defined(MAILIO_HAVE_OPENSSL)
                    dedupe_hash = sha256_hex(raw);
#endif
                    // Normalize end-of-lines to CRLF for parsing. After switching to chunk-based timeouts,
                    // some servers/messages may present bare LF or lone CR. The MIME/codec stack expects
                    // consistent CRLFs and will split into lines without embedded CR/LF before 7bit decode.
                    if (!raw.empty())
                    {
                        string normalized;
                        normalized.reserve(raw.size() + raw.size() / 32);
                        for (size_t i = 0; i < raw.size(); ++i)
                        {
                            char c = raw[i];
                            if (c == '\r')
                            {
                                if (i + 1 < raw.size() && raw[i + 1] == '\n')
                                {
                                    // Already CRLF, copy once and skip the LF.
                                    normalized += "\r\n";
                                    ++i;
                                }
                                else
                                {
                                    // Lone CR -> CRLF
                                    normalized += "\r\n";
                                }
                            }
                            else if (c == '\n')
                            {
                                // Bare LF -> CRLF
                                normalized += "\r\n";
                            }
                            else
                            {
                                normalized += c;
                            }
                        }
                        raw.swap(normalized);
                    }
                    
                    // Add the message to the msg map
                    msg_str.emplace(
                        is_uids ? uid_no : sequence_no,
                        make_tuple(
                            move(raw),
                            uid_no,
                            sequence_no,
                            move(dedupe_hash),
                            move(message_flags)
                        )
                    );
                    
                }
            }
            // The tagged response determines status and parses provided messages in `msg_str`.
            else if (parsed_line.tag == to_string(tag_))
            {
                if (parsed_line.result.value() == tag_result_response_t::OK)
                {
                    has_more = false;
                    finalize_collected();
                }
                else if (parsed_line.result.value() == tag_result_response_t::NO)
                {
                    // Some servers respond with NO when any requested messages in a range no longer
                    // exist (e.g., UID FETCH 53498:*). In that case, return whatever messages we
                    // collected and do not throw. 
                    has_more = false;
                    finalize_collected();
                }
                else
                    throw imap_error("Fetching message failure.", "Response=`" + parsed_line.response + "`.");
            }
            else
                throw imap_error("Invalid tag when fetching a message.", "Parsed tag=`" + parsed_line.tag + "`.");
        }
    }
    catch (const invalid_argument& exc)
    {
        throw imap_error("Parsing failure.", exc.what());
    }
    catch (const out_of_range& exc)
    {
        throw imap_error("Parsing failure.", exc.what());
    }

    reset_response_parser();
}


void imap::append(const list<string>& folder_name, const message& msg)
{
    string delim = folder_delimiter();
    string folder_name_s = folder_tree_to_string(folder_name, delim);
    append(folder_name_s, msg);
}


void imap::append(const string& folder_name, const message& msg)
{
    string msg_str;
    msg.format(msg_str, message_format_options_t{true, false});

    string cmd = "APPEND " + to_astring(folder_name);
    cmd.append(" {" + to_string(msg_str.size()) + "}");
    dlg_->send(format(cmd));
    string line = dlg_->receive();
    tag_result_response_t parsed_line = parse_tag_result(line);
    if (parsed_line.result == tag_result_response_t::BAD || parsed_line.tag != CONTINUE_RESPONSE)
        throw imap_error("Message appending failure.", "Response=`" + parsed_line.response + "`.");

    dlg_->send(msg_str);
    bool has_more = true;
    while (has_more)
    {
        line = dlg_->receive();
        tag_result_response_t parsed_line = parse_tag_result(line);
        if (parsed_line.tag == to_string(tag_))
        {
            if (parsed_line.result != tag_result_response_t::OK)
                throw imap_error("Message appending failure.", "Line=`" + line + "`.");
            has_more = false;
        }
        else if (parsed_line.tag != UNTAGGED_RESPONSE)
            throw imap_error("Expecting the untagged response.", "Tag=`" + parsed_line.tag + "`.");
    }
}


auto imap::statistics(const string& mailbox, unsigned int info) -> mailbox_stat_t
{
    mailbox_stat_t stat;
    stat.mailbox_name = mailbox;
    // It doesn't like search terms it doesn't recognize.
    // Some older protocol versions or some servers may not support them.
    // So unseen uidnext and uidvalidity are optional.
    string cmd = "STATUS " + to_astring(mailbox) + " (messages recent";
    if (info & mailbox_stat_t::UNSEEN)
        cmd += " unseen";
    if (info & mailbox_stat_t::UID_NEXT)
        cmd += " uidnext";
    if (info & mailbox_stat_t::UID_VALIDITY)
        cmd += " uidvalidity";
    // Only request HIGHESTMODSEQ if asked for and the server advertises CONDSTORE.
    if ((info & mailbox_stat_t::HIGHEST_MODSEQ) &&
        std::find_if(capabilities().begin(), capabilities().end(), [](const std::string &cap){ return boost::iequals(cap, "CONDSTORE"); }) != capabilities().end())
        cmd += " highestmodseq";
    cmd += ")";

    dlg_->send(format(cmd));

    bool has_more = true;
    try
    {
        while (has_more)
        {
            reset_response_parser();
            string line = dlg_->receive();
            tag_result_response_t parsed_line = parse_tag_result(line);

            if (parsed_line.tag == UNTAGGED_RESPONSE)
            {
                parse_response(parsed_line.response);
                if (!iequals(mandatory_part_.front()->atom, "STATUS"))
                    throw imap_error("Expecting the status atom.", "Line=`" + line + "`.");
                mandatory_part_.pop_front();

                bool mess_found = false, recent_found = false;
                for (auto it = mandatory_part_.begin(); it != mandatory_part_.end(); it++)
                    if ((*it)->token_type == response_token_t::token_type_t::LIST && (*it)->parenthesized_list.size() >= 2)
                    {
                        bool key_found = false;
                        string key;
                        auto mp = *it;
                        for(auto il = mp->parenthesized_list.begin(); il != mp->parenthesized_list.end(); ++il)
                        {
                            const string& value = (*il)->atom;
                            if (key_found)
                            {
                                if (iequals(key, "MESSAGES"))
                                {
                                    stat.messages_no = stoul(value);
                                    mess_found = true;
                                }
                                else if (iequals(key, "RECENT"))
                                {
                                    stat.messages_recent = stoul(value);
                                    recent_found = true;
                                }
                                else if (iequals(key, "UNSEEN"))
                                {
                                    stat.messages_unseen = stoul(value);
                                }
                                else if (iequals(key, "UIDNEXT"))
                                {
                                    stat.uid_next = stoul(value);
                                }
                                else if (iequals(key, "UIDVALIDITY"))
                                {
                                    stat.uid_validity = stoul(value);
                                }
                                else if (iequals(key, "HIGHESTMODSEQ"))
                                {
                                    // RFC 7162: mod-sequence is a 64-bit integer.
                                    stat.highest_modseq = std::stoull(value);
                                }
                                key_found = false;
                            }
                            else
                            {
                                key = value;
                                key_found = true;
                            }
                        }
                    }
                // The MESSAGES and RECENT are required.
                if (!mess_found || !recent_found)
                    throw imap_error("No messages or recent messages found.", "");
            }
            else if (parsed_line.tag == to_string(tag_))
            {
                if (parsed_line.result.has_value() && parsed_line.result.value() == tag_result_response_t::OK)
                {
                    has_more = false;
                }
                else
                {
                    // Best-effort: treat NO/BAD as missing/inaccessible mailbox instead of throwing.
                    stat.not_exist = true;
                    reset_response_parser();
                    return stat;
                }
            }
            else
                throw imap_error("Parsing failure.", "Tag=`" + parsed_line.tag + "`.");
        }
    }
    catch (const invalid_argument& exc)
    {
        throw imap_error("Parsing failure.", exc.what());
    }
    catch (const out_of_range& exc)
    {
        throw imap_error("Parsing failure.", exc.what());
    }

    reset_response_parser();
    return stat;
}


auto imap::statistics(const list<string>& folder_name, unsigned int info) -> mailbox_stat_t
{
    string delim = folder_delimiter();
    string folder_name_s = folder_tree_to_string(folder_name, delim);
    auto stat = statistics(folder_name_s, info);
    stat.mailbox_name = folder_name_s;
    return stat;
}

std::vector<imap::mailbox_stat_t> imap::bulk_status(const std::vector<std::string>& mailboxes)
{
    std::vector<mailbox_stat_t> out;
    out.reserve(mailboxes.size());

    if (mailboxes.empty())
        return out;

    const auto &caps = capabilities();
    auto has_cap = [&](const std::string &cap){
        return std::find_if(caps.begin(), caps.end(), [&](const std::string& c){ return iequals(c, cap); }) != caps.end();
    };
    const bool support_list_status = has_cap("LIST-STATUS");
    const bool support_condstore = has_cap("CONDSTORE");

    // Fast-path for a single mailbox: use the lightweight `STATUS` via `statistics()`.
    // Avoiding LIST "" * for a single mailbox, which would happen with e.g. Gmail
    if (mailboxes.size() == 1)
    {
        unsigned int info = mailbox_stat_t::UID_NEXT | mailbox_stat_t::UID_VALIDITY;
        if (support_condstore)
            info |= mailbox_stat_t::HIGHEST_MODSEQ;
        mailbox_stat_t stat = statistics(mailboxes.front(), info);
        stat.mailbox_name = mailboxes.front();
        out.push_back(std::move(stat));
        return out;
    }

    auto normalize_mailbox = [](std::string s) -> std::string
    {
        boost::trim(s);
        if (s.size() >= 2 && s.front() == '"' && s.back() == '"')
            s = s.substr(1, s.size() - 2);
        boost::trim(s);
        return s;
    };

    // Helper: scan a parenthesized list for key/value pairs (MESSAGES/UIDNEXT/...).
    auto scan_kv_pairs_in_list = [&](mailbox_stat_t& stat, const std::list<std::shared_ptr<response_token_t>>& pl)
    {
        bool key_found = false;
        string key;
        for (const auto& elem : pl)
        {
            if (elem->token_type != response_token_t::token_type_t::ATOM)
            {
                // Reset on non-atom to avoid dangling keys across nested lists.
                key_found = false;
                continue;
            }
            if (!key_found)
            {
                key = elem->atom;
                key_found = true;
                continue;
            }

            const string& value = elem->atom;
            if (iequals(key, "MESSAGES")) stat.messages_no = stoul(value);
            else if (iequals(key, "UIDNEXT")) stat.uid_next = stoul(value);
            else if (iequals(key, "UIDVALIDITY")) stat.uid_validity = stoul(value);
            else if (iequals(key, "HIGHESTMODSEQ")) stat.highest_modseq = std::stoull(value);
            key_found = false;
        }
    };

    // Helper: recursively walk tokens and capture any STATUS-like key/value lists, including LIST-STATUS nesting.
    auto scan_token_tree = [&](auto&& self, mailbox_stat_t& stat, const std::list<std::shared_ptr<response_token_t>>& lst) -> void
    {
        for (const auto& tok : lst)
        {
            if (tok->token_type != response_token_t::token_type_t::LIST)
                continue;

            // Scan this list directly (covers plain STATUS responses: (MESSAGES 1 UIDNEXT 2 ...)).
            scan_kv_pairs_in_list(stat, tok->parenthesized_list);

            // Handle LIST-STATUS wrapper: (STATUS (MESSAGES 1 UIDNEXT 2 ...))
            if (tok->parenthesized_list.size() >= 2)
            {
                auto it = tok->parenthesized_list.begin();
                if ((*it)->token_type == response_token_t::token_type_t::ATOM && iequals((*it)->atom, "STATUS"))
                {
                    ++it;
                    if (it != tok->parenthesized_list.end() && (*it)->token_type == response_token_t::token_type_t::LIST)
                        scan_kv_pairs_in_list(stat, (*it)->parenthesized_list);
                }
            }

            // Recurse into nested lists.
            self(self, stat, tok->parenthesized_list);
        }
    };

    // Helper: parse an untagged STATUS response and update stats_by_name.
    auto parse_untagged_status = [&](const std::string& response, std::unordered_map<std::string, mailbox_stat_t>& stats_by_name) -> std::optional<std::string>
    {
        try
        {
            reset_response_parser();
            parse_response(response);
            if (mandatory_part_.empty() || mandatory_part_.front()->token_type != response_token_t::token_type_t::ATOM ||
                !iequals(mandatory_part_.front()->atom, "STATUS"))
            {
                reset_response_parser();
                return std::nullopt;
            }

            mandatory_part_.pop_front();
            if (mandatory_part_.empty() || mandatory_part_.front()->token_type != response_token_t::token_type_t::ATOM)
            {
                reset_response_parser();
                return std::nullopt;
            }

            const std::string mailbox = normalize_mailbox(mandatory_part_.front()->atom);
            auto& stat = stats_by_name[mailbox];
            stat.mailbox_name = mailbox;
            scan_token_tree(scan_token_tree, stat, mandatory_part_);
            scan_token_tree(scan_token_tree, stat, optional_part_);
            reset_response_parser();
            return mailbox;
        }
        catch (...)
        {
            reset_response_parser();
            return std::nullopt;
        }
    };

    // LIST-STATUS path (if supported): use a single LIST ... RETURN (STATUS ...) and filter client-side.
    if (support_list_status)
    {
        std::unordered_map<std::string, mailbox_stat_t> stats_by_name;
        stats_by_name.reserve(mailboxes.size());

        std::string cmd = "LIST \"\" * RETURN (STATUS (messages uidnext uidvalidity";
        if (support_condstore)
            cmd += " highestmodseq";
        cmd += "))";

        const unsigned tag_no = tag_ + 1;
        dlg_->send(format(cmd));

        bool has_more = true;
        bool tagged_ok = false;
        while (has_more)
        {
            std::string line = dlg_->receive();
            auto parsed_line = parse_tag_result(line);
            if (parsed_line.tag == UNTAGGED_RESPONSE)
            {
                // Some servers (e.g., Gmail) reply with separate untagged STATUS lines after LIST.
                // Prefer parsing STATUS lines directly.
                if (parse_untagged_status(parsed_line.response, stats_by_name).has_value())
                    continue;

                // Expect LIST responses which may embed STATUS lists (LIST-STATUS).
                try
                {
                    reset_response_parser();
                    parse_response(parsed_line.response);

                    // Extract mailbox name from: LIST <attr-list> <delim> <mailbox> ...
                    std::string mailbox;
                    auto it = mandatory_part_.begin();
                    for (; it != mandatory_part_.end(); ++it)
                    {
                        if ((*it)->token_type == response_token_t::token_type_t::ATOM && iequals((*it)->atom, "LIST"))
                            break;
                    }
                    if (it != mandatory_part_.end())
                    {
                        ++it; // after LIST
                        if (it != mandatory_part_.end() && (*it)->token_type == response_token_t::token_type_t::LIST)
                            ++it; // attributes
                        if (it != mandatory_part_.end() && (*it)->token_type == response_token_t::token_type_t::ATOM)
                            ++it; // delimiter
                        if (it != mandatory_part_.end() && (*it)->token_type == response_token_t::token_type_t::ATOM)
                            mailbox = normalize_mailbox((*it)->atom);
                    }

                    if (!mailbox.empty())
                    {
                        auto& stat = stats_by_name[mailbox];
                        stat.mailbox_name = mailbox;
                        // LIST-STATUS nests STATUS inside a list; recurse to find (STATUS (...)) anywhere.
                        scan_token_tree(scan_token_tree, stat, mandatory_part_);
                        scan_token_tree(scan_token_tree, stat, optional_part_);
                    }

                    reset_response_parser();
                }
                catch (...)
                {
                    reset_response_parser();
                }
            }
            else if (parsed_line.tag == to_string(tag_no))
            {
                tagged_ok = parsed_line.result.has_value() && parsed_line.result.value() == tag_result_response_t::OK;
                has_more = false;
            }
            else
            {
                // Ignore unsolicited responses.
                continue;
            }
        }

        if (tagged_ok)
        {
            // Preserve order and always emit one stat per requested mailbox.
            // If exact match is missing, try case-insensitive match as a fallback.
            std::unordered_map<std::string, std::string> lower_to_key;
            lower_to_key.reserve(stats_by_name.size());
            for (const auto& kv : stats_by_name)
            {
                std::string lower = boost::to_lower_copy(kv.first);
                if (lower_to_key.find(lower) == lower_to_key.end())
                    lower_to_key.emplace(std::move(lower), kv.first);
            }

            for (const auto& mb : mailboxes)
            {
                mailbox_stat_t stat;
                stat.mailbox_name = mb;
                auto it = stats_by_name.find(normalize_mailbox(mb));
                if (it == stats_by_name.end())
                {
                    auto lt = lower_to_key.find(boost::to_lower_copy(mb));
                    if (lt != lower_to_key.end())
                        it = stats_by_name.find(lt->second);
                }

                if (it != stats_by_name.end())
                {
                    stat = it->second;
                    stat.mailbox_name = mb;
                }
                else
                {
                    stat.not_exist = true;
                }

                out.push_back(std::move(stat));
            }
            reset_response_parser();
            return out;
        }

        // If LIST-STATUS path failed (non-OK), fall through to the STATUS fallback.
        reset_response_parser();
    }

    // Fallback path (no LIST-STATUS, e.g., Gmail/Outlook): pipeline STATUS commands in small batches.
    // This avoids RTT-per-mailbox latency and adds capped adaptive throttling to reduce rate-limit risk.
    {
        std::unordered_map<std::string, mailbox_stat_t> stats_by_name;
        stats_by_name.reserve(mailboxes.size());
        std::unordered_set<std::string> not_exist;
        not_exist.reserve(mailboxes.size());

        // Throttle policy: enforce a minimum batch wall time by inserting sleeps when the server is very fast.
        // Cap the total added delay so "~100 mailboxes" stays in the seconds range; beyond that, callers
        // should implement higher-level pacing if they need it.
        const std::size_t batch_size = 10;
        const auto min_batch_duration = milliseconds(250);
        auto sleep_budget = milliseconds(static_cast<long long>(std::min<std::size_t>(2500, mailboxes.size() * 25))); // <= ~2.5s extra

        std::size_t i = 0;
        while (i < mailboxes.size())
        {
            const std::size_t end = std::min(mailboxes.size(), i + batch_size);
            const auto batch_start = steady_clock::now();

            std::unordered_set<unsigned long> pending_tags;
            pending_tags.reserve(end - i);
            std::unordered_map<unsigned long, std::string> tag_to_mailbox;
            tag_to_mailbox.reserve(end - i);
            std::unordered_set<std::string> saw_status_mailbox;
            saw_status_mailbox.reserve(end - i);

            for (std::size_t j = i; j < end; ++j)
            {
                const std::string& mb = mailboxes[j];
                const std::string mb_norm = normalize_mailbox(mb);
                std::string cmd = "STATUS " + to_astring(mb) + " (messages uidnext uidvalidity";
                if (support_condstore)
                    cmd += " highestmodseq";
                cmd += ")";

                const unsigned long tag_no = static_cast<unsigned long>(tag_ + 1);
                dlg_->send(format(cmd));
                pending_tags.insert(tag_no);
                tag_to_mailbox.emplace(tag_no, mb_norm);
            }

            while (!pending_tags.empty())
            {
                std::string line = dlg_->receive();
                auto parsed_line = parse_tag_result(line);

                if (parsed_line.tag == UNTAGGED_RESPONSE)
                {
                    auto mb = parse_untagged_status(parsed_line.response, stats_by_name);
                    if (mb.has_value())
                        saw_status_mailbox.insert(mb.value());
                    continue;
                }

                // Tagged completion.
                unsigned long tag_val = 0;
                try
                {
                    tag_val = stoul(parsed_line.tag);
                }
                catch (...)
                {
                    continue; // unrelated tagged response
                }

                auto pt = pending_tags.find(tag_val);
                if (pt == pending_tags.end())
                    continue; // unrelated tagged response

                const auto mb_it = tag_to_mailbox.find(tag_val);
                const std::string mb = (mb_it != tag_to_mailbox.end()) ? mb_it->second : std::string{};

                if (!parsed_line.result.has_value() || parsed_line.result.value() != tag_result_response_t::OK)
                {
                    if (!mb.empty())
                        not_exist.insert(mb);
                }
                else
                {
                    // STATUS should have produced an untagged STATUS line; if it didn't, treat as inaccessible.
                    if (!mb.empty() && saw_status_mailbox.find(mb) == saw_status_mailbox.end())
                        not_exist.insert(mb);
                }

                pending_tags.erase(pt);
            }

            const auto elapsed = duration_cast<milliseconds>(steady_clock::now() - batch_start);
            if (elapsed < min_batch_duration && sleep_budget.count() > 0)
            {
                auto sleep_for = std::min(min_batch_duration - elapsed, sleep_budget);
                if (sleep_for.count() > 0)
                {
                    std::this_thread::sleep_for(sleep_for);
                    sleep_budget -= sleep_for;
                }
            }

            i = end;
        }

        // Materialize output in input order.
        for (const auto& mb : mailboxes)
        {
            mailbox_stat_t stat;
            stat.mailbox_name = mb;
            const auto mb_norm = normalize_mailbox(mb);
            if (not_exist.find(mb_norm) != not_exist.end())
            {
                stat.not_exist = true;
            }
            else
            {
                auto it = stats_by_name.find(mb_norm);
                if (it != stats_by_name.end())
                {
                    stat = it->second;
                    stat.mailbox_name = mb;
                }
                else
                {
                    stat.not_exist = true;
                }
            }
            out.push_back(std::move(stat));
        }
    }

    reset_response_parser();
    return out;
}


unsigned long imap::status_uidnext(const string& mailbox)
{
    // Issue the light-weight STATUS for UIDNEXT only.
    string cmd = "STATUS " + to_astring(mailbox) + " (uidnext)";
    dlg_->send(format(cmd));

    unsigned long uidnext = 0;
    bool has_more = true;
    try
    {
        while (has_more)
        {
            reset_response_parser();
            string line = dlg_->receive();
            tag_result_response_t parsed_line = parse_tag_result(line);

            if (parsed_line.tag == UNTAGGED_RESPONSE)
            {
                parse_response(parsed_line.response);
                if (mandatory_part_.empty() || mandatory_part_.front()->token_type != response_token_t::token_type_t::ATOM ||
                    !iequals(mandatory_part_.front()->atom, "STATUS"))
                    throw imap_error("Expecting the status atom.", "Line=`" + line + "`.");
                mandatory_part_.pop_front();

                // Expect: STATUS <mailbox> (UIDNEXT <num> ...)
                // Find the first list token and scan for UIDNEXT
                for (auto it = mandatory_part_.begin(); it != mandatory_part_.end(); ++it)
                {
                    if ((*it)->token_type == response_token_t::token_type_t::LIST && (*it)->parenthesized_list.size() >= 2)
                    {
                        bool have_key = false;
                        string key;
                        for (const auto &elem : (*it)->parenthesized_list)
                        {
                            const string &val = elem->atom;
                            if (!have_key)
                            {
                                key = val;
                                have_key = true;
                            }
                            else
                            {
                                if (iequals(key, "UIDNEXT"))
                                {
                                    uidnext = stoul(val);
                                    // Continue processing until tagged OK is received
                                }
                                have_key = false;
                            }
                        }
                    }
                }
            }
            else if (parsed_line.tag == to_string(tag_))
            {
                if (parsed_line.result.has_value() && parsed_line.result.value() == tag_result_response_t::OK)
                    has_more = false;
                else
                    throw imap_error("STATUS UIDNEXT failure.", "Line=`" + line + "`.");
            }
            else
                throw imap_error("Parsing failure.", "Tag=`" + parsed_line.tag + "`.");
        }
    }
    catch (const invalid_argument& exc)
    {
        throw imap_error("Parsing failure.", exc.what());
    }
    catch (const out_of_range& exc)
    {
        throw imap_error("Parsing failure.", exc.what());
    }

    reset_response_parser();
    return uidnext;
}


unsigned long imap::uid_from_sequence_no(unsigned long seq_no)
{
    // Query the UID for a specific message sequence number.
    // Send: FETCH <seq_no> (UID)
    // If the message does not exist (e.g., empty mailbox or out-of-range), treat as 0.

    string cmd = "FETCH " + to_string(seq_no) + " (UID)";
    dlg_->send(format(cmd));

    unsigned long uid = 0;
    bool has_more = true;
    try
    {
        while (has_more)
        {
            reset_response_parser();
            string line = dlg_->receive();
            tag_result_response_t parsed_line = parse_tag_result(line);

            if (parsed_line.tag == UNTAGGED_RESPONSE)
            {
                // Expect: * <seq> FETCH (UID <n>)
                parse_response(parsed_line.response);

                // Some servers may interleave unrelated untagged responses; skip those.
                if (mandatory_part_.empty() || mandatory_part_.front()->token_type != response_token_t::token_type_t::ATOM)
                    continue;

                // Verify sequence number matches, if present; otherwise proceed leniently.
                unsigned long got_seq = 0;
                try
                {
                    got_seq = stoul(mandatory_part_.front()->atom);
                }
                catch (...)
                {
                    // Not a FETCH line we can interpret; skip.
                    continue;
                }

                // Advance and expect FETCH atom next.
                mandatory_part_.pop_front();
                if (mandatory_part_.empty() || mandatory_part_.front()->token_type != response_token_t::token_type_t::ATOM ||
                    !iequals(mandatory_part_.front()->atom, "FETCH"))
                {
                    // Not a FETCH payload; ignore.
                    continue;
                }

                // Scan the first list for UID <n>.
                for (auto part : mandatory_part_)
                {
                    if (part->token_type == response_token_t::token_type_t::LIST)
                    {
                        bool have_key = false;
                        string key;
                        for (const auto &elem : part->parenthesized_list)
                        {
                            if (elem->token_type != response_token_t::token_type_t::ATOM)
                                continue;
                            const string &a = elem->atom;
                            if (!have_key)
                            {
                                key = a;
                                have_key = true;
                            }
                            else
                            {
                                if (iequals(key, "UID"))
                                {
                                    uid = stoul(a);
                                }
                                have_key = false;
                            }
                        }
                    }
                }

                // If server returned different sequence number, do not treat as success; wait for tagged completion.
                (void)got_seq; // current implementation does not enforce equality strictly.
            }
            else if (parsed_line.tag == to_string(tag_))
            {
                // Completion of the FETCH command.
                if (!parsed_line.result.has_value() || parsed_line.result.value() != tag_result_response_t::OK)
                {
                    // Many servers return NO/BAD if the sequence number is out of range.
                    // In that case, return 0 to indicate "no such message".
                    has_more = false;
                }
                else
                {
                    has_more = false;
                }
            }
            else
            {
                throw imap_error("Parsing failure.", "Tag=`" + parsed_line.tag + "`.");
            }
        }
    }
    catch (const invalid_argument &)
    {
        reset_response_parser();
        return 0UL;
    }
    catch (const out_of_range &)
    {
        reset_response_parser();
        return 0UL;
    }

    reset_response_parser();
    return uid;
}


auto imap::changed_since(unsigned long long mod_seq) -> changed_since_result_t
{
    // CHANGEDSINCE is defined by RFC 7162 (CONDSTORE/QRESYNC). Require that the server advertises it.
    const auto &caps = capabilities();
    const bool support_condstore = std::find_if(caps.begin(), caps.end(), [](const std::string &cap){ return boost::iequals(cap, "CONDSTORE"); }) != caps.end();
    const bool support_qresync = std::find_if(caps.begin(), caps.end(), [](const std::string &cap){ return boost::iequals(cap, "QRESYNC"); }) != caps.end();
    if (!support_condstore && !support_qresync)
        throw imap_error("Server does not support CONDSTORE/QRESYNC.", "");

    // Always use UID FETCH since callers want UIDs; sequence numbers are included only if present.
    // Ask for UID/FLAGS/MODSEQ and apply CHANGEDSINCE.
    std::string cmd = "UID FETCH 1:* (UID FLAGS MODSEQ) (CHANGEDSINCE " + std::to_string(mod_seq) + ")";
    dlg_->send(format(cmd));

    changed_since_result_t result;
    // De-duplicate by UID; some servers may emit multiple FETCH lines per message.
    std::map<unsigned long, changed_since_result_t::changed_message_t> changed_by_uid;
    std::vector<unsigned long> changed_order;
    bool has_more = true;

    // Parse uid-set strings like "1:4,9,11:12".
    auto parse_uid_set = [&](const std::string& uidset) -> std::vector<unsigned long> {
        std::vector<unsigned long> out;
        std::vector<std::string> parts;
        boost::split(parts, uidset, boost::is_any_of(LIST_SEPARATOR));
        for (auto p : parts)
        {
            boost::trim(p);
            if (p.empty() || p == RANGE_ALL)
                continue;
            auto colon = p.find(RANGE_SEPARATOR);
            if (colon == std::string::npos)
            {
                out.push_back(std::stoul(p));
                continue;
            }
            auto a = p.substr(0, colon);
            auto b = p.substr(colon + 1);
            boost::trim(a);
            boost::trim(b);
            if (a.empty() || b.empty() || a == RANGE_ALL || b == RANGE_ALL)
                continue;
            unsigned long start = std::stoul(a);
            unsigned long end = std::stoul(b);
            if (end < start)
                std::swap(start, end);
            // Expand ranges; callers can de-dup if needed.
            for (unsigned long v = start; v <= end; ++v)
            {
                out.push_back(v);
                if (v == std::numeric_limits<unsigned long>::max())
                    break;
            }
        }
        return out;
    };

    try
    {
        while (has_more)
        {
            reset_response_parser();
            std::string line = dlg_->receive();
            tag_result_response_t parsed_line = parse_tag_result(line);

            if (parsed_line.tag == UNTAGGED_RESPONSE)
            {
                parse_response(parsed_line.response);
                // Handle optional VANISHED responses if present.
                if (!mandatory_part_.empty() && mandatory_part_.front()->token_type == response_token_t::token_type_t::ATOM &&
                    iequals(mandatory_part_.front()->atom, "VANISHED"))
                {
                    // Expected: VANISHED [EARLIER] <uidset>
                    mandatory_part_.pop_front();
                    if (!mandatory_part_.empty() && mandatory_part_.front()->token_type == response_token_t::token_type_t::ATOM &&
                        iequals(mandatory_part_.front()->atom, "EARLIER"))
                        mandatory_part_.pop_front();

                    if (!mandatory_part_.empty() && mandatory_part_.front()->token_type == response_token_t::token_type_t::ATOM)
                    {
                        auto uids = parse_uid_set(mandatory_part_.front()->atom);
                        result.vanished_uids.insert(result.vanished_uids.end(), uids.begin(), uids.end());
                    }
                    continue;
                }

                // Expect: * <seq> FETCH (...)
                if (mandatory_part_.empty() || mandatory_part_.front()->token_type != response_token_t::token_type_t::ATOM)
                    continue;

                std::optional<unsigned long> seq_opt;
                try
                {
                    unsigned long seq = std::stoul(mandatory_part_.front()->atom);
                    if (seq != 0)
                        seq_opt = seq;
                }
                catch (...)
                {
                    continue; // unsolicited untagged
                }
                mandatory_part_.pop_front();

                if (mandatory_part_.empty() || mandatory_part_.front()->token_type != response_token_t::token_type_t::ATOM ||
                    !iequals(mandatory_part_.front()->atom, "FETCH"))
                    continue;

                unsigned long uid = 0;
                std::vector<std::string> flags;
                std::optional<unsigned long long> msg_modseq;

                // Find the FETCH attribute list and scan it.
                for (const auto& part : mandatory_part_)
                {
                    if (part->token_type != response_token_t::token_type_t::LIST)
                        continue;

                    const auto& lst = part->parenthesized_list;
                    for (auto it = lst.begin(); it != lst.end(); ++it)
                    {
                        const auto& tok = *it;
                        if (!tok || tok->token_type != response_token_t::token_type_t::ATOM)
                            continue;

                        if (iequals(tok->atom, "UID"))
                        {
                            auto nx = it; ++nx;
                            if (nx != lst.end() && *nx && (*nx)->token_type == response_token_t::token_type_t::ATOM)
                                uid = std::stoul((*nx)->atom);
                        }
                        else if (iequals(tok->atom, "FLAGS"))
                        {
                            auto nx = it; ++nx;
                            if (nx == lst.end() || !*nx)
                                continue;
                            const auto& ft = *nx;
                            auto add_flag = [&](const std::shared_ptr<response_token_t>& flag_token) {
                                if (flag_token && flag_token->token_type == response_token_t::token_type_t::ATOM && !flag_token->atom.empty())
                                    flags.push_back(flag_token->atom);
                            };
                            if (ft->token_type == response_token_t::token_type_t::LIST)
                            {
                                for (const auto& f : ft->parenthesized_list)
                                    add_flag(f);
                            }
                            else if (ft->token_type == response_token_t::token_type_t::ATOM)
                            {
                                add_flag(ft);
                            }
                        }
                        else if (iequals(tok->atom, "MODSEQ"))
                        {
                            auto nx = it; ++nx;
                            if (nx == lst.end() || !*nx)
                                continue;
                            const auto& mt = *nx;
                            // MODSEQ is typically a list: (12345)
                            if (mt->token_type == response_token_t::token_type_t::LIST && !mt->parenthesized_list.empty())
                            {
                                const auto& first = mt->parenthesized_list.front();
                                if (first && first->token_type == response_token_t::token_type_t::ATOM)
                                    msg_modseq = std::stoull(first->atom);
                            }
                            else if (mt->token_type == response_token_t::token_type_t::ATOM)
                            {
                                msg_modseq = std::stoull(mt->atom);
                            }
                        }
                    }

                    // Only one list is expected for FETCH attributes.
                    break;
                }

                if (uid == 0)
                {
                    // Best-effort: skip odd FETCH responses that don't carry UID.
                    debug_bugfix("CHANGEDSINCE skipped FETCH without UID: " + line);
                    continue;
                }

                changed_since_result_t::changed_message_t cm;
                cm.uid = uid;
                cm.sequence_no = seq_opt;
                cm.flags = std::move(flags);
                cm.modseq = msg_modseq;

                if (changed_by_uid.find(uid) == changed_by_uid.end())
                    changed_order.push_back(uid);
                changed_by_uid[uid] = std::move(cm);
            }
            else if (parsed_line.tag == to_string(tag_))
            {
                if (!parsed_line.result.has_value() || parsed_line.result.value() != tag_result_response_t::OK)
                    throw imap_error("CHANGEDSINCE failure.", "Response=`" + parsed_line.response + "`.");
                has_more = false;
            }
            else
            {
                throw imap_error("Parsing failure.", "Tag=`" + parsed_line.tag + "`." );
            }
        }
    }
    catch (const invalid_argument& exc)
    {
        throw imap_error("Parsing failure.", exc.what());
    }
    catch (const out_of_range& exc)
    {
        throw imap_error("Parsing failure.", exc.what());
    }

    reset_response_parser();
    // Materialize de-duplicated changes preserving first-seen order.
    result.changed.clear();
    result.changed.reserve(changed_order.size());
    for (auto uid : changed_order)
    {
        auto it = changed_by_uid.find(uid);
        if (it != changed_by_uid.end())
            result.changed.push_back(it->second);
    }

    // De-duplicate vanished UIDs (servers may repeat VANISHED on retransmission).
    if (!result.vanished_uids.empty())
    {
        std::sort(result.vanished_uids.begin(), result.vanished_uids.end());
        result.vanished_uids.erase(std::unique(result.vanished_uids.begin(), result.vanished_uids.end()), result.vanished_uids.end());
    }
    return result;
}


std::vector<std::string> imap::fetch_changed_gmail_labels(unsigned long long last_modseq)
{
    // CHANGEDSINCE is defined by RFC 7162 (CONDSTORE/QRESYNC). Gmail exposes a global MODSEQ.
    // Require server support for CHANGEDSINCE and Gmail's X-GM-EXT-1 extension.
    const auto &caps = capabilities();
    const auto has_cap = [&](const std::string &cap) {
        return std::find_if(caps.begin(), caps.end(), [&](const std::string &c){ return boost::iequals(c, cap); }) != caps.end();
    };
    if (!has_cap("CONDSTORE") && !has_cap("QRESYNC"))
        throw imap_error("Server does not support CONDSTORE/QRESYNC.", "");
    if (!has_cap("X-GM-EXT-1"))
        throw imap_error("Server does not support Gmail X-GM-EXT-1 (X-GM-LABELS).", "");

    // Execute exactly the Gmail-specific command requested by the caller.
    std::string cmd = "UID FETCH 1:* (X-GM-LABELS) (CHANGEDSINCE " + std::to_string(last_modseq) + ")";
    dlg_->send(format(cmd));

    std::vector<std::string> labels;
    std::unordered_set<std::string> seen;
    bool has_more = true;

    auto add_label = [&](const std::shared_ptr<response_token_t>& tok)
    {
        if (!tok)
            return;

        std::string s;
        if (tok->token_type == response_token_t::token_type_t::ATOM)
            s = tok->atom;
        else if (tok->token_type == response_token_t::token_type_t::LITERAL)
            s = tok->literal;
        else
            return;

        boost::trim(s);
        if (s.empty())
            return;

        if (seen.insert(s).second)
            labels.push_back(std::move(s));
    };

    try
    {
        while (has_more)
        {
            reset_response_parser();
            std::string line = dlg_->receive();
            tag_result_response_t parsed_line = parse_tag_result(line);

            if (parsed_line.tag == UNTAGGED_RESPONSE)
            {
                parse_response(parsed_line.response);

                // Ignore unrelated untagged responses (EXISTS/RECENT/OK/CAPABILITY/etc.).
                if (mandatory_part_.empty() || mandatory_part_.front()->token_type != response_token_t::token_type_t::ATOM)
                    continue;

                // Best-effort: ignore VANISHED responses (QRESYNC).
                if (iequals(mandatory_part_.front()->atom, "VANISHED"))
                    continue;

                // Expect: * <seq> FETCH (...)
                try
                {
                    (void)std::stoul(mandatory_part_.front()->atom);
                }
                catch (...)
                {
                    continue;
                }
                mandatory_part_.pop_front();

                if (mandatory_part_.empty() || mandatory_part_.front()->token_type != response_token_t::token_type_t::ATOM ||
                    !iequals(mandatory_part_.front()->atom, "FETCH"))
                    continue;

                // Find the FETCH attribute list.
                std::shared_ptr<response_token_t> fetch_list_token = nullptr;
                for (const auto& part : mandatory_part_)
                {
                    if (part && part->token_type == response_token_t::token_type_t::LIST)
                    {
                        fetch_list_token = part;
                        break;
                    }
                }
                if (!fetch_list_token)
                    continue;

                // Scan list for X-GM-LABELS.
                const auto& lst = fetch_list_token->parenthesized_list;
                for (auto it = lst.begin(); it != lst.end(); ++it)
                {
                    const auto& key = *it;
                    if (!key || key->token_type != response_token_t::token_type_t::ATOM)
                        continue;
                    if (!iequals(key->atom, "X-GM-LABELS"))
                        continue;

                    auto nx = it;
                    ++nx;
                    if (nx == lst.end() || !*nx)
                        break;

                    const auto& val = *nx;
                    if (val->token_type == response_token_t::token_type_t::LIST)
                    {
                        for (const auto& lab : val->parenthesized_list)
                            add_label(lab);
                    }
                    else
                    {
                        // Be permissive if server returns a non-list value.
                        add_label(val);
                    }
                }
            }
            else if (parsed_line.tag == to_string(tag_))
            {
                if (!parsed_line.result.has_value() || parsed_line.result.value() != tag_result_response_t::OK)
                    throw imap_error("Gmail label CHANGEDSINCE failure.", "Response=`" + parsed_line.response + "`.");
                has_more = false;
            }
            else
            {
                throw imap_error("Parsing failure.", "Tag=`" + parsed_line.tag + "`.");
            }
        }
    }
    catch (const invalid_argument& exc)
    {
        throw imap_error("Parsing failure.", exc.what());
    }
    catch (const out_of_range& exc)
    {
        throw imap_error("Parsing failure.", exc.what());
    }

    reset_response_parser();
    return labels;
}


void imap::remove(const string& mailbox, unsigned long message_no, bool is_uid)
{
    select(mailbox);
    remove(message_no, is_uid);
}


void imap::remove(const list<string>& mailbox, unsigned long message_no, bool is_uid)
{
    string delim = folder_delimiter();
    string mailbox_s = folder_tree_to_string(mailbox, delim);
    remove(mailbox_s, message_no, is_uid);
}


void imap::remove(unsigned long message_no, bool is_uid)
{
    string cmd;
    if (is_uid)
        cmd.append("UID ");
    cmd.append("STORE " + to_string(message_no) + " +FLAGS (\\Deleted)");
    dlg_->send(format(cmd));

    bool has_more = true;
    try
    {
        while (has_more)
        {
            reset_response_parser();
            string line = dlg_->receive();
            tag_result_response_t parsed_line = parse_tag_result(line);

            if (parsed_line.tag == UNTAGGED_RESPONSE)
            {
                parse_response(parsed_line.response);

                if (mandatory_part_.empty())
                    throw imap_error("No mandatory part.", "Response=`" + parsed_line.response + "`.");
                auto msg_no_token = mandatory_part_.front();
                mandatory_part_.pop_front();

                if (mandatory_part_.empty())
                    throw imap_error("No mandatory part.", "Response=`" + parsed_line.response + "`.");
                auto fetch_token = mandatory_part_.front();
                if (!iequals(fetch_token->atom, "FETCH"))
                    throw imap_error("Parsing failure.", "Tag=`" + fetch_token->atom + "`.");
                mandatory_part_.pop_front();

                // Check the list with flags.

                if (mandatory_part_.empty())
                    throw imap_error("No mandatory part.", "Response=`" + parsed_line.response + "`.");
                auto flags_token_list = mandatory_part_.front();
                if (flags_token_list->token_type != response_token_t::token_type_t::LIST)
                    throw imap_error("Expecting the list.", "Line=`" + line + "`.");

                std::shared_ptr<response_token_t> uid_token = nullptr;
                auto uid_token_it = flags_token_list->parenthesized_list.begin();
                do
                    if (iequals((*uid_token_it)->atom, "UID"))
                    {
                        uid_token_it++;
                        if (uid_token_it == flags_token_list->parenthesized_list.end())
                            throw imap_error("No UID.", "");
                        uid_token = *uid_token_it;
                        break;
                    }
                    else
                        uid_token_it++;
                while (uid_token_it != flags_token_list->parenthesized_list.end());

                if (is_uid)
                {
                    if (uid_token == nullptr)
                        throw imap_error("No UID.", "");
                    msg_no_token = uid_token;
                }

                if (msg_no_token->token_type != response_token_t::token_type_t::ATOM || stoul(msg_no_token->atom) != message_no)
                    throw imap_error("Deleting message failure.", "");

                continue;
            }
            else if (parsed_line.tag == to_string(tag_))
            {
                if (!parsed_line.result.has_value() || parsed_line.result.value() != tag_result_response_t::OK)
                    throw imap_error("Deleting message failure.", "");
                else
                {
                    reset_response_parser();
                    dlg_->send(format("CLOSE"));
                    string line = dlg_->receive();
                    tag_result_response_t parsed_line = parse_tag_result(line);

                    if (!iequals(parsed_line.tag, to_string(tag_)))
                        throw imap_error("Incorrect tag.", "Tag=`" + parsed_line.tag + "`.");
                    if (!parsed_line.result.has_value() || parsed_line.result.value() != tag_result_response_t::OK)
                        throw imap_error("Deleting message failure.", "");
                }
                has_more = false;
            }
            else
                throw imap_error("Incorrect tag.", "Tag=`" + parsed_line.tag + "`.");
        }
    }
    catch (const invalid_argument& exc)
    {
        throw imap_error("Parsing failure.", exc.what());
    }
    catch (const out_of_range& exc)
    {
        throw imap_error("Parsing failure.", exc.what());
    }
}


void imap::search(const list<imap::search_condition_t>& conditions, list<unsigned long>& results, bool want_uids)
{
    string cond_str;
    std::size_t elem = 0;
    for (const auto& c : conditions)
        if (elem++ < conditions.size() - 1)
            cond_str += c.imap_string + TOKEN_SEPARATOR_STR;
        else
            cond_str += c.imap_string;
    search(cond_str, results, want_uids);
}


bool imap::create_folder(const string& folder_name)
{
    dlg_->send(format("CREATE " + to_astring(folder_name)));

    string line = dlg_->receive();
    tag_result_response_t parsed_line = parse_tag_result(line);
    if (parsed_line.tag != to_string(tag_))
        throw imap_error("Incorrect tag.", "Tag=`" + parsed_line.tag + "`.");
    if (parsed_line.result.value() == tag_result_response_t::NO)
        return false;
    if (parsed_line.result.value() != tag_result_response_t::OK)
        throw imap_error("Creating folder failure.", "Response=`" + parsed_line.response + "`.");
    return true;

}


bool imap::create_folder(const list<string>& folder_name)
{
    string delim = folder_delimiter();
    string folder_str = folder_tree_to_string(folder_name, delim);
    return create_folder(folder_str);
}


auto imap::list_folders(const string& folder_name) -> mailbox_folder_t
{
    string delim = folder_delimiter();
    dlg_->send(format("LIST " + QUOTED_STRING_SEPARATOR + QUOTED_STRING_SEPARATOR + TOKEN_SEPARATOR_STR + to_astring(folder_name + "*")));
    mailbox_folder_t mailboxes;

    bool has_more = true;
    try
    {
        while (has_more)
        {
            string line = dlg_->receive();
            tag_result_response_t parsed_line = parse_tag_result(line);
            parse_response(parsed_line.response);
            if (parsed_line.tag == UNTAGGED_RESPONSE)
            {
                auto token = mandatory_part_.front();
                mandatory_part_.pop_front();
                if (!iequals(token->atom, "LIST"))
                    throw imap_error("Expecting the list atom.", "Atom=`" + token->atom + "`.");

                if (mandatory_part_.size() < 2)
                    throw imap_error("Listing folders failure.", "");

                shared_ptr<response_token_t> attr_tokens;
                shared_ptr<response_token_t> mailbox_token;
                for (const auto& tok : mandatory_part_)
                {
                    if (!attr_tokens && tok->token_type == response_token_t::token_type_t::LIST)
                        attr_tokens = tok;
                    if (tok->token_type == response_token_t::token_type_t::ATOM ||
                        tok->token_type == response_token_t::token_type_t::LITERAL)
                        mailbox_token = tok;
                }

                if (!mailbox_token)
                    throw imap_error("Parsing failure.", "Line=`" + line + "`.");

                string folder_full_name = mailbox_token->token_type == response_token_t::token_type_t::ATOM
                                              ? mailbox_token->atom
                                              : mailbox_token->literal;

                bool selectable = true;
                vector<string> attributes;
                if (attr_tokens)
                {
                    for (const auto& attr_tok : attr_tokens->parenthesized_list)
                    {
                        if (attr_tok->token_type != response_token_t::token_type_t::ATOM)
                            continue;
                        string attr = attr_tok->atom;
                        attributes.push_back(attr);
                        if (iequals(attr, "\\Noselect") || iequals(attr, "\\NonExistent"))
                            selectable = false;
                    }
                }

                if (folder_full_name.empty())
                    continue;

                vector<string> folders_hierarchy;
                if (delim.empty())
                    folders_hierarchy.push_back(folder_full_name);
                else
                    split(folders_hierarchy, folder_full_name, is_any_of(delim));

                map<string, mailbox_folder_t>* mbox = &mailboxes.folders;
                mailbox_folder_t* node = nullptr;
                for (const auto& f : folders_hierarchy)
                {
                    auto fit = find_if(mbox->begin(), mbox->end(), [&f](const std::pair<string, mailbox_folder_t>& mf){ return mf.first == f; });
                    if (fit == mbox->end())
                        fit = mbox->insert(std::make_pair(f, mailbox_folder_t{})).first;
                    node = &(fit->second);
                    mbox = &(node->folders);
                }

                if (node)
                {
                    node->selectable = selectable;
                    node->attributes = attributes;
                }
            }
            else if (parsed_line.tag == to_string(tag_))
            {
                has_more = false;
            }
            reset_response_parser();
        }
    }
    catch (const invalid_argument& exc)
    {
        throw imap_error("Parsing failure.", exc.what());
    }
    catch (const out_of_range& exc)
    {
        throw imap_error("Parsing failure.", exc.what());
    }

    return mailboxes;
}


auto imap::list_folders(const list<string>& folder_name) -> mailbox_folder_t
{
    string delim = folder_delimiter();
    string folder_name_s = folder_tree_to_string(folder_name, delim);
    return list_folders(folder_name_s);
}

auto imap::list_special_use(bool only_special) -> special_use_map_t
{
    // Ensure delimiter is known so that later callers can split names if they wish.
    (void)folder_delimiter();

    special_use_map_t result;

    // Use cached server capabilities to decide which commands to issue.
    const auto &caps = capabilities();
    auto has_cap = [&](const string &needle) -> bool {
        for (const auto &c : caps)
            if (iequals(c, needle))
                return true;
        return false;
    };

    auto parse_and_collect = [&](const string& command, const vector<string>& accept_atoms) -> bool
    {
        // Returns true if the command completed with tagged OK. Returns false on tagged NO/BAD.
        // Never throws; best effort parsing.
        try
        {
            dlg_->send(format(command));
        }
        catch (...)
        {
            return false;
        }

        bool has_more = true;
        while (has_more)
        {
            string line;
            try
            {
                line = dlg_->receive();
                auto parsed_line = parse_tag_result(line);

                if (parsed_line.tag == UNTAGGED_RESPONSE)
                {
                    try
                    {
                        reset_response_parser();
                        parse_response(parsed_line.response);
                        if (mandatory_part_.empty() || mandatory_part_.front()->token_type != response_token_t::token_type_t::ATOM)
                            continue;

                        auto head = mandatory_part_.front();
                        mandatory_part_.pop_front();
                        bool atom_ok = false;
                        for (const auto& a : accept_atoms)
                            if (iequals(head->atom, a)) { atom_ok = true; break; }
                        if (!atom_ok)
                            continue;

                        // Locate attribute list (first LIST token), delimiter (ignored), and mailbox name (last ATOM/LITERAL)
                        shared_ptr<response_token_t> attr_list_tok;
                        for (auto& tok : mandatory_part_)
                            if (tok->token_type == response_token_t::token_type_t::LIST) { attr_list_tok = tok; break; }

                        // Find name token scanning from the end
                        string mailbox_name;
                        for (auto it = mandatory_part_.rbegin(); it != mandatory_part_.rend(); ++it)
                        {
                            if ((*it)->token_type == response_token_t::token_type_t::ATOM)
                            {
                                mailbox_name = (*it)->atom;
                                break;
                            }
                            else if ((*it)->token_type == response_token_t::token_type_t::LITERAL)
                            {
                                mailbox_name = (*it)->literal;
                                break;
                            }
                        }
                        if (mailbox_name.empty())
                            continue;

                        vector<string> special_attrs;
                        if (attr_list_tok)
                        {
                            for (const auto& a : attr_list_tok->parenthesized_list)
                            {
                                if (a->token_type == response_token_t::token_type_t::ATOM)
                                {
                                    const string& attr = a->atom;
                                    if (!attr.empty() && attr[0] == '\\')
                                    {
                                        if (iequals(attr, "\\All") || iequals(attr, "\\Archive") || iequals(attr, "\\Drafts") ||
                                            iequals(attr, "\\Flagged") || iequals(attr, "\\Junk") || iequals(attr, "\\Sent") ||
                                            iequals(attr, "\\Trash") || iequals(attr, "\\Important"))
                                        {
                                            special_attrs.push_back(attr);
                                        }
                                    }
                                }
                            }
                        }

                        if (!special_attrs.empty() || !only_special)
                            result[mailbox_name] = move(special_attrs);
                    }
                    catch (...)
                    {
                        // Best effort: ignore parsing problems on this line.
                        reset_response_parser();
                        continue;
                    }
                }
                else if (parsed_line.tag == to_string(tag_))
                {
                    // Completion of the command. If not OK, signal refusal.
                    bool ok = parsed_line.result.has_value() && parsed_line.result.value() == tag_result_response_t::OK;
                    reset_response_parser();
                    return ok;
                }
                // Ignore other tags
            }
            catch (...)
            {
                // Can't parse this line or receive failed; skip and try next
                continue;
            }
        }
        return true;
    };

    // Try preferred: LIST RETURN (SPECIAL-USE) if server advertises SPECIAL-USE
    bool ok = false;
    if (has_cap("SPECIAL-USE"))
        ok = parse_and_collect("LIST \"\" \"*\" RETURN (SPECIAL-USE)", {"LIST"});

    // If SPECIAL-USE failed or empty, try XLIST only if server advertises XLIST
    if ((!ok || result.empty()) && has_cap("XLIST"))
        (void)parse_and_collect("XLIST \"\" \"*\"", {"XLIST", "LIST"});

    // When only_special=true, avoid issuing a plain LIST fallback (which returns no special-use attrs)
    // to prevent duplicate full LIST calls in higher-level functions.
    if (!only_special && result.empty())
        (void)parse_and_collect("LIST \"\" \"*\"", {"LIST"});

    return result;
}

const std::vector<std::string>& imap::capabilities()
{
    if (capabilities_cached_)
        return capabilities_cache_;

    capabilities_cache_.clear();
    try
    {
        dlg_->send(format("CAPABILITY"));
        bool has_more = true;
        while (has_more)
        {
            string line = dlg_->receive();
            auto parsed_line = parse_tag_result(line);
            if (parsed_line.tag == UNTAGGED_RESPONSE)
            {
                try
                {
                    reset_response_parser();
                    parse_response(parsed_line.response);
                    // Expect: * CAPABILITY <tokens...>
                    if (!mandatory_part_.empty() && mandatory_part_.front()->token_type == response_token_t::token_type_t::ATOM &&
                        iequals(mandatory_part_.front()->atom, "CAPABILITY"))
                    {
                        mandatory_part_.pop_front();
                        for (const auto &tok : mandatory_part_)
                            if (tok->token_type == response_token_t::token_type_t::ATOM)
                                capabilities_cache_.push_back(tok->atom);
                    }
                }
                catch (...)
                {
                    reset_response_parser();
                }
            }
            else if (parsed_line.tag == to_string(tag_))
            {
                has_more = false;
            }
        }
        reset_response_parser();
    }
    catch (...)
    {
        reset_response_parser();
    }

    capabilities_cached_ = true;
    return capabilities_cache_;
}

void imap::enable(const std::vector<std::string>& extensions)
{
    // Build ENABLE command with space-separated extension tokens.
    std::string cmd = "ENABLE";
    if (!extensions.empty())
    {
        cmd += TOKEN_SEPARATOR_STR;
        cmd += boost::algorithm::join(extensions, TOKEN_SEPARATOR_STR);
    }

    dlg_->send(format(cmd));

    bool has_more = true;
    try
    {
        while (has_more)
        {
            reset_response_parser();
            std::string line = dlg_->receive();
            tag_result_response_t parsed_line = parse_tag_result(line);

            if (parsed_line.tag == UNTAGGED_RESPONSE)
            {
                // Best-effort: parse and ignore ENABLED payload if present.
                try
                {
                    parse_response(parsed_line.response);
                    // Expect optional: * ENABLED <tokens...>
                    // No state changes are required here; ignore content.
                }
                catch (...)
                {
                    // Ignore parse failures on unsolicited lines.
                    reset_response_parser();
                    continue;
                }
            }
            else if (parsed_line.tag == to_string(tag_))
            {
                if (!parsed_line.result.has_value() || parsed_line.result.value() != tag_result_response_t::OK)
                    throw imap_error("ENABLE failure.", "Response=`" + parsed_line.response + "`.");
                has_more = false;
            }
            else
            {
                throw imap_error("Incorrect tag parsed.", "Tag=`" + parsed_line.tag + "`.");
            }
        }
    }
    catch (const std::invalid_argument& exc)
    {
        throw imap_error("Parsing failure.", exc.what());
    }
    catch (const std::out_of_range& exc)
    {
        throw imap_error("Parsing failure.", exc.what());
    }

    reset_response_parser();
}

auto imap::list_special_use_by_attr() -> special_use_by_attr_map_t
{
    // Return cached mapping if already computed for this session.
    if (special_use_by_attr_cached_)
        return special_use_by_attr_cache_;

    // Use the best-effort collector and invert into attr->mailbox map.
    // We want only special-use mailboxes, so filter client-side.
    auto per_mailbox = list_special_use(true);

    auto normalize = [](const string& attr) -> string
    {
        // Canonicalize a few common synonyms from XLIST into SPECIAL-USE names.
        if (iequals(attr, "\\AllMail") || iequals(attr, "\\All")) return "\\All";
        if (iequals(attr, "\\Junk") || iequals(attr, "\\Spam")) return "\\Junk";
        if (iequals(attr, "\\Sent")) return "\\Sent";
        if (iequals(attr, "\\Trash")) return "\\Trash";
        if (iequals(attr, "\\Drafts")) return "\\Drafts";
        if (iequals(attr, "\\Flagged")) return "\\Flagged";
        if (iequals(attr, "\\Archive")) return "\\Archive";
        if (iequals(attr, "\\Important")) return "\\Important";
        return attr; // pass-through unknowns
    };

    special_use_by_attr_cache_.clear();
    for (const auto& kv : per_mailbox)
    {
        const auto& mailbox = kv.first;
        const auto& attrs = kv.second;
        for (const auto& a : attrs)
        {
            string canon = normalize(a);
            if (!canon.empty() && special_use_by_attr_cache_.find(canon) == special_use_by_attr_cache_.end())
                special_use_by_attr_cache_.emplace(canon, mailbox);
        }
    }
    special_use_by_attr_cached_ = true;
    return special_use_by_attr_cache_;
}

auto imap::list_folders_interest() -> folders_interest_list_t
{
    folders_interest_list_t out;

    // 1) Collect special-use mapping (best effort)
    auto special = list_special_use_by_attr();

    // Helper to test if a name matches a blacklist token (case-insensitive, substring match)
    auto icontains = [](const string& hay, const string& needle) -> bool
    {
        if (needle.empty()) return false;
        auto h = hay; auto n = needle;
        boost::algorithm::to_lower(h);
        boost::algorithm::to_lower(n);
        return h.find(n) != string::npos;
    };

    // 2) List all folders from root using existing helper
    mailbox_folder_t tree = list_folders("");

    // Flatten the tree to full paths
    string delim = folder_delimiter();
    vector<string> all_folders;
    auto walk = [&](const auto& self, const mailbox_folder_t& node, const string& prefix) -> void
    {
        for (const auto& kv : node.folders)
        {
            string name = prefix.empty() ? kv.first : (prefix + delim + kv.first);
            if (kv.second.selectable)
                all_folders.push_back(name);
            self(self, kv.second, name);
        }
    };
    walk(walk, tree, "");

    // 3) Build inverse map mailbox->special-uses from special (attr->mailbox)
    map<string, vector<string>> mailbox_attrs;
    for (const auto& kv : special)
        mailbox_attrs[kv.second].push_back(kv.first);

    // 4) Heuristics per folder
    for (const auto& mbox : all_folders)
    {
        bool interesting = false;

        // Always interesting: INBOX (case-insensitive exact)
        if (iequals(mbox, "INBOX"))
        {
            interesting = true;
        }
        else
        {
            // If it has SPECIAL-USE
            auto it = mailbox_attrs.find(mbox);
            if (it != mailbox_attrs.end())
            {
                // Positive: \Sent, \Archive
                for (const auto& a : it->second)
                    if (iequals(a, "\\Sent") || iequals(a, "\\Archive"))
                        interesting = true;

                // Negative overrides: \Trash, \Junk, \Drafts, \All, \Important, \Flagged
                for (const auto& a : it->second)
                    if (iequals(a, "\\Trash") || iequals(a, "\\Junk") || iequals(a, "\\Drafts") ||
                        iequals(a, "\\All") || iequals(a, "\\Important") || iequals(a, "\\Flagged"))
                        interesting = false;
            }

            // If no explicit special-use flags or still undecided, use small name blacklist
            if (!interesting)
            {
                static const char* blacklist[] = {
                    "Sync Issues", "Conflicts", "Local Failures", "Server Failures",
                    "Conversation History", "Clutter", "RSS Feeds", "RSS Subscriptions",
                    "Suggested Contacts", "Outbox", "Calendar", "Contacts", "Tasks",
                    "Notes", "Journal", "All Mail", "Important", "Starred", "Spam",
                    "Trash", "Junk", "Drafts"
                };
                bool black = false;
                for (auto term : blacklist)
                    if (icontains(mbox, term)) { black = true; break; }
                if (!black)
                {
                    // Default: most user-created folders are interesting, but avoid marking vendor roots like [Gmail]
                    if (!icontains(mbox, "[Gmail]"))
                        interesting = true;
                }
            }
        }

        out.emplace_back(mbox, interesting);
    }

    return out;
}

auto imap::list_folders_high_level() -> high_level_folders_list_t
{
    high_level_folders_list_t out;

    list_special_use_by_attr(); // ensure it ran once
    map<string, vector<string>> special_by_mailbox;
    for (const auto& kv : special_use_by_attr_cache_)
        special_by_mailbox[kv.second].push_back(kv.first);

    mailbox_folder_t tree = list_folders("");
    string delim = folder_delimiter();

    auto join_path = [&](const string& prefix, const string& leaf) -> string
    {
        if (prefix.empty())
            return leaf;
        if (delim.empty())
            return prefix + leaf;
        return prefix + delim + leaf;
    };

    auto has_attr = [](const vector<string>& attrs, const string& target) -> bool
    {
        for (const auto& attr : attrs)
            if (iequals(attr, target))
                return true;
        return false;
    };

    auto attr_to_type = [](const string& attr) -> std::optional<mailbox_folder_type_t>
    {
        if (iequals(attr, "\\Inbox"))
            return mailbox_folder_type_t::INBOX;
        if (iequals(attr, "\\Sent"))
            return mailbox_folder_type_t::SENT;
        if (iequals(attr, "\\Drafts"))
            return mailbox_folder_type_t::DRAFTS;
        if (iequals(attr, "\\Trash"))
            return mailbox_folder_type_t::TRASH;
        if (iequals(attr, "\\Junk") || iequals(attr, "\\Spam"))
            return mailbox_folder_type_t::JUNK;
        if (iequals(attr, "\\Archive"))
            return mailbox_folder_type_t::ARCHIVE;
        if (iequals(attr, "\\Flagged"))
            return mailbox_folder_type_t::FLAGGED;
        if (iequals(attr, "\\All") || iequals(attr, "\\AllMail"))
            return mailbox_folder_type_t::ALL;
        if (iequals(attr, "\\Important"))
            return mailbox_folder_type_t::IMPORTANT;
        return std::nullopt;
    };

    auto determine_type = [&](const vector<string>& attrs, const string& path) -> mailbox_folder_type_t
    {
        for (const auto& attr : attrs)
        {
            auto mapped = attr_to_type(attr);
            if (mapped.has_value())
                return mapped.value();
        }
        if (iequals(path, "INBOX"))
            return mailbox_folder_type_t::INBOX;
        return mailbox_folder_type_t::REGULAR;
    };

    auto walk = [&](const auto& self, const mailbox_folder_t& node, const string& prefix) -> void
    {
        for (const auto& kv : node.folders)
        {
            const auto& folder = kv.second;
            string path = join_path(prefix, kv.first);

            vector<string> attrs = folder.attributes;
            auto special_it = special_by_mailbox.find(path);
            if (special_it != special_by_mailbox.end())
                attrs.insert(attrs.end(), special_it->second.begin(), special_it->second.end());

            if (folder.selectable)
            {
                auto type = determine_type(attrs, path);
                bool is_virtual = (type == mailbox_folder_type_t::ALL ||
                                   type == mailbox_folder_type_t::FLAGGED ||
                                   type == mailbox_folder_type_t::IMPORTANT);
                bool can_add = folder.selectable && !is_virtual && !has_attr(attrs, "\\Noinferiors");
                bool can_delete = folder.selectable && type == mailbox_folder_type_t::REGULAR;
                bool is_custom = (type == mailbox_folder_type_t::REGULAR) && !iequals(path, "INBOX");

                mailbox_high_level_t entry;
                entry.path = path;
                entry.name = kv.first;
                entry.type = type;
                entry.is_virtual = is_virtual;
                entry.can_add = can_add;
                entry.is_custom = is_custom;
                entry.can_delete = can_delete;

                out.push_back(std::move(entry));
            }

            self(self, folder, path);
        }
    };

    walk(walk, tree, "");
    return out;
}


bool imap::delete_folder(const string& folder_name)
{
    dlg_->send(format("DELETE " + to_astring(folder_name)));

    string line = dlg_->receive();
    tag_result_response_t parsed_line = parse_tag_result(line);
    if (parsed_line.tag != to_string(tag_))
        throw imap_error("Incorrect tag.", "Tag=`" + parsed_line.tag + "`.");
    if (parsed_line.result.value() == tag_result_response_t::NO)
        return false;
    if (parsed_line.result.value() != tag_result_response_t::OK)
        throw imap_error("Deleting folder failure.", "Line=`" + line + "`.");
    return true;
}


bool imap::delete_folder(const list<string>& folder_name)
{
    string delim = folder_delimiter();
    string folder_name_s = folder_tree_to_string(folder_name, delim);
    return delete_folder(folder_name_s);
}


bool imap::rename_folder(const string& old_name, const string& new_name)
{
    dlg_->send(format("RENAME " + to_astring(old_name) + TOKEN_SEPARATOR_STR + to_astring(new_name)));

    string line = dlg_->receive();
    tag_result_response_t parsed_line = parse_tag_result(line);
    if (parsed_line.tag != to_string(tag_))
        throw imap_error("Incorrect tag.", "Tag=`" + parsed_line.tag + "`.");
    if (parsed_line.result.value() == tag_result_response_t::NO)
        return false;
    if (parsed_line.result.value() != tag_result_response_t::OK)
        throw imap_error("Renaming folder failure.", "Line=`" + line + "`.");
    return true;
}


bool imap::rename_folder(const list<string>& old_name, const list<string>& new_name)
{
    string delim = folder_delimiter();
    string old_name_s = folder_tree_to_string(old_name, delim);
    string new_name_s = folder_tree_to_string(new_name, delim);
    return rename_folder(old_name_s, new_name_s);
}


string imap::connect()
{
    // read greetings message
    string line = dlg_->receive();
    tag_result_response_t parsed_line = parse_tag_result(line);

    if (parsed_line.tag != UNTAGGED_RESPONSE)
        throw imap_error("Incorrect tag.", "Tag=`" + parsed_line.tag + "`.");
    if (!parsed_line.result.has_value() || parsed_line.result.value() != tag_result_response_t::OK)
        throw imap_error("Connection to server failure.", "Line=`" + line + "`.");
    return parsed_line.response;
}


void imap::switch_tls()
{
    dlg_->send(format("STARTTLS"));
    string line = dlg_->receive();
    tag_result_response_t parsed_line = parse_tag_result(line);
    if (parsed_line.tag == UNTAGGED_RESPONSE)
        throw imap_error("Bad server response.", "");
    if (parsed_line.result.value() != tag_result_response_t::OK)
        throw imap_error("Start TLS refused by server.", "");

    dlg_ = dialog_ssl::to_ssl(dlg_, *ssl_options_);
}


void imap::auth_login(const string& username, const string& password)
{
    auto user_esc = to_astring(username);
    auto pass_esc = to_astring(password);
    auto cmd = format("LOGIN " + user_esc + TOKEN_SEPARATOR_STR + pass_esc);
    dlg_->send(cmd);

    bool has_more = true;
    while (has_more)
    {
        string line = dlg_->receive();
        tag_result_response_t parsed_line = parse_tag_result(line);

        if (parsed_line.tag == UNTAGGED_RESPONSE)
            continue;
        if (parsed_line.tag != to_string(tag_))
            throw imap_error("Incorrect tag.", "Tag=`" + parsed_line.tag + "`.");
        if (parsed_line.result.value() != tag_result_response_t::OK)
            throw imap_error("Authentication failure.", "line=`" + line + "`.");

        has_more = false;
    }
}

void imap::auth_login_xoauth2(const std::string &username, const std::string &access_token)
{
    // XOAUTH2 SASL initial client response as per RFC 7628 (and Google docs):
    // base64("user=" user "\x01auth=Bearer " access_token "\x01\x01")
    std::string sasl = "user=" + username + "\x01" + "auth=Bearer " + access_token + "\x01\x01";
    std::string sasl_b64 = b64_encode(sasl);
    // IMAP requires a tagged command: AUTHENTICATE XOAUTH2 <base64>
    // (Unlike SMTP which may negotiate with numeric codes.)
    dlg_->send(format("AUTHENTICATE XOAUTH2 " + sasl_b64));

    // We expect one of:
    // 1. Immediate tagged OK => success.
    // 2. A continuation '+' with a base64 JSON error, then we must send an empty line to abort, then a tagged NO/BAD.
    // 3. Direct tagged NO/BAD failure.
    string error_b64;          
    string response;          

    bool done = false;
    while (!done)
    {
        string line = dlg_->receive();
        tag_result_response_t parsed_line = parse_tag_result(line);
        if (parsed_line.tag == CONTINUE_RESPONSE)
        {
            // Continuation with base64 encoded JSON error.
            error_b64 = parsed_line.response;
            // Per XOAUTH2 failure flow, send empty line to abort.
            try
            {
                dlg_->send("");
            }
            catch (...)
            {
                // ignore send failure here; we'll proceed to receive final tagged result
            }
            continue; // read final tagged response
        }
        else if (parsed_line.tag == UNTAGGED_RESPONSE)
        {
            // Ignore unrelated untagged responses during auth.
            continue;
        }
        else if (parsed_line.tag == to_string(tag_))
        {
            // Tagged completion.
            if (parsed_line.result.has_value() && parsed_line.result.value() == tag_result_response_t::OK)
            {
                return; // Success
            }
            // Failure path: collect final response text.
            if (parsed_line.result.has_value())
            {
                response = line;
            }            
            done = true;
        }
        else
        {
            throw imap_error("Incorrect tag.", "Tag=`" + parsed_line.tag + "`.");
        }
    }

    std::string details = std::string{"JSON={"}
        + "\"error\": \"" + error_b64 + "\"," 
        + "\"response\": \"" + response + "\"" 
        + "}";

    throw imap_error("Authentication rejection.", details);
}

void imap::search(const string& conditions, list<unsigned long>& results, bool want_uids)
{
    string cmd;
    if (want_uids)
        cmd.append("UID ");
    cmd.append("SEARCH " + conditions);
    dlg_->send(format(cmd));

    bool has_more = true;
    try
    {
        while (has_more)
        {
            reset_response_parser();
            string line = dlg_->receive();
            tag_result_response_t parsed_line = parse_tag_result(line);
            if (parsed_line.tag == UNTAGGED_RESPONSE)
            {
                parse_response(parsed_line.response);

                auto search_token = mandatory_part_.front();
                // ignore other responses, although not sure whether this is by the rfc or not
                if (search_token->token_type == response_token_t::token_type_t::ATOM && !iequals(search_token->atom, "SEARCH"))
                    continue;
                mandatory_part_.pop_front();

                for (auto it = mandatory_part_.begin(); it != mandatory_part_.end(); it++)
                    if ((*it)->token_type == response_token_t::token_type_t::ATOM)
                    {
                        const unsigned long idx = stoul((*it)->atom);
                        if (idx == 0)
                            throw imap_error("Incorrect message id.", "Line=`" + line + "`.");
                        results.push_back(idx);
                    }
            }
            else if (parsed_line.tag == to_string(tag_))
            {
                if (parsed_line.result.value() != tag_result_response_t::OK)
                    throw imap_error("Search mailbox failure.", "Line=`" + line + "`.");

                has_more = false;
            }
            else
            {
                throw imap_error("Incorrect tag parsed.", "Tag=`" + parsed_line.tag + "`.");
            }
        }
    }
    catch (const invalid_argument& exc)
    {
        throw imap_error("Parsing failure.", exc.what());
    }
    catch (const out_of_range& exc)
    {
        throw imap_error("Parsing failure.", exc.what());
    }
    reset_response_parser();
}


void imap::start_tls(bool is_tls)
{
    is_start_tls_ = is_tls;
}


void imap::ssl_options(const std::optional<dialog_ssl::ssl_options_t> options)
{
    ssl_options_ = options;
}


string imap::folder_delimiter()
{
    try
    {
        if (folder_delimiter_.empty())
        {
            dlg_->send(format("LIST " + QUOTED_STRING_SEPARATOR + QUOTED_STRING_SEPARATOR + TOKEN_SEPARATOR_STR + QUOTED_STRING_SEPARATOR + QUOTED_STRING_SEPARATOR));
            bool has_more = true;
            while (has_more)
            {
                string line = dlg_->receive();
                tag_result_response_t parsed_line = parse_tag_result(line);
                if (parsed_line.tag == UNTAGGED_RESPONSE && folder_delimiter_.empty())
                {
                    parse_response(parsed_line.response);
                    if (!iequals(mandatory_part_.front()->atom, "LIST"))
                        throw imap_error("Incorrect atom parsed.", "Line=`" + line + "`.");
                    mandatory_part_.pop_front();

                    if (mandatory_part_.size() < 3)
                        throw imap_error("Determining folder delimiter failure.", "");
                    auto it = mandatory_part_.begin();
                    if ((*(++it))->token_type != response_token_t::token_type_t::ATOM)
                        throw imap_error("Incorrect atom parsed.", "");
                    folder_delimiter_ = trim_copy_if((*it)->atom, [](char c ){ return c == QUOTED_STRING_SEPARATOR_CHAR; });
                    reset_response_parser();
                }
                else if (parsed_line.tag == to_string(tag_))
                {
                    if (parsed_line.result.value() != tag_result_response_t::OK)
                        throw imap_error("Determining folder delimiter failure.", "Line=`" + line + "`.");

                    has_more = false;
                }
            }
        }
        return folder_delimiter_;
    }
    catch (const invalid_argument& exc)
    {
        throw imap_error("Parsing failure.", exc.what());
    }
    catch (const out_of_range& exc)
    {
        throw imap_error("Parsing failure.", exc.what());
    }
}

imap::idle_result_t imap::idle(const std::function<bool(const idle_event_t &)> &on_event,
                               std::chrono::milliseconds timeout,
                               const std::atomic_bool &cancel)
{
    
    debug_bugfix("imap::idle IN");
    
    // Independent, long-lived IDLE loop per RFC 2177.
    // Contract:
    // - Do not rely on dialog timeout to end the loop; instead, use a deadline and
    //   swallow dialog "timed out" errors to keep listening until deadline/cancel.
    // - Forward networking exceptions (non-timeout) to caller.
    // - Best-effort parse of untagged server responses; deliver events to callback.
    // - React to "* BYE" by returning idle_result_t::BYE.

    auto is_timeout_error = [](const dialog_error &ex) -> bool {
        std::string msg = ex.what();
        return msg.find("timed out") != std::string::npos;
    };

    const auto deadline = steady_clock::now() + timeout;

    // Ensure we can periodically wake to check cancel/deadline even if caller set dialog timeout to
    // 0. Temporarily set a conservative poll timeout if needed, then restore.
    const auto orig_net_to = dlg_->timeout();
    if (orig_net_to.count() == 0)
        dlg_->set_timeout(std::chrono::seconds(10));

    struct restore_timeout_t {
        std::shared_ptr<dialog> d; 
        milliseconds orig;
        ~restore_timeout_t(){ if (d) d->set_timeout(orig); }
    } _restore{dlg_, orig_net_to};

    auto deliver_event = [&](idle_event_t ev) -> bool {
        try {
            if (on_event)
                return on_event(ev);
            return true;
        } catch (...) {
            // Do not allow callback exceptions to unwind internals; treat as stop.
            return false;
        }
    };

    auto parse_and_emit = [&](const std::string &line, const tag_result_response_t &parsed_line) -> std::optional<idle_result_t>
    {
        // Return BYE if server sent BYE. Otherwise emit an event if recognized, or OTHER.
        try
        {
            reset_response_parser();
            parse_response(parsed_line.response);

            // Detect BYE: "* BYE ..." (first mandatory token ATOM == BYE)
            if (!mandatory_part_.empty() && mandatory_part_.front()->token_type == response_token_t::token_type_t::ATOM)
            {
                if (iequals(mandatory_part_.front()->atom, "BYE"))
                {
                    is_idling_.store(false, std::memory_order_release);
                    return idle_result_t::BYE;
                }
            }

            idle_event_t ev;
            ev.type = idle_event_t::type_t::OTHER;
            ev.number = 0;
            ev.raw = parsed_line.response;

            // Common untagged forms: "* <n> EXISTS", "* <n> EXPUNGE", "* <n> RECENT",
            // and "* <n> FETCH (FLAGS (...))".
            if (mandatory_part_.size() >= 2 &&
                mandatory_part_.front()->token_type == response_token_t::token_type_t::ATOM &&
                std::next(mandatory_part_.begin())->get()->token_type == response_token_t::token_type_t::ATOM)
            {
                auto it = mandatory_part_.begin();
                auto first = *it; ++it;
                auto second = *it;
                try { ev.number = stoul(first->atom); } catch (...) { ev.number = 0; }
                if (iequals(second->atom, "EXISTS"))
                    ev.type = idle_event_t::type_t::EXISTS;
                else if (iequals(second->atom, "RECENT"))
                    ev.type = idle_event_t::type_t::RECENT;
                else if (iequals(second->atom, "EXPUNGE"))
                    ev.type = idle_event_t::type_t::EXPUNGE;
                else if (iequals(second->atom, "FETCH"))
                {
                    // Attempt to detect FLAGS in the list to mark as metadata change.
                    for (auto &tok : mandatory_part_)
                    {
                        if (tok->token_type == response_token_t::token_type_t::LIST)
                        {
                            for (auto &sub : tok->parenthesized_list)
                            {
                                if (sub->token_type == response_token_t::token_type_t::ATOM && iequals(sub->atom, "FLAGS"))
                                {
                                    ev.type = idle_event_t::type_t::FETCH_FLAGS;
                                    break;
                                }
                            }
                        }
                    }
                    if (ev.type == idle_event_t::type_t::OTHER)
                        ev.type = idle_event_t::type_t::FETCH_FLAGS; // best-effort default for FETCH
                }
            }

            // Emit to client; if client asks to stop, end IDLE gracefully.
            bool cont = deliver_event(ev);
            if (!cont)
                return idle_result_t::EXPIRED; // use EXPIRED to signal normal end
        }
        catch (const imap_error &)
        {
            // Best-effort: fall back to OTHER with raw payload
            idle_event_t ev;
            ev.type = idle_event_t::type_t::OTHER;
            ev.number = 0;
            ev.raw = parsed_line.response.empty() ? line : parsed_line.response;
            bool cont = deliver_event(ev);
            if (!cont)
                return idle_result_t::EXPIRED;
        }
        return std::nullopt;
    };

    auto wait_for_continuation = [&]() -> std::optional<idle_result_t>
    {
        // Wait until we see "+" continuation or we hit deadline/cancel/BYE.
        while (!cancel.load(std::memory_order_acquire))
        {
            if (steady_clock::now() >= deadline)
                return idle_result_t::EXPIRED;
            try
            {
                std::string line = dlg_->receive();
                auto pl = parse_tag_result(line);
                if (pl.tag == CONTINUE_RESPONSE)
                    return std::nullopt; // ready to idle
                if (pl.tag == UNTAGGED_RESPONSE)
                {
                    auto res = parse_and_emit(line, pl);
                    if (res.has_value())
                        return res; // BYE or client stop
                }
                else if (pl.tag == to_string(tag_))
                {
                    // If server responds with tagged NO/BAD here, IDLE was rejected (e.g., no mailbox selected).
                    if (pl.result.has_value() && pl.result.value() != tag_result_response_t::OK)
                        throw imap_error("IDLE command rejected.", "Response=`" + pl.response + "`.");
                    // Otherwise, treat as benign premature completion; re-issue if time allows.
                    return std::nullopt;
                }
                // Ignore unrelated lines
            }
            catch (const dialog_planned_disconnect&)
            {
                // Planned disconnect before we actually entered idling state.
                // No DONE required here; propagate to caller so higher-level code is aware.
                throw;
            }
            catch (const dialog_error &ex)
            {
                if (is_timeout_error(ex))
                    continue; // keep waiting until our deadline
                throw; // forward all other networking errors
            }
        }
        return idle_result_t::EXPIRED;
    };

    auto start_idle = [&]() -> std::optional<idle_result_t>
    {
        // Issue IDLE and await continuation.
        try
        {
            dlg_->send(format("IDLE"));
        }
        catch (const dialog_error &ex)
        {
            if (is_timeout_error(ex))
            {
                // Retry until deadline
                return std::nullopt;
            }
            throw;
        }
        auto cont_res = wait_for_continuation();
        if (cont_res.has_value())
            return cont_res; // BYE or EXPIRED
        is_idling_.store(true, std::memory_order_release);
        return std::nullopt;
    };

    // Begin IDLE session (and re-IDLE as necessary if server ends it prematurely).
    while (steady_clock::now() < deadline && !cancel.load(std::memory_order_acquire))
    {
        auto r = start_idle();
        if (r.has_value())
            return r.value();

        // Main receive loop while idling
        while (steady_clock::now() < deadline && !cancel.load(std::memory_order_acquire))
        {
            try
            {
                std::string line = dlg_->receive();
                auto pl = parse_tag_result(line);
                if (pl.tag == UNTAGGED_RESPONSE)
                {
                    auto res = parse_and_emit(line, pl);
                    if (res.has_value())
                    {
                        // BYE or client requested stop; exit IDLE.
                        is_idling_.store(false, std::memory_order_release);

                        // If this is a normal stop (not BYE), send DONE and drain until either
                        // the tagged completion arrives or a single receive timeout occurs.
                        if (res.value() != idle_result_t::BYE)
                        {
                            try { dlg_->send("DONE"); } catch (const dialog_error &dex) { if (!is_timeout_error(dex)) throw; }
                            // Drain best-effort until we see our tag or receive times out once.
                            while (true)
                            {
                                try
                                {
                                    auto l2 = dlg_->receive();
                                    auto pl2 = parse_tag_result(l2);
                                    if (pl2.tag == to_string(tag_)) break;
                                    if (pl2.tag == UNTAGGED_RESPONSE) { (void)parse_and_emit(l2, pl2); }
                                    // Ignore unrelated tags here.
                                }
                                catch (const dialog_error &dex)
                                {
                                    if (is_timeout_error(dex))
                                        break; // one timeout -> assume drained sufficiently
                                    throw;
                                }
                            }
                        }
                        return res.value();
                    }
                }
                else if (pl.tag == to_string(tag_))
                {
                    // Server ended IDLE. If completion is NO/BAD, propagate so the client can react.
                    if (pl.result.has_value() && pl.result.value() != tag_result_response_t::OK)
                        throw imap_error("IDLE terminated by server.", "Response=`" + pl.response + "`.");
                    is_idling_.store(false, std::memory_order_release);
                    break; // break inner loop to re-idle if time remains
                }
                else if (pl.tag == CONTINUE_RESPONSE)
                {
                    // Already idling; ignore spurious continuation
                }
            }
            catch (const dialog_planned_disconnect&)
            {
                // Planned disconnect during active idling: exit loops and let the common
                // cleanup path below send DONE using the existing, fully featured sequence.
                break; // break inner loop
            }
            catch (const dialog_error &ex)
            {
                if (is_timeout_error(ex))
                {
                    // Periodic inactivity; keep waiting until deadline
                    continue;
                }
                throw; // forward other networking errors
            }
        }

        // If we left the inner loop because of time/cancel, exit; otherwise re-IDLE.
        if (steady_clock::now() >= deadline || cancel.load(std::memory_order_acquire) || planned_disconnect_.load(std::memory_order_acquire))
            break;
    }

    // If still idling, terminate depending on reason: normal expiry vs cancel/disconnect.
    if (is_idling_.exchange(false, std::memory_order_acq_rel))
    {
        // Route planned disconnect through the full DONE sequence when it occurred during active idling.
        const bool cancelled = cancel.load(std::memory_order_acquire) || planned_disconnect_.load(std::memory_order_acquire);
        if (cancelled)
        {
            // Courtesy DONE: use a very short send-timeout and do not wait for a reply.
            auto prev_to = dlg_->timeout();
            dlg_->set_timeout(std::chrono::milliseconds(100));
            try { dlg_->send("DONE"); } catch (...) { /* ignore */ }
            dlg_->set_timeout(prev_to);
        }
        else
        {
            // Normal idle expiry: send DONE and drain until tagged completion or a single timeout.
            try
            {
                dlg_->send("DONE");
            }
            catch (const dialog_error &ex)
            {
                if (!is_timeout_error(ex))
                    throw;
            }
            while (true) // need a loop in case we get unsolicited untagged responses
            {
                try
                {
                    auto line = dlg_->receive();
                    auto pl = parse_tag_result(line);
                    if (pl.tag == to_string(tag_))
                        break;
                    if (pl.tag == UNTAGGED_RESPONSE)
                    {
                        (void)parse_and_emit(line, pl);
                    }
                    // Ignore unrelated tagged lines.
                }
                catch (const dialog_error &ex)
                {
                    if (is_timeout_error(ex))
                    {
                        break; // one timeout -> done draining
                    }
                    throw;
                }
            }
        }
    }

    // If a planned stop initiated this unwind, signal it to the caller as an exception now that
    // the normal DONE sequence has been executed.
    if (planned_disconnect_.load(std::memory_order_acquire))
        throw dialog_planned_disconnect("Planned disconnect.", "IDLE ended by planned disconnect.");

    return idle_result_t::EXPIRED;
}

void imap::disconnect(std::chrono::milliseconds timeout)
{
    debug_bugfix("imap::disconnect IN");
    // If already planning a disconnect, do nothing.
    if (planned_disconnect_.exchange(true, std::memory_order_acq_rel))
        return;
    // Request a graceful planned interrupt; underlying idle loop will catch dialog_planned_disconnect.
    try { dlg_->request_planned_interrupt(); } catch (...) { }
    // Optionally wait a short grace period for idle loop to unwind (non-blocking if not idling).
    auto deadline = std::chrono::steady_clock::now() + timeout;
    while (dlg_->is_in_wait() && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    // If still in wait after grace, perform hard abort.
    if (dlg_->is_in_wait())
        try { dlg_->abort_now(); } catch (...) { }
}

void imap::noop()
{
    // Issue NOOP and process responses until the tagged completion line.
    dlg_->send(format("NOOP"));
    bool has_more = true;
    try
    {
        while (has_more)
        {
            reset_response_parser();
            string line = dlg_->receive();
            tag_result_response_t parsed_line = parse_tag_result(line);
            if (parsed_line.tag == UNTAGGED_RESPONSE)
            {
                // Parse and ignore any untagged updates per RFC 3501 (EXISTS, EXPUNGE, RECENT, FETCH, etc.).
                parse_response(parsed_line.response);
                continue;
            }
            else if (parsed_line.tag == to_string(tag_))
            {
                if (parsed_line.result.has_value() && parsed_line.result.value() == tag_result_response_t::OK)
                {
                    has_more = false;
                    break;
                }
                throw imap_error("NOOP failure.", "Response=`" + parsed_line.response + "`.");
            }
            else
            {
                throw imap_error("Incorrect tag parsed.", "Tag=`" + parsed_line.tag + "`.");
            }
        }
    }
    catch (const invalid_argument& exc)
    {
        throw imap_error("Parsing failure.", exc.what());
    }
    catch (const out_of_range& exc)
    {
        throw imap_error("Parsing failure.", exc.what());
    }
    reset_response_parser();
}

void imap::strict_mode(bool mode) { strict_mode_ = mode; }
void imap::strict_codec_mode(bool mode) { strict_codec_mode_ = mode; }
bool imap::strict_mode() const { return strict_mode_; }
bool imap::strict_codec_mode() const { return strict_codec_mode_; }

void imap::test_simulate_disconnect() { 
    dlg_->simulate_disconnect(); 
}

void imap::test_set_simulated_error(dialog::simulated_error_t err, int count) { 
    dlg_->set_simulated_error(err, count); 
}

auto imap::parse_tag_result(const string& line) const -> tag_result_response_t
{
    string::size_type tag_pos = line.find(TOKEN_SEPARATOR_STR);
    if (tag_pos == string::npos)
        throw imap_error("Parsing failure.", "");
    string tag = line.substr(0, tag_pos);

    string::size_type result_pos = string::npos;
    result_pos = line.find(TOKEN_SEPARATOR_STR, tag_pos + 1);
    string result_s = line.substr(tag_pos + 1, result_pos - tag_pos - 1);
    std::optional<tag_result_response_t::result_t> result = std::nullopt;
    if (iequals(result_s, "OK"))
        result = make_optional(tag_result_response_t::OK);
    if (iequals(result_s, "NO"))
        result = make_optional(tag_result_response_t::NO);
    if (iequals(result_s, "BAD"))
        result = make_optional(tag_result_response_t::BAD);

    string response;
    if (result.has_value())
        response = line.substr(result_pos + 1);
    else
        response = line.substr(tag_pos + 1);
    return tag_result_response_t(tag, result, response);
}


/*
Protocol defines response line as tag (including plus and asterisk chars), result (ok, no, bad) and the response content which consists of optional
and mandatory part. Protocol grammar defines the response as sequence of atoms, string literals and parenthesized list (which itself can contain
atoms, string literal and parenthesized lists). The grammar can be parsed in one pass by counting which token is read: atom, string literal or
parenthesized list:
1. if a square bracket is reached, then an optional part is found, so parse its content as usual
2. if a brace is read, then string literal size is found, so read a number and then literal itself
3. if a parenthesis is found, then a list is being read, so increase the parenthesis counter and proceed
4. for a regular char check the state and determine if an atom or string size/literal is read

Token of the grammar is defined by `response_token_t` and stores one of the three types. Since parenthesized list is recursively defined, it keeps
sequence of tokens. When a character is read, it belongs to the last token of the sequence of tokens at the given parenthesis depth. The last token
of the response expression is found by getting the last token of the token sequence at the given depth (in terms of parenthesis count).
*/
void imap::parse_response(const string& response)
{
    list<shared_ptr<imap::response_token_t>>* token_list;

    if (literal_state_ == string_literal_state_t::READING)
    {
        token_list = optional_part_state_ ? find_last_token_list(optional_part_) : find_last_token_list(mandatory_part_);
        if (token_list->back()->token_type == response_token_t::token_type_t::LITERAL && literal_bytes_read_ > token_list->back()->literal.size())
            throw imap_error("Parser failure.", "");
        unsigned long literal_size = stoul(token_list->back()->literal_size);
        if (literal_bytes_read_ + response.size() < literal_size)
        {
            token_list->back()->literal += response + codec::END_OF_LINE;
            literal_bytes_read_ += response.size() + eols_no_;
            if (literal_bytes_read_ == literal_size)
                literal_state_ = string_literal_state_t::DONE;
            return;
        }
        else
        {
            string::size_type resp_len = response.size();
            token_list->back()->literal += response.substr(0, literal_size - literal_bytes_read_);
            literal_bytes_read_ += literal_size - literal_bytes_read_;
            literal_state_ = string_literal_state_t::DONE;
            parse_response(response.substr(resp_len - (literal_size - literal_bytes_read_) - 1));
            return;
        }
    }

    shared_ptr<response_token_t> cur_token;
    for (auto ch : response)
    {
        switch (ch)
        {
            case OPTIONAL_BEGIN:
            {
                if (atom_state_ == atom_state_t::QUOTED)
                    cur_token->atom +=ch;
                else
                {
                    if (optional_part_state_)
                        throw imap_error("Parser failure.", "");

                    optional_part_state_ = true;
                }
            }
            break;

            case OPTIONAL_END:
            {
                if (atom_state_ == atom_state_t::QUOTED)
                    cur_token->atom +=ch;
                else
                {
                    if (!optional_part_state_)
                        throw imap_error("Parser failure.", "");

                    optional_part_state_ = false;
                    atom_state_ = atom_state_t::NONE;
                }
            }
            break;

            case LIST_BEGIN:
            {
                if (atom_state_ == atom_state_t::QUOTED)
                    cur_token->atom +=ch;
                else
                {
                    cur_token = make_shared<response_token_t>();
                    cur_token->token_type = response_token_t::token_type_t::LIST;
                    token_list = optional_part_state_ ? find_last_token_list(optional_part_) : find_last_token_list(mandatory_part_);
                    token_list->push_back(cur_token);
                    parenthesis_list_counter_++;
                    atom_state_ = atom_state_t::NONE;
                }
            }
            break;

            case LIST_END:
            {
                if (atom_state_ == atom_state_t::QUOTED)
                    cur_token->atom +=ch;
                else
                {
                    if (parenthesis_list_counter_ == 0)
                        throw imap_error("Parser failure.", "");

                    parenthesis_list_counter_--;
                    atom_state_ = atom_state_t::NONE;
                }
            }
            break;

            case STRING_LITERAL_BEGIN:
            {
                if (atom_state_ == atom_state_t::QUOTED)
                    cur_token->atom +=ch;
                else
                {
                    if (literal_state_ == string_literal_state_t::SIZE)
                        throw imap_error("Parser failure.", "");

                    cur_token = make_shared<response_token_t>();
                    cur_token->token_type = response_token_t::token_type_t::LITERAL;
                    token_list = optional_part_state_ ? find_last_token_list(optional_part_) : find_last_token_list(mandatory_part_);
                    token_list->push_back(cur_token);
                    literal_state_ = string_literal_state_t::SIZE;
                    atom_state_ = atom_state_t::NONE;
                }
            }
            break;

            case STRING_LITERAL_END:
            {
                if (atom_state_ == atom_state_t::QUOTED)
                    cur_token->atom +=ch;
                else
                {
                    if (literal_state_ == string_literal_state_t::NONE)
                        throw imap_error("Parser failure.", "");

                    literal_state_ = string_literal_state_t::WAITING;
                }
            }
            break;

            case TOKEN_SEPARATOR_CHAR:
            {
                if (atom_state_ == atom_state_t::QUOTED)
                    cur_token->atom +=ch;
                else
                {
                    if (cur_token != nullptr)
                    {
                        trim(cur_token->atom);
                        atom_state_ = atom_state_t::NONE;
                    }
                }
            }
            break;

            case QUOTED_ATOM:
            {
                if (atom_state_ == atom_state_t::NONE)
                {
                    cur_token = make_shared<response_token_t>();
                    cur_token->token_type = response_token_t::token_type_t::ATOM;
                    token_list = optional_part_state_ ? find_last_token_list(optional_part_) : find_last_token_list(mandatory_part_);
                    token_list->push_back(cur_token);
                    atom_state_ = atom_state_t::QUOTED;
                }
                else if (atom_state_ == atom_state_t::QUOTED)
                {
                    // The backslash and a double quote within an atom is the double quote only.
                    if (token_list->back()->atom.back() != codec::BACKSLASH_CHAR)
                        atom_state_ = atom_state_t::NONE;
                    else
                        token_list->back()->atom.back() = ch;
                }
            }
            break;

            default:
            {
                // Double backslash in an atom is translated to the single backslash.
                if (ch == codec::BACKSLASH_CHAR && atom_state_ == atom_state_t::QUOTED && token_list->back()->atom.back() == codec::BACKSLASH_CHAR)
                    break;

                if (literal_state_ == string_literal_state_t::SIZE)
                {
                    if (!isdigit(ch))
                        throw imap_error("Parser failure.", "");

                    cur_token->literal_size += ch;
                }
                else if (literal_state_ == string_literal_state_t::WAITING)
                {
                    // no characters allowed after the right brace, crlf is required
                    throw imap_error("Parser failure.", "");
                }
                else
                {
                    if (atom_state_ == atom_state_t::NONE)
                    {
                        cur_token = make_shared<response_token_t>();
                        cur_token->token_type = response_token_t::token_type_t::ATOM;
                        token_list = optional_part_state_ ? find_last_token_list(optional_part_) : find_last_token_list(mandatory_part_);
                        token_list->push_back(cur_token);
                        atom_state_ = atom_state_t::PLAIN;
                    }
                    cur_token->atom += ch;
                }
            }
        }
    }

    if (literal_state_ == string_literal_state_t::WAITING)
        literal_state_ = string_literal_state_t::READING;
}

void imap::reset_response_parser()
{
    optional_part_.clear();
    mandatory_part_.clear();
    optional_part_state_ = false;
    atom_state_ = atom_state_t::NONE;
    parenthesis_list_counter_ = 0;
    literal_state_ = string_literal_state_t::NONE;
    literal_bytes_read_ = 0;
    eols_no_ = 2;
}


string imap::format(const string& command)
{
    return to_string(++tag_) + TOKEN_SEPARATOR_STR + command;
}


void imap::trim_eol(string& line)
{
    if (line.length() >= 1 && line[line.length() - 1] == codec::END_OF_LINE[0])
    {
        eols_no_ = 2;
        line.pop_back();
    }
    else
        eols_no_ = 1;
}


string imap::folder_tree_to_string(const list<string>& folder_tree, string delimiter) const
{
    string folders;
    std::size_t elem = 0;
    for (const auto& f : folder_tree)
        if (elem++ < folder_tree.size() - 1)
            folders += f + delimiter;
        else
            folders += f;
    return folders;
}


string imap::imap_date_to_string(const boost::gregorian::date& gregorian_date)
{
    stringstream ss;
    ss.exceptions(std::ios_base::failbit);
    boost::gregorian::date_facet* facet = new boost::gregorian::date_facet("%d-%b-%Y");
    ss.imbue(std::locale(ss.getloc(), facet));
    ss << gregorian_date;
    return ss.str();
}



list<shared_ptr<imap::response_token_t>>* imap::find_last_token_list(list<shared_ptr<response_token_t>>& token_list)
{
    list<shared_ptr<response_token_t>>* list_ptr = &token_list;
    unsigned int depth = 1;
    while (!list_ptr->empty() && list_ptr->back()->token_type == response_token_t::token_type_t::LIST && depth <= parenthesis_list_counter_)
    {
        list_ptr = &(list_ptr->back()->parenthesized_list);
        depth++;
    }
    return list_ptr;
}


imaps::imaps(const string& hostname, unsigned port, milliseconds timeout) : imap(hostname, port, timeout)
{
    ssl_options_ =
        {
            boost::asio::ssl::context::sslv23,
            boost::asio::ssl::verify_none
        };
    is_start_tls_ = false;
}


string imaps::authenticate(const string& username, const string& password, auth_method_t method)
{
    string greeting;
    if (method == auth_method_t::LOGIN)
    {
        is_start_tls_ = false;
        greeting = imap::authenticate(username, password, imap::auth_method_t::LOGIN);
    }
    else if (method == auth_method_t::START_TLS)
    {
        is_start_tls_ = true;
        greeting = imap::authenticate(username, password, imap::auth_method_t::LOGIN);
    }
    else if (method == auth_method_t::XOAUTH2)
    {
        is_start_tls_ = false;
        greeting = imap::authenticate(username, password, imap::auth_method_t::XOAUTH2);
    }
    return greeting;
}


void imaps::ssl_options(const dialog_ssl::ssl_options_t& options)
{
    *ssl_options_ = options;
}


imap_error::imap_error(const string& msg, const string& details) : dialog_error(msg, details)
{
}


imap_error::imap_error(const char* msg, const string& details) : dialog_error(msg, details)
{
}


} // namespace mailio
