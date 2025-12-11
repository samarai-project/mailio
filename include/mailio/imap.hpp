/*

imap.cpp
--------

Copyright (C) 2016, Tomislav Karastojkovic (http://www.alepho.com).

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

*/


#pragma once

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4251)
#endif

#include <chrono>
#include <list>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <tuple>
#include <variant>
#include <optional>
#include <vector>
#include <functional>
#include <atomic>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/date_time/gregorian/gregorian.hpp>
#include <cstdint>
#include "dialog.hpp"
#include "message.hpp"
#include "export.hpp"


namespace mailio
{


/**
IMAP client implementation.
**/
class MAILIO_EXPORT imap
{
public:

    /**
    Mailbox statistics structure.
    **/
    struct mailbox_stat_t
    {
        /**
        Statistics information to be retrieved.
        **/
        enum stat_info_t {
            DEFAULT = 0, 
            UNSEEN = 1, 
            UID_NEXT = 2, 
            UID_VALIDITY = 4, 
            HIGHEST_MODSEQ = 8
        };

        /**
        Number of messages in the mailbox.
        **/
        unsigned long messages_no;

        /**
        Number of recent messages in the mailbox.
        **/
        unsigned long messages_recent;

        /**
        The non-zero number of unseen messages in the mailbox.

        Zero indicates the server did not report this and no assumptions can be made about the number of unseen messages.
        **/
        unsigned long messages_unseen;

        /**
        The non-zero message sequence number of the first unseen message in the mailbox.

        Zero indicates the server did not report this and no assumptions can be made about the first unseen message.
        **/
        unsigned long messages_first_unseen;

        /**
        The non-zero next unique identifier value of the mailbox.

        Zero indicates the server did not report this and no assumptions can be made about the next unique identifier.
        **/
        unsigned long uid_next;

        /**
        The non-zero unique identifier validity value of the mailbox.

        Zero indicates the server did not report this and does not support UIDs.
        **/
        unsigned long uid_validity;

        /**
        The non-zero highest modification sequence number of the mailbox (CONDSTORE/QRESYNC).

        Zero indicates the server did not report this or does not support CONDSTORE.
        **/
        unsigned long long highest_modseq;

        /** Name of the mailbox these stats correspond to. */
        std::string mailbox_name;

        /** True if the mailbox does not exist or is not accessible. */
        bool not_exist{false};

        /**
        Setting the number of messages to zero.
        **/
        mailbox_stat_t() : messages_no(0), messages_recent(0), messages_unseen(0), messages_first_unseen(0), uid_next(0), uid_validity(0), highest_modseq(0)
        {
        }
    };

    /**
    Bulk STATUS across multiple mailboxes using best-effort semantics.

    If the server advertises LIST-STATUS, the method prefers issuing LIST RETURN (STATUS ...)
    per mailbox; otherwise it falls back to a simple STATUS loop using `statistics()`.

    The returned vector always has one entry per requested mailbox, preserving order. For
    non-existent or inaccessible mailboxes, the corresponding `mailbox_stat_t` will have
    `not_exist=true` and other fields set to zero.

    Fields populated: MESSAGES, UIDNEXT, UIDVALIDITY, and HIGHESTMODSEQ when supported
    (CONDSTORE capability) and available in server responses.

    @param mailboxes  List of mailbox names to query.
    @return           Vector of mailbox_stat_t in the same order as input.
    */
    std::vector<mailbox_stat_t> bulk_status(const std::vector<std::string>& mailboxes);

    /**
    Mailbox folder tree.
    **/
    struct mailbox_folder_t
    {
        std::map<std::string, mailbox_folder_t> folders;
        bool selectable = true;
        std::vector<std::string> attributes;
    };

    /**
    High-level classification of folders for client discovery.
    */
    enum class mailbox_folder_type_t
    {
        REGULAR,
        INBOX,
        SENT,
        DRAFTS,
        TRASH,
        JUNK,
        ARCHIVE,
        FLAGGED,
        ALL,
        IMPORTANT
    };

    /**
    Flat folder descriptor returned by `list_folders_high_level`.
    */
    struct mailbox_high_level_t
    {
        std::string path;                /**< IMAP mailbox identifier to use with SELECT. */
        std::string name;                /**< User-facing folder name (leaf in the hierarchy). */
        mailbox_folder_type_t type;      /**< Classification derived from SPECIAL-USE/INBOX rules. */
        bool is_virtual = false;         /**< True for virtual/aggregate folders (All Mail, Flagged, Important). */
        bool can_add = false;            /**< True if messages can be appended or moved into the folder. */
        bool is_custom = false;          /**< True if folder is user-created (i.e. not well-known). */
        bool can_delete = false;         /**< True if folder can be deleted. */
    };

    /**
    Available authentication methods.

    The following mechanisms are allowed:
    - LOGIN: The username and password are sent in plain format.
    **/
    enum class auth_method_t {LOGIN, XOAUTH2};

    /**
    Single message ID or range of message IDs to be searched for.
    **/
    typedef std::pair<unsigned long, std::optional<unsigned long>> messages_range_t;

    /**
    Condition used by IMAP searching.

    It consists of key and value. Each key except the ALL has a value of the appropriate type: string, list of IDs, date.

    @todo Since both key and value types are known at compile time, perhaps they should be checked then instead at runtime.
    **/
    struct MAILIO_EXPORT search_condition_t
    {
        /**
        Condition key to be used as message search criteria.

        The following searching criteria are defined:
        - ALL: all messages in the mailbox.
        - SID_LIST: messages with session identifiers specified in the set.
        - UID_LIST: messages with unique identifiers specified in the set.
        - SUBJECT: messages that contain the specified string in the subject.
        - BODY: messages that contain the specified string in the body.
        - FROM: messages that contain the specified string in the 'from' field.
        - TO: messages that contain the specified string in the 'to' field.
        - BEFORE_DATE: messages whose internal date is earlier than the specified date.
        - ON_DATE: messages whose internal date is within the specified date.
        - SINCE_DATE: messages whose internal date is within or later than the specified date.
        - NEW: messages that have the `\Recent` flag set but not `\Seen`.
        - RECENT: messages that have the `\Recent` flag set.
        - SEEN: messages that have the `\Seen` flag set.
        - UNSEEN: messages that do not have the `\Seen` flag set.

        @todo Criteria for the flags set.
        @todo Negative (not) criteria.
        **/
        enum key_type {ALL, SID_LIST, UID_LIST, SUBJECT, BODY, FROM, TO, BEFORE_DATE, ON_DATE, SINCE_DATE, NEW, RECENT, SEEN, UNSEEN} key;

        /**
        Condition value type to be used as message search criteria.

        Key ALL uses null because it does not need the value. Single ID can be given or range of IDs, or more than one range.
        **/
        typedef std::variant
        <
            std::monostate,
            std::string,
            std::list<messages_range_t>,
            boost::gregorian::date
        >
        value_type;

        /**
        Condition value itself.
        **/
        value_type value;

        /**
        String used to send over IMAP.
        **/
        std::string imap_string;

        /**
        Creating the IMAP string of the given condition.

        @param condition_key   Key to search for.
        @param condition_value Value to search for, default (empty) value is meant for the ALL key.
        @throw imap_error      Invaid search condition.
        **/
        search_condition_t(key_type condition_key, value_type condition_value = value_type());
    };

    /**
    Creating a connection to a server.

    @param hostname Hostname of the server.
    @param port     Port of the server.
    @param timeout  Network timeout after which I/O operations fail. If zero, then no timeout is set i.e. I/O operations are synchronous.
    @throw *        `dialog::dialog(const string&, unsigned)`.
    **/
    imap(const std::string& hostname, unsigned port, std::chrono::milliseconds timeout = std::chrono::milliseconds(0));

    /**
    Sending the logout command and closing the connection.
    **/
    virtual ~imap();

    imap(const imap&) = delete;

    imap(imap&&) = delete;

    void operator=(const imap&) = delete;

    void operator=(imap&&) = delete;

    /**
    Set a human-friendly name for this IMAP session.

    The name is forwarded to the underlying network dialog so that
    debug logs get prefixed with the session label. Useful when running
    multiple concurrent sessions and diagnosing traffic.

    Example: set_session_name("acc1");
    Results in log lines like: [acc1] SEND: <cmd>

    @param name  Arbitrary identifier; empty clears the name.
    */
    void set_session_name(const std::string& name);

    /** Get the current IMAP session name (possibly empty). */
    std::string session_name() const;

    /**
    Authenticating with the given credentials.

    The method should be called only once on an existing object - it is not possible to authenticate again within the same connection.

    @param username Username to authenticate.
    @param password Password to authenticate.
    @param method   Authentication method to use.
    @return         The server greeting message.

    @throw *        `connect()`, `auth_login(const string&, const string&)`.
    **/
    std::string authenticate(const std::string& username, const std::string& password, auth_method_t method);

    /**
    Selecting a mailbox.

    @param folder_name Folder to list.
    @return            Mailbox statistics.
    @throw imap_error  Selecting mailbox failure.
    @throw imap_error  Parsing failure.
    @throw *           `parse_tag_result(const string&)`, `dialog::send(const string&)`, `dialog::receive()`.
    @todo              Add server error messages to exceptions.
    @todo              Catch exceptions of `stoul` function.
    **/
    mailbox_stat_t select(const std::list<std::string>& folder_name, bool read_only = false);

    /**
    Selecting a mailbox.

    @param mailbox    Mailbox to select.
    @param read_only  Flag if the selected mailbox is only readable or also writable.
    @return           Mailbox statistics.
    @throw imap_error Selecting mailbox failure.
    @throw imap_error Parsing failure.
    @throw *          `parse_tag_result(const string&)`, `dialog::send(const string&)`, `dialog::receive()`.
    @todo             Add server error messages to exceptions.
    **/
    mailbox_stat_t select(const std::string& mailbox, bool read_only = false);

    /**
    Fetching a message from the mailbox.

    Some servers report success if a message with the given number does not exist, so the method returns with the empty `msg`. Other considers
    fetching non-existing message to be an error, and an exception is thrown.

    @param mailbox     Mailbox to fetch from.
    @param message_no  Number of the message to fetch.
    @param msg         Message to store the result.
    @param is_uid      Using a message uid number instead of a message sequence number.
    @param header_only    Flag if only the message header should be fetched.
    @param dont_set_seen  If true, fetches the message using PEEK semantics so the \\Seen flag is not set on the server. The returned octets are
                          byte-for-byte identical to the RFC822 variant (RFC822 == BODY[]; RFC822.HEADER == BODY.PEEK[HEADER]).
    @throw imap_error  Fetching message failure.
    @throw imap_error  Parsing failure.
    @throw *           `fetch(const list<messages_range_t>&, map<unsigned long, message>&, bool, bool, codec::line_len_policy_t)`.
    @todo              Add server error messages to exceptions.
    **/
    void fetch(const std::string& mailbox, unsigned long message_no, bool is_uid, message& msg, bool header_only = false,
               bool dont_set_seen = false);

    /**
    Fetching a message from an already selected mailbox.

    A mailbox must already be selected before calling this method.

    Some servers report success if a message with the given number does not exist, so the method returns with the empty `msg`. Other considers
    fetching non-existing message to be an error, and an exception is thrown.

    @param message_no  Number of the message to fetch.
    @param msg         Message to store the result.
    @param is_uid      Using a message uid number instead of a message sequence number.
    @param header_only    Flag if only the message header should be fetched.
    @param dont_set_seen  If true, use PEEK semantics to avoid setting \\Seen while preserving the exact returned bytes.
    @throw *           `fetch(const list<messages_range_t>&, map<unsigned long, message>&, bool, bool, codec::line_len_policy_t)`.
    @todo              Add server error messages to exceptions.
    **/
    void fetch(unsigned long message_no, message& msg, bool is_uid = false, bool header_only = false,
               bool dont_set_seen = false);

    /**
    Fetching messages from an already selected mailbox.

    A mailbox must already be selected before calling this method.

    Some servers report success if a message with the given number does not exist, so the method returns with the empty `msg`. Other considers
    fetching non-existing message to be an error, and an exception is thrown.

    @param messages_range Range of message numbers or UIDs to fetch.
    @param found_messages Map of messages to store the results, indexed by message number or uid.
                          It does not clear the map first, so that results can be accumulated.
    @param is_uids        Using message UID numbers instead of a message sequence numbers.
    @param header_only    Flag if only the message headers should be fetched.
    @param line_policy    Decoder line policy to use while parsing each message.
    @param dont_set_seen  If true, use BODY.PEEK to avoid setting the \\Seen flag on the server; octets are identical to RFC822/HEADER variants.
    @throw imap_error     Fetching message failure.
    @throw imap_error     Parsing failure.
    @throw *              `parse_tag_result(const string&)`, `parse_response(const string&)`,
                          `dialog::send(const string&)`, `dialog::receive()`, `message::parse(const string&, bool)`.
    @todo                 Add server error messages to exceptions.
    **/
    void fetch(const std::list<messages_range_t>& messages_range, std::map<unsigned long, message>& found_messages, bool is_uids = false,
        bool header_only = false, codec::line_len_policy_t line_policy = codec::line_len_policy_t::RECOMMENDED,
        bool dont_set_seen = false);

    /**
    Appending a message to the given folder.

    @param folder_name Folder to append the message.
    @param msg         Message to append.
    @throw *           `append(const string&, const message&)`.
    **/
    void append(const std::list<std::string>& folder_name, const message& msg);

    /**
    Appending a message to the given folder.

    @param folder_name Folder to append the message.
    @param msg         Message to append.
    @throw imap_error  `Message appending failure.`, `parse_tag_result(const string&)`, `dialog::send(const string&)`, `dialog::receive()`,
                       `message::format(std::string&, bool)`.
    **/
    void append(const std::string& folder_name, const message& msg);

    /**
    Getting the mailbox statistics.

    The server might not support unseen, uidnext, or uidvalidity, which will cause an exception, so those parameters are optional.

    @param mailbox    Mailbox name.
    @param info       Statistics information to be retrieved.
    @return           Mailbox statistics.
    @throw imap_error Parsing failure.
    @throw imap_error Getting statistics failure.
    @throw *          `parse_tag_result(const string&)`, `parse_response(const string&)`, `dialog::send(const string&)`, `dialog::receive()`.
    @todo             Add server error messages to exceptions.
    @todo             Exceptions by `stoul()` should be rethrown as parsing failure.
    **/
    mailbox_stat_t statistics(const std::string& mailbox, unsigned int info = mailbox_stat_t::DEFAULT);


    /**
    Overload of the `statistics(const std::string&, unsigned int)`.

    @param folder_name Name of the folder to query for the statistics.
    @param info        Statistics information to be retrieved.
    @return            Mailbox statistics.
    @throw *           `statistics(const std::string&, unsigned int)`.
    **/
    mailbox_stat_t statistics(const std::list<std::string>& folder_name, unsigned int info = mailbox_stat_t::DEFAULT);

    /**
    Query only UIDNEXT for a mailbox using a lightweight STATUS.

    Sends: STATUS "mailbox" (UIDNEXT) and returns the numeric UIDNEXT value.

    @param mailbox     Mailbox name.
    @return            UIDNEXT value for the mailbox.
    @throw imap_error  Parsing failure or server error.
    */
    unsigned long status_uidnext(const std::string& mailbox);
 
    /**
    Get the UID corresponding to a given message sequence number in the currently selected mailbox.

    The method issues:
        FETCH <seq_no> (UID)
    against the already selected mailbox and returns the UID value reported by
    the server for that message. If the requested sequence number does not exist
    (e.g., the mailbox is empty or seq_no is out of range), returns 0.

    Notes:
    - A mailbox must be selected prior to calling this method (e.g., via select()).
    - On protocol or server errors (tagged NO/BAD unrelated to non-existence), an exception
      is thrown; 0 is reserved for the "no such message" case.

    @param seq_no      Message sequence number to query.
    @return            UID for the message, or 0 if no such message.
    @throw imap_error  Parsing failure or server error.
    */
    unsigned long uid_from_sequence_no(unsigned long seq_no);
 
    /**
    Removing a message from the given mailbox.

    @param mailbox    Mailbox to use.
    @param message_no Number of the message to remove.
    @param is_uid     Using a message uid number instead of a message sequence number.
    @throw imap_error Deleting message failure.
    @throw imap_error Parsing failure.
    @throw *          `select(const string&)`, `parse_tag_result(const string&)`, `remove(unsigned long, bool)`, `dialog::send(const string&)`, `dialog::receive()`.
    @todo             Add server error messages to exceptions.
    **/
    void remove(const std::string& mailbox, unsigned long message_no, bool is_uid = false);

    /**
    Removing a message from the given mailbox.

    @param mailbox    Mailbox to use.
    @param message_no Number of the message to remove.
    @param is_uid     Using a message uid number instead of a message sequence number.
    @throw *          `remove(const string&, bool)`.
    @todo             Add server error messages to exceptions.
    **/
    void remove(const std::list<std::string>& mailbox, unsigned long message_no, bool is_uid = false);

    /**
    Removing a message from an already selected mailbox.

    @param message_no Number of the message to remove.
    @param is_uid     Using a message uid number instead of a message sequence number.
    @throw imap_error Deleting message failure.
    @throw imap_error Parsing failure.
    @throw *          `parse_tag_result(const string&)`, `dialog::send(const string&)`, `dialog::receive()`.
    @todo             Add server error messages to exceptions.
    @todo             Catch exceptions of `stoul` function.
    **/
    void remove(unsigned long message_no, bool is_uid = false);

    /**
    Searching a mailbox.

    The RFC 3501 section 6.4.4 does not specify whether another untagged response except the SEARCH can be obtained. However, there are IMAP servers which
    send, for instance, the EXISTS response. Thus, such non-specified responses are ignored, instead of being reported as errors.

    @param conditions  List of conditions taken in conjuction way.
    @param results     Store resulting list of message sequence numbers or UIDs here.
                       Does not clear the list first, so that results can be accumulated.
    @param want_uids   Return a list of message UIDs instead of message sequence numbers.
    @throw imap_error  Search mailbox failure.
    @throw imap_error  Parsing failure.
    @throw *           `parse_tag_result(const string&)`, `dialog::send(const string&)`, `dialog::receive()`.
    @todo              Add server error messages to exceptions.
    **/
    void search(const std::list<search_condition_t> &conditions, std::list<unsigned long> &results, bool want_uids = false);

 
    struct idle_event_t
    {
        enum class type_t
        {
            EXISTS,      // Signals a change in the total number of messages in the selected mailbox
            EXPUNGE,     // Signals that a message has been permanently removed
            RECENT,      // Informs about the number of messages with the \Recent flag
            FETCH_FLAGS, // indicates a metadata change for a specific message
            OTHER
        } type;
        // Numeric payload when present (message sequence number etc.). 0 if not applicable.
        unsigned long number{0};
        // Raw untagged response text (without tag/result), best-effort for diagnostics.
        std::string raw;
    };
    enum class idle_result_t
    {
        EXPIRED,
        BYE,
    };
        /**
        Enter RFC 2177 IDLE and stream untagged mailbox updates to a callback.

        Semantics and guarantees:
        - Independent timeout: The idle timeout controls how long this method stays
            in the IDLE state before returning idle_result_t::EXPIRED. It is completely
            independent of the lower, short networking timeout configured on the dialog
            (typically 10–20 seconds). A network timeout does NOT end IDLE by itself;
            it is treated as transient inactivity and the loop continues until the
            idle timeout elapses, cancellation is requested, a server BYE is received,
            or a real networking error occurs.
        - Best-effort parsing: Server untagged responses are parsed leniently.
            Recognized events (EXISTS, EXPUNGE, RECENT, FETCH FLAGS) are reported via
            idle_event_t. Unknown or malformed lines are delivered as OTHER with the
            raw text preserved.
        - Server BYE: If the server sends an untagged BYE, the method exits promptly
            and returns idle_result_t::BYE.
        - Exceptions: Networking errors other than timeouts are forwarded to the
            caller (e.g., disconnects, protocol I/O failures). Parsing problems do not
            throw; they are surfaced as OTHER events. The method itself avoids throwing
            unless absolutely necessary to report a genuine networking issue.
        - DONE handling: On natural exit (timeout or callback requests stop), the
            method will send DONE and best-effort wait for the tagged completion to
            keep the protocol state consistent. In the presence of planned disconnects
            or time pressure, this is best-effort only.

        @param on_event Callback invoked for each observed event. Return true to keep
                                        idling, false to stop and return idle_result_t::EXPIRED.
        @param timeout  Maximum duration to remain in IDLE before returning EXPIRED.
        @param cancel   External cancellation flag checked between receives; when set
                                        the method exits like a timeout with EXPIRED.
        @return         idle_result_t::EXPIRED when the idle period ends normally or
                                        cancellation is observed; idle_result_t::BYE when the server
                                        closes the connection.
        @throw *        Networking failures (other than timeouts) from the underlying
                                        dialog are rethrown to the caller.
        */
        idle_result_t idle(const std::function<bool(const idle_event_t &)> &on_event,
                                             std::chrono::milliseconds timeout,
                                             const std::atomic_bool &cancel);

    /**
    Gracefully disconnect from the server within a bounded timeout.

    Behavior:
    - If currently in IDLE, send DONE and wait up to the given timeout for the tagged OK.
    - Regardless of server response, abort pending I/O and close the socket so
        callers are not blocked during shutdown.
    - Any in-flight or subsequent IMAP operations will throw imap_planned_disconnect
        to signal an intentional shutdown.

    @param timeout Maximum time to spend attempting a graceful DONE. Defaults to 200ms.
    */
    void disconnect(std::chrono::milliseconds timeout = std::chrono::milliseconds(200));

    /**
    Adjust the underlying dialog timeout for subsequent IMAP I/O.

    Useful to shorten timeouts during connect/auth/select, and lengthen when
    entering long-lived IDLE.
    */
    void set_timeout(std::chrono::milliseconds timeout)
    {
        if (dlg_)
            dlg_->set_timeout(timeout);
    }
    std::chrono::milliseconds timeout() const { return dlg_ ? dlg_->timeout() : std::chrono::milliseconds(0); }

    /**
    Creating folder.

    @param folder_name Folder to be created.
    @return            True if created, false if not.
    @throw imap_error  Parsing failure.
    @throw imap_error  Creating folder failure.
    @throw *           `parse_tag_result(const string&)`, `dialog::send(const string&)`, `dialog::receive()`.
    @todo              Return status really needed?
    **/
    bool create_folder(const std::string& folder_name);

    /**
    Creating folder.

    @param folder_name Folder to be created.
    @return            True if created, false if not.
    @throw *           `folder_delimiter()`, `create_folder(const string&)`.
    @todo              Return status really needed?
    **/
    bool create_folder(const std::list<std::string>& folder_name);

    /**
    Listing folders.

    @param folder_name Folder to list.
    @return            Subfolder tree of the folder.
    @throw imap_error  Listing folders failure.
    @throw imap_error  Parsing failure.
    @throw *           `folder_delimiter()`, `parse_tag_result`, `dialog::send(const string&)`, `dialog::receive()`.
    **/
    mailbox_folder_t list_folders(const std::string& folder_name);

    /**
    Listing folders.

    @param folder_name Folder to list.
    @return            Subfolder tree of the folder.
    @throw *           `folder_delimiter()`, `list_folders(const string&)`.
    **/
    mailbox_folder_t list_folders(const std::list<std::string> &folder_name);

    /**
    Listing folders with SPECIAL-USE attributes (RFC 6154 / RFC 5258).

    Sends an extended LIST command to retrieve special-use attributes like
    \All, \Archive, \Drafts, \Junk, \Sent, \Trash (and \Important if supported).

    If only_special is false (default), the command used is:
        LIST "" "*" RETURN (SPECIAL-USE)
    which returns all mailboxes along with any SPECIAL-USE attributes they have.

    If only_special is true, the command used is:
        LIST (SPECIAL-USE) "" "*"
    which returns only mailboxes that are marked with SPECIAL-USE.

    Returned map keys are mailbox names; values are vectors of special-use
    attribute strings as advertised by the server (e.g., "\\Sent").

    @param only_special If true, list only special-use mailboxes; otherwise return
                                            special-use attributes for all mailboxes.
    @return             Map of mailbox name to a list of its SPECIAL-USE attributes.
    @throw imap_error   Listing folders failure or parsing failure.
    */
    using special_use_map_t = std::map<std::string, std::vector<std::string>>;
    special_use_map_t list_special_use(bool only_special = false);

    /**
    Best-effort mapping of SPECIAL-USE attribute to mailbox name.

    Returns a map keyed by canonical special-use names (e.g., "\\Sent", "\\Trash",
    "\\Drafts", "\\Junk", "\\Archive", "\\All", "\\Important", "\\Flagged")
    with the value being the mailbox name that advertises that special use.

    If multiple mailboxes claim the same attribute, the first one seen wins. The method
    never throws on parsing mismatches; it attempts RETURN (SPECIAL-USE), then XLIST, then
    plain LIST, and extracts what it can.

    @return Map of special-use attribute to mailbox name.
    */
    using special_use_by_attr_map_t = std::map<std::string, std::string>;
    special_use_by_attr_map_t list_special_use_by_attr();

    /**
    Best-effort listing of folders with an "interest" flag for end users.

    Heuristics:
    - Always mark INBOX as interesting.
    - Mark \Sent and \Archive mailboxes as interesting.
    - Mark utility/system folders as not interesting: \Trash, \Junk (Spam), \Drafts,
        \All (All Mail), \Important, \Flagged.
    - Apply a small name-based blacklist for vendor maintenance folders (e.g.,
        "Sync Issues", "Conflicts", "Local Failures", "Server Failures",
        "Conversation History", "Clutter", "RSS Feeds", "Suggested Contacts",
        "Outbox", and non-mail modules like "Calendar", "Contacts", "Tasks",
        "Notes", "Journal").
    - Best-effort special-use detection; falls back to names if absent.

    Implementation uses existing listing helpers; it does not duplicate IMAP I/O.

    @return Vector of pairs (mailbox name, is_interesting).
    */
    using folders_interest_list_t = std::vector<std::pair<std::string, bool>>;
    folders_interest_list_t list_folders_interest();

    /**
    Flat high-level folder listing suitable for folder discovery in clients.

    Collects existing folder metadata, folds in SPECIAL-USE information, skips non-selectable
    nodes and applies heuristics for capability flags (virtual/canAdd/canDelete/custom).

    @return Ordered list of folder descriptors (leaf order from LIST traversal).
    @throw * `list_special_use_by_attr()`, `list_folders(const string&)`, `folder_delimiter()`.
    */
    using high_level_folders_list_t = std::vector<mailbox_high_level_t>;
    high_level_folders_list_t list_folders_high_level();

    /**
    Return server CAPABILITY tokens, cached for the lifetime of this imap instance.

    The first call issues CAPABILITY and stores the returned atoms. Subsequent calls
    return the cached list without additional network I/O.
    */
    const std::vector<std::string>& capabilities();

    /**
    Deleting a folder.

    @param folder_name Folder to delete.
    @return            True if deleted, false if not.
    @throw imap_error  Parsing failure.
    @throw imap_error  Deleting folder failure.
    @throw *           `folder_delimiter()`, `parse_tag_result(const string&)`, `dialog::send(const string&)`, `dialog::receive()`.
    @todo              Return status really needed?
    **/
    bool delete_folder(const std::string& folder_name);

    /**
    Deleting a folder.

    @param folder_name Folder to delete.
    @return            True if deleted, false if not.
    @throw *           `delete_folder(const string&)`.
    @todo              Return status really needed?
    **/
    bool delete_folder(const std::list<std::string>& folder_name);

    /**
    Renaming a folder.

    @param old_name    Old name of the folder.
    @param new_name    New name of the folder.
    @return            True if renaming is successful, false if not.
    @throw imap_error  Parsing failure.
    @throw imap_error  Renaming folder failure.
    @throw *           `folder_delimiter()`, `parse_tag_result(const string&)`, `dialog::send(const string&)`, `dialog::receive()`.
    @todo              Return status really needed?
    **/
    bool rename_folder(const std::string& old_name, const std::string& new_name);

    /**
    Renaming a folder.

    @param old_name    Old name of the folder.
    @param new_name    New name of the folder.
    @return            True if renaming is successful, false if not.
    @throw *           `rename_folder(const string&, const string&)`.
    @todo              Return status really needed?
    **/
    bool rename_folder(const std::list<std::string>& old_name, const std::list<std::string>& new_name);

    /**
    Setting the start TLS option.

    @param is_tls If true, the start TLS option is turned on, otherwise is turned off.
    **/
    void start_tls(bool is_tls);

    /**
    Setting SSL options.

    @param options SSL options to set.
    **/
    void ssl_options(const std::optional<dialog_ssl::ssl_options_t> options);

    /**
    Determining folder delimiter of a mailbox.

    It is required to know the folder delimiter string in case one wants to deal with the folder names as strings.

    @return           Folder delimiter.
    @throw imap_error Determining folder delimiter failure.
    @throw *          `parse_tag_result(const string&)`, `dialog::send(const string&)`, `dialog::receive()`.
    **/
    std::string folder_delimiter();

    /**
    Sending a NOOP command to verify the session is alive and to receive any pending updates.

    The method sends the IMAP NOOP command, swallows any untagged responses (such as EXISTS, EXPUNGE, RECENT,
    or FETCH updates), and returns when the tagged OK is received. If the server responds with NO/BAD or a
    protocol parsing error occurs, an exception is thrown. Network errors propagate from the underlying dialog.

    @throw imap_error If the server returns NO/BAD or if parsing fails.
    */
    void noop();
    
    /**
    Enable or disable strict IMAP parsing and validation.

    When enabled, parsing is less tolerant to non-conforming server responses and
    may raise errors where a best-effort fallback would otherwise be used.

    @param mode True to enable strict parsing; false to use best-effort behavior.
    */
    void strict_mode(bool mode);

    /**
    Enable or disable strict codec behavior for MIME/header decoding.

    When enabled, MIME and header codecs adhere strictly to RFCs; malformed
    encodings will cause errors rather than best-effort decoding.

    @param mode True to enable strict codec mode; false for permissive decoding.
    */
    void strict_codec_mode(bool mode);

    /**
    Get whether strict IMAP parsing is enabled.

    @return True if strict mode is enabled; false otherwise.
    */
    bool strict_mode() const;

    /**
    Get whether strict codec mode is enabled.

    @return True if strict codec mode is enabled; false otherwise.
    */
    bool strict_codec_mode() const;    
    
#ifdef MAILIO_TEST_HOOKS
public:
   
    /**
    Test helper: simulate a transport disconnect on the underlying dialog.
    */
    void test_simulate_disconnect();

    /** Configure a simulated dialog error for the next N operations. */
    void test_set_simulated_error(dialog::simulated_error_t err, int count = 1);
    
#endif

protected:

    /**
    Formatting range of IDs to a string.

    @param id_pair Range of IDs to format.
    @return        Range od IDs as IMAP grammar string.
    **/
    static std::string messages_range_to_string(messages_range_t id_pair);

    /**
    Formatting list of ranges of IDs to a string.

    @param ranges List of ID ranges to format.
    @return       List of ranges of IDs as IMAP grammar string.
    **/
    static std::string messages_range_list_to_string(std::list<messages_range_t> ranges);

    /**
    Escaping the double quote and backslashes.

    @param text String to escape.
    @return     Escaped string.
    **/
    static std::string to_astring(const std::string& text);

    /**
    Untagged response character as defined by the protocol.
    **/
    static const std::string UNTAGGED_RESPONSE;

    /**
    Continuation response character as defined by the protocol.
    **/
    static const std::string CONTINUE_RESPONSE;

    /**
    Colon as a separator in the message list range.
    **/
    static const std::string RANGE_SEPARATOR;

    /**
    Character to mark all messages until the end of range.
    **/
    static const std::string RANGE_ALL;

    /**
    Comma as a separator of the list members.
    **/
    static const std::string LIST_SEPARATOR;

    /**
    Character used by IMAP to separate tokens.
    **/
    static const char TOKEN_SEPARATOR_CHAR{' '};

    /**
    String representation of the token separator character.
    **/
    static const std::string TOKEN_SEPARATOR_STR;

    /**
    Quoted string delimiter.
    **/
    static const char QUOTED_STRING_SEPARATOR_CHAR{'"'};

    /**
    String representation of the quoted string delimiter character.
    **/
    static const std::string QUOTED_STRING_SEPARATOR;

    /**
    Character which begins the optional section.
    **/
    static const char OPTIONAL_BEGIN{'['};

    /**
    Character which ends the optional section.
    **/
    static const char OPTIONAL_END{']'};

    /**
    Character which begins the list.
    **/
    static const char LIST_BEGIN{'('};

    /**
    Character which ends the list.
    **/
    static const char LIST_END{')'};

    /**
    Character which begins the literal string.
    **/
    static const char STRING_LITERAL_BEGIN{'{'};

    /**
    Character which ends the literal string.
    **/
    static const char STRING_LITERAL_END{'}'};

    /**
    Delimiter of a quoted atom in the protocol.
    **/
    static const char QUOTED_ATOM{'"'};

    /**
    Initiating a session to the server.

    @return           The server greeting message.
    @throw imap_error Connection to server failure.
    @throw imap_error Parsing failure.
    @throw *          `parse_tag_result(const string&)`, `dialog::receive()`.
    @todo             Add server error messages to exceptions.
    **/
    std::string connect();

    /**
    Switching to TLS layer.

    @throw imap_error Bad server response.
    @throw imap_error Start TLS refused by server.
    @throw *          `parse_tag_result(const std::string&)`, `dialog::to_ssl()`, `dialog::send(const std::string&)`, `dialog::receive()`.
    **/
    void switch_tls();

    /**
    Performing an authentication by using the login method.

    @param username   Username to authenticate.
    @param password   Password to authenticate.
    @throw imap_error Authentication failure.
    @throw imap_error Parsing failure.
    @throw *          `parse_tag_result(const string&)`, `dialog::send(const string&)`, `dialog::receive()`.
    @todo             Add server error messages to exceptions.
    **/
    void auth_login(const std::string& username, const std::string& password);
    
    /**
    Perform XOAUTH2 authentication using a bearer access token.

    @param username      Account identifier (often the email address).
    @param access_token  OAuth2 bearer token to present to the server.
    @throw imap_error    Authentication failure or parsing failure.
    */
    void auth_login_xoauth2(const std::string &username, const std::string &access_token);

    /**
    Searching a mailbox.

    @param conditions  String of search keys.
    @param results     Store resulting list of indexes here.
    @param want_uids   Return a list of message uids instead of message sequence numbers.
    @throw imap_error  Search mailbox failure.
    @throw imap_error  Parsing failure.
    @throw *           `parse_tag_result(const string&)`, `dialog::send(const string&)`, `dialog::receive()`.
    @todo              Add server error messages to exceptions.
    **/
    void search(const std::string& conditions, std::list<unsigned long>& results, bool want_uids = false);

    /**
    Folder delimiter string determined by the IMAP server.
    **/
    std::string folder_delimiter_;

    // Cached capabilities (per-session)
    std::vector<std::string> capabilities_cache_;
    bool capabilities_cached_ = false;

    // Cached SPECIAL-USE attr->mailbox mapping (per-session)
    special_use_by_attr_map_t special_use_by_attr_cache_;
    bool special_use_by_attr_cached_ = false;

    /**
    Parsed elements of IMAP response line.
    **/
    struct tag_result_response_t
    {
        /**
        Possible response results.
        **/
        enum result_t {OK, NO, BAD};

        /**
        Tag of the response.
        **/
        std::string tag;

        /**
        Result of the response, if exists.
        **/
        std::optional<result_t> result;

        /**
        Rest of the response line.
        **/
        std::string response;

        tag_result_response_t() = default;

        /**
        Initializing the tag, result and rest of the line with the given values.
        **/
        tag_result_response_t(const std::string& parsed_tag, const std::optional<result_t>& parsed_result, const std::string& parsed_response) :
            tag(parsed_tag), result(parsed_result), response(parsed_response)
        {
        }

        tag_result_response_t(const tag_result_response_t&) = delete;

        tag_result_response_t(tag_result_response_t&&) = delete;

        ~tag_result_response_t() = default;

        tag_result_response_t& operator=(const tag_result_response_t&) = delete;

        tag_result_response_t& operator=(tag_result_response_t&&) = delete;

        /**
        Formatting the response line to a user friendly format.

        @return Response line as string.
        **/
        std::string to_string() const;
    };

    /**
    Parsing a line into tag, result and response which is the rest of the line.

    @param line       Response line to parse.
    @return           Tuple with the tag, result and response.
    @throw imap_error Parsing failure.
    */
    tag_result_response_t parse_tag_result(const std::string& line) const;

    /**
    Parsing a response (without tag and result) into optional and mandatory part.

    This is the main function that deals with the IMAP grammar.

    @param response   Response to parse without tag and result.
    @throw imap_error Parser failure.
    @throw *          `std::stoul`.
    @todo             Perhaps the error should point to a part of the string where the parsing fails.
    **/
    void parse_response(const std::string& response);

    /**
    Resetting the parser state to the initial one.
    **/
    void reset_response_parser();

    /**
    Formatting a tagged command.

    @param command Command to format.
    @return        New tag as string.
    **/
    std::string format(const std::string& command);

    /**
    Trimming trailing CR character.

    @param line Line to trim.
    **/
    void trim_eol(std::string& line);

    /**
    Formatting folder tree to string.

    @param folder_tree Folders to format into string.
    @param delimiter   Delimiter of the folders.
    @return            Formatted string.
    **/
    std::string folder_tree_to_string(const std::list<std::string>& folder_tree, std::string delimiter) const;

    /**
    Converting gregorian date to string required by IMAP searching condition.

    @param gregorian_date Gregorian date to convert.
    @return               Date as string required by IMAP search condition.
    @todo                 Static method of `search_condition_t` structure?
    **/
    static std::string imap_date_to_string(const boost::gregorian::date& gregorian_date);

    /**
    Dialog to use for send/receive operations.
    **/
    std::shared_ptr<dialog> dlg_;

    /** True while inside idle() main loop after server continuation received. */
    std::atomic<bool> is_idling_{false};
    
    /** Set when a planned disconnect is underway to alter behavior (skip DONE on errors). */
    std::atomic<bool> planned_disconnect_{false};

    /**
    SSL options to set.
    **/
    std::optional<dialog_ssl::ssl_options_t> ssl_options_;

    /**
    Flag to switch to the TLS.
    **/
    bool is_start_tls_;

    /**
    Tag used to identify requests and responses.
    **/
    unsigned tag_;

    /**
    Token of the response defined by the grammar.

    Its type is determined by the content, and can be either atom, string literal or parenthesized list. Thus, it can be considered as union of
    those three types.
    **/
    struct response_token_t
    {
        /**
        Token type which can be empty in the case that is not determined yet, atom, string literal or parenthesized list.
        **/
        enum class token_type_t {EMPTY, ATOM, LITERAL, LIST} token_type;

        /**
        Token content in case it is atom.
        **/
        std::string atom;

        /**
        Token content in case it is string literal.
        **/
        std::string literal;

        /**
        String literal is first determined by its size, so it's stored here before reading the literal itself.
        **/
        std::string literal_size;

        /**
        Token content in case it is parenthesized list.

        It can store either of the three types, so the definition is recursive.
        **/
        std::list<std::shared_ptr<response_token_t>> parenthesized_list;

        /**
        Default constructor.
        **/
        response_token_t() : token_type(token_type_t::EMPTY)
        {
        }
    };

    /**
    Optional part of the response, determined by the square brackets.
    **/
    std::list<std::shared_ptr<response_token_t>> optional_part_;

    /**
    Mandatory part of the response, which is any text outside of the square brackets.
    **/
    std::list<std::shared_ptr<response_token_t>> mandatory_part_;

    /**
    Parser state if an optional part is reached.
    **/
    bool optional_part_state_;

    /**
    Parser state if an atom is reached.
    **/
    enum class atom_state_t {NONE, PLAIN, QUOTED} atom_state_;

    /**
    Counting open parenthesis of a parenthized list, thus it also keeps parser state if a parenthesized list is reached.
    **/
    unsigned int parenthesis_list_counter_;

    /**
    Parser state if a string literal is reached.
    **/
    enum class string_literal_state_t {NONE, SIZE, WAITING, READING, DONE} literal_state_;

    /**
    Keeping the number of bytes read so far while parsing a string literal.
    **/
    std::string::size_type literal_bytes_read_;

    /**
    Finding last token of the list at the given depth in terms of parenthesis count.

    When a new token is found, this method enables to find the last current token and append the new one.

    @param token_list Token sequence to traverse.
    @return           Last token of the given sequence at the current depth of parenthesis count.
    **/
    std::list<std::shared_ptr<response_token_t>>* find_last_token_list(std::list<std::shared_ptr<response_token_t>>& token_list);

    /**
    Keeping the number of end-of-line characters to be counted as additionals to a formatted line.

    If CR is removed, then two characters are counted as additional when a literal is read. If CR is not removed, then only LF was removed
    during network read, so one character is counted as additional when a literal is read.

    This is necessary for cases when the protocol returns literal with lines ended with LF only. Not sure is that is the specification violation,
    perhaps CRLF at the end of each line read from network is necessary.

    @todo Check if this is breaking protocol, so it has to be added to a strict mode.
    **/
    std::string::size_type eols_no_;
    
    /**
    Flag indicating strict IMAP response parsing.
    */
    bool strict_mode_ = false;

    /**
    Flag indicating strict codec behavior for MIME/header decoding.
    */
    bool strict_codec_mode_ = false;
    
};


/**
Secure version of `imap` class.
**/
class MAILIO_DEPRECATED imaps : public imap
{
public:

    /**
    Available authentication methods over the TLS connection.

    The following mechanisms are allowed:
    - LOGIN: The username and password are sent in plain format.
    - START_TLS: For the TCP connection, a TLS negotiation is asked before sending the login parameters.
    **/
    enum class auth_method_t {LOGIN, START_TLS, XOAUTH2 };

    /**
    Making a connection to the server.

    Calls parent constructor to do all the work.

    @param hostname Hostname of the server.
    @param port     Port of the server.
    @param timeout  Network timeout after which I/O operations fail. If zero, then no timeout is set i.e. I/O operations are synchronous.
    @throw *        `imap::imap(const std::string&, unsigned)`.
    **/
    imaps(const std::string& hostname, unsigned port, std::chrono::milliseconds timeout = std::chrono::milliseconds(0));

    /**
    Sending the logout command and closing the connection.

    Calls parent destructor to do all the work.
    **/
    virtual ~imaps() = default;

    imaps(const imap&) = delete;

    imaps(imaps&&) = delete;

    void operator=(const imaps&) = delete;

    void operator=(imaps&&) = delete;

    /**
    Authenticating with the given credentials.

    @param username Username to authenticate.
    @param password Password to authenticate.
    @param method   Authentication method to use.
    @throw *        `connect()`, `dialog::to_ssl()`, `start_tls()`, `auth_login(const std::string&, const std::string&)`.
    **/
    std::string authenticate(const std::string& username, const std::string& password, auth_method_t method);

    /**
    Setting SSL options.

    @param options SSL options to set.
    **/
    void ssl_options(const dialog_ssl::ssl_options_t& options);
};


/**
Error thrown by IMAP client.
**/
class imap_error : public dialog_error
{
public:

    /**
    Calling parent constructor.

    @param msg  Error message.
    @param details Detailed message.
    **/
    imap_error(const std::string& msg, const std::string& details);

    /**
    Calling parent constructor.

    @param msg  Error message.
    @param details Detailed message.
    **/
    explicit imap_error(const char* msg, const std::string& details);

    imap_error(const imap_error&) = default;

    imap_error(imap_error&&) = default;

    ~imap_error() = default;

    imap_error& operator=(const imap_error&) = default;

    imap_error& operator=(imap_error&&) = default;
};

/**
Error thrown by IMAP when operations are aborted due to an intentional disconnect.
*/
class imap_planned_disconnect : public imap_error
{
public:
    using imap_error::imap_error;
};


} // namespace mailio


#ifdef _MSC_VER
#pragma warning(pop)
#endif
