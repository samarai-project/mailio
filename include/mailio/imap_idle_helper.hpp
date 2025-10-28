/*

imap_idle_helper.hpp
--------------------

Small helper to run IDLE listeners for multiple mailboxes using separate IMAP
connections. This is optional and sits outside the core class to avoid
threading inside imap.

*/

#pragma once

#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <memory>
#include <functional>
#include "imap.hpp"

namespace mailio {

struct idle_spec
{
    // Dedicated connection per mailbox
    std::shared_ptr<imap> conn;
    std::string mailbox;
    bool read_only{true};
};

/**
Start one background thread per mailbox spec that repeatedly calls imap::idle.

Arguments:
- specs: list of (connection, mailbox) pairs; each connection will be SELECTed
         on that mailbox and used exclusively by its thread.
- on_change: callback invoked from the corresponding thread when an EXISTS/RECENT
             event is observed; provides the mailbox name and event details.
- stop: shared cancellation flag; set to true to stop all threads.
- max_idle: maximum single IDLE duration before re-idling (server limits are often <= 29 minutes).

Returns: a vector of joinable std::thread. The caller owns and should join them.
*/
inline std::vector<std::thread> start_idle_threads(
    const std::vector<idle_spec>& specs,
    std::function<void(const std::string& mailbox, const imap::idle_event_t&)> on_change,
    std::shared_ptr<std::atomic_bool> stop,
    std::chrono::milliseconds max_idle = std::chrono::minutes(15))
{
    std::vector<std::thread> threads;
    threads.reserve(specs.size());

    for (const auto& s : specs)
    {
        threads.emplace_back([s, on_change, stop, max_idle]() mutable {
            try
            {
                auto stat = s.conn->select(s.mailbox, s.read_only);
                (void)stat;
            }
            catch (...) { return; }

            while (!stop->load())
            {
                try
                {
                    s.conn->idle(
                        [&](const imap::idle_event_t& ev){
                            if (ev.type == imap::idle_event_t::type_t::EXISTS || ev.type == imap::idle_event_t::type_t::RECENT)
                            {
                                if (on_change)
                                    on_change(s.mailbox, ev);
                            }
                            // keep idling
                            return !stop->load();
                        },
                        max_idle,
                        *stop
                    );
                }
                catch (...)
                {
                    // Optional: small backoff on error
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                }

                // Optional: send NOOP between cycles to flush any updates
                if (stop->load()) break;
                try { s.conn->noop(); } catch (...) {}
            }
        });
    }
    return threads;
}

} // namespace mailio
