// This file Copyright © Mnemosyne LLC.
// It may be used under GPLv2 (SPDX: GPL-2.0-only), GPLv3 (SPDX: GPL-3.0-only),
// or any future license endorsed by Mnemosyne LLC.
// License text can be found in the licenses/ folder.

#include <algorithm>
#include <chrono>
#include <memory>
#include <string>
#include <string_view>

#if defined(__APPLE__) || defined(__linux__)
#include <arpa/inet.h> // inet_addr()
#endif

#include <fmt/format.h>

#define LIBTRANSMISSION_PORT_FORWARDING_MODULE
#include "libtransmission/log.h"
#include "libtransmission/net.h"
#include "libtransmission/port-forwarding-natpmp.h"
#include "libtransmission/port-forwarding-upnp.h"
#include "libtransmission/port-forwarding.h"
#include "libtransmission/timer.h"
#include "libtransmission/tr-assert.h"
#include "libtransmission/utils.h" // for _()

struct tr_upnp;

using namespace std::literals;

namespace
{
// Whether miniupnpc will read `name` as an interface that sockets can be bound to.
// It reads anything inet_addr() can parse as an address instead, and an address such
// as "0.0.0.0" would send discovery through the default route.
[[nodiscard]] bool is_upnp_interface_name([[maybe_unused]] std::string_view const name)
{
#if defined(__APPLE__) || defined(__linux__)
    return tr_net_bind_interface_index(name) && inet_addr(std::string{ name }.c_str()) == INADDR_NONE;
#else
    return false; // sockets cannot be bound to an interface on this platform
#endif
}
} // namespace

class tr_port_forwarding_impl final : public tr_port_forwarding
{
public:
    explicit tr_port_forwarding_impl(Mediator& mediator)
        : mediator_{ mediator }
    {
    }

    ~tr_port_forwarding_impl() override
    {
        is_shutting_down_ = true;
        stopForwarding();
    }

    tr_port_forwarding_impl(tr_port_forwarding_impl&&) = delete;
    tr_port_forwarding_impl(tr_port_forwarding_impl const&) = delete;
    tr_port_forwarding_impl& operator=(tr_port_forwarding_impl&&) = delete;
    tr_port_forwarding_impl& operator=(tr_port_forwarding_impl const&) = delete;

    void local_port_changed() override
    {
        if (!is_enabled_)
        {
            return;
        }

        stopTimer();
        natPulse(false);
        startTimer();
    }

    void set_enabled(bool enabled) override
    {
        if (enabled)
        {
            is_enabled_ = true;
            startTimer();
        }
        else
        {
            is_enabled_ = false;
            stopForwarding();
        }
    }

    [[nodiscard]] bool is_enabled() const noexcept override
    {
        return is_enabled_;
    }

    [[nodiscard]] tr_port_forwarding_state state() const noexcept override
    {
        return std::max(natpmp_state_, upnp_state_);
    }

private:
    void stopTimer()
    {
        timer_.reset();
    }

    void stopForwarding()
    {
        tr_logAddTrace("stopped");
        natPulse(false);

        natpmp_.reset();
        natpmp_state_ = TR_PORT_UNMAPPED;

        tr_upnpClose(upnp_);
        upnp_ = nullptr;
        upnp_state_ = TR_PORT_UNMAPPED;

        stopTimer();
    }

    void startTimer()
    {
        timer_ = mediator_.timer_maker().create([this]() { this->onTimer(); });
        restartTimer();
    }

    void restartTimer()
    {
        if (!timer_)
        {
            return;
        }

        // when to wake up again
        switch (state())
        {
        case TR_PORT_MAPPED:
            // if we're mapped, everything is fine... check back at `renew_time`
            // to renew the port forwarding if it's expired
            do_port_check_ = true;
            if (auto const now = tr_time(); natpmp_->renewTime() > now)
            {
                timer_->start_single_shot(std::chrono::seconds{ natpmp_->renewTime() - now });
            }
            else // ???
            {
                timer_->start_single_shot(1min);
            }
            break;

        case TR_PORT_ERROR:
            // some kind of an error. wait a minute and retry
            timer_->start_single_shot(1min);
            break;

        default:
            // in progress. pulse frequently.
            timer_->start_single_shot(333ms);
            break;
        }
    }

    void onTimer()
    {
        TR_ASSERT(timer_);

        // do something
        natPulse(do_port_check_);
        do_port_check_ = false;

        // set up the timer for the next pulse
        restartTimer();
    }

    static constexpr char const* getNatStateStr(int state)
    {
        switch (state)
        {
        case TR_PORT_MAPPING:
            return _("Starting");

        case TR_PORT_MAPPED:
            return _("Forwarded");

        case TR_PORT_UNMAPPING:
            return _("Stopping");

        case TR_PORT_UNMAPPED:
            return _("Not forwarded");

        default:
            return "???";
        }
    }

    void natPulse(bool do_check)
    {
        auto const is_enabled = is_enabled_ && !is_shutting_down_;
        auto const bind_interface = tr_net_effective_bind_interface(mediator_.bind_interface());
        auto const is_interface_bound = !std::empty(bind_interface);

        // NAT-PMP's socket is bound to the configured interface when it is created,
        // so start over if the interface changes
        if (!natpmp_ || natpmp_->bind_interface() != bind_interface)
        {
            natpmp_ = std::make_unique<tr_natpmp>(bind_interface);
        }

        // UPnP discovery and the gateway it found belong to the previous interface
        if (upnp_ != nullptr && upnp_bind_interface_ != bind_interface)
        {
            // a disabled pulse releases any mapping and leaves the handle safe to close
            tr_upnpPulse(upnp_, mediator_.advertised_peer_port(), mediator_.local_peer_port(), false, false, {});
            tr_upnpClose(upnp_);
            upnp_ = nullptr;
            upnp_state_ = TR_PORT_UNMAPPED;
        }

        if (upnp_ == nullptr)
        {
            upnp_ = tr_upnpInit();
            upnp_bind_interface_ = bind_interface;
        }

        auto const old_state = state();

        auto const result = natpmp_->pulse(mediator_.local_peer_port(), is_enabled);
        natpmp_state_ = result.state;
        if (!std::empty(result.local_port) && !std::empty(result.advertised_port))
        {
            mediator_.on_port_forwarded(result.advertised_port);
            tr_logAddInfo(
                fmt::format(
                    fmt::runtime(_("Mapped private port {private_port} to public port {public_port}")),
                    fmt::arg("private_port", result.local_port.host()),
                    fmt::arg("public_port", result.advertised_port.host())));
        }

        auto const upnp_is_enabled = is_enabled && (!is_interface_bound || is_upnp_interface_name(bind_interface));
        auto const upnp_bindaddr = is_interface_bound ? std::string{ bind_interface } :
                                                        mediator_.incoming_peer_address().display_name();
        upnp_state_ = tr_upnpPulse(
            upnp_,
            mediator_.advertised_peer_port(),
            mediator_.local_peer_port(),
            upnp_is_enabled,
            do_check,
            upnp_bindaddr);

        if (auto const new_state = state(); new_state != old_state)
        {
            tr_logAddInfo(
                fmt::format(
                    fmt::runtime(_("State changed from '{old_state}' to '{state}'")),
                    fmt::arg("old_state", getNatStateStr(old_state)),
                    fmt::arg("state", getNatStateStr(new_state))));
        }
    }

    Mediator& mediator_;

    bool is_enabled_ = false;
    bool is_shutting_down_ = false;
    bool do_port_check_ = false;

    tr_port_forwarding_state natpmp_state_ = TR_PORT_UNMAPPED;
    tr_port_forwarding_state upnp_state_ = TR_PORT_UNMAPPED;

    tr_upnp* upnp_ = nullptr;
    std::string upnp_bind_interface_;
    std::unique_ptr<tr_natpmp> natpmp_;

    std::unique_ptr<tr::Timer> timer_;
};

std::unique_ptr<tr_port_forwarding> tr_port_forwarding::create(Mediator& mediator)
{
    return std::make_unique<tr_port_forwarding_impl>(mediator);
}
