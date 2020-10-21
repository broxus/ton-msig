#pragma once

#ifdef MSIG_WITH_API

#include <td/actor/actor.h>

#include <boost/asio/ip/tcp.hpp>

namespace app
{
namespace net = boost::asio;
using tcp = boost::asio::ip::tcp;

class App;

class Api final : public td::actor::Actor {
public:
    constexpr static td::Slice actor_name = "Api";

    Api(td::actor::ActorShared<App> parent, td::uint16 port);

private:
    void start_up() final;
    void tear_down() final;
    void hangup_shared() final;

    void tick();

    net::io_context ioc_;
    tcp::acceptor acceptor_;

    td::actor::ActorShared<App> parent_;

    std::map<td::int64, td::actor::ActorOwn<>> actors_;
    td::int64 actor_id_{1};
};

}  // namespace app

#endif
