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
    Api(td::actor::ActorShared<App> parent, td::int16 port);

private:
    void start_up() final;
    void tear_down() final;

    void tick();

    net::io_context ioc{1};
    tcp::acceptor acceptor_;

    td::actor::ActorShared<App> parent_;
};

}  // namespace app

#endif
