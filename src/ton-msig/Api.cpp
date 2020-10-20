#include "Api.hpp"

#ifdef MSIG_WITH_API

#include <res/config.h>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/config.hpp>

#include "App.hpp"

namespace app
{
namespace beast = boost::beast;
namespace http = beast::http;

namespace mime_type
{
constexpr auto application_json = "application/json";

}  // namespace mime_type

namespace http_error
{
#define DEFINE_ERROR(var) constexpr auto var = #var;

DEFINE_ERROR(unknown_http_body)
}  // namespace http_error

namespace
{
template <typename B, class Body, class Allocator>
auto make_response(const http::request<Body, http::basic_fields<Allocator>>& req, http::status status) -> http::response<B>
{
    http::response<B> res{status, req.version()};
    res.set(http::field::server, PROJECT_NAME);
    res.set(http::field::content_type, mime_type::application_json);
    res.keep_alive(req.keep_alive());
    return res;
}
}  // namespace

class SessionActor final : public td::actor::Actor {
public:
    explicit SessionActor(td::actor::ActorShared<> parent, tcp::socket&& socket)
        : parent_{std::move(parent)}
        , socket_{std::move(socket)}
    {
    }

private:
    void start_up() final { tick(); }

    void finish(td::Status status)
    {
        if (status.is_error()) {
            LOG(ERROR) << status;
        }
        socket_.shutdown(tcp::socket::shutdown_send, ec_);
        stop();
    }

    void tick()
    {
        http::request<http::string_body> req;

        http::read(socket_, buffer_, req, ec_);
        if (ec_ == http::error::end_of_stream) {
            return finish(td::Status::OK());
        }
        else if (ec_) {
            return finish(td::Status::Error(ec_.message()));
        }

        handle_request(std::move(req));

        if (ec_) {
            return finish(td::Status::Error(ec_.message()));
        }
        if (close_) {
            return finish(td::Status::OK());
        }

        td::actor::send_closure(actor_id(this), &SessionActor::tick);
    }

    template <bool isRequest, class Body, class Fields>
    void send(http::message<isRequest, Body, Fields>&& msg)
    {
        close_ = msg.need_eof();
        http::serializer<isRequest, Body, Fields> sr{msg};
        http::write(socket_, sr, ec_);
    }

    template <class Body, class Allocator>
    auto bad_request(const http::request<Body, http::basic_fields<Allocator>>& req, beast::string_view why)
    {
        auto res = make_response<http::string_body>(req, http::status::bad_request);
        res.body() = R"({"error":")" + std::string{why} + "\"}";
        res.prepare_payload();
        return res;
    }

    template <class Body, class Allocator>
    auto not_found(const http::request<Body, http::basic_fields<Allocator>>& req)
    {
        auto res = make_response<http::empty_body>(req, http::status::not_found);
        res.prepare_payload();
        return res;
    }

    template <class Body, class Allocator>
    auto server_error(const http::request<Body, http::basic_fields<Allocator>>& req, beast::string_view what)
    {
        auto res = make_response<http::string_body>(req, http::status::internal_server_error);
        res.body() = "An error occurred: '" + std::string(what) + "'";
        res.prepare_payload();
        return res;
    }

    template <class Body, class Allocator>
    void handle_request(http::request<Body, http::basic_fields<Allocator>>&& req)
    {
        switch (req.method()) {
            case http::verb::head: {
                auto res = make_response<http::empty_body>(req, http::status::ok);
                return send(std::move(res));
            }
            case http::verb::get: {
                auto res = make_response<http::empty_body>(req, http::status::ok);
                return send(std::move(res));
            }
            default: {
                return send(bad_request(req, http_error::unknown_http_body));
            }
        }
    }

    td::actor::ActorShared<> parent_;
    tcp::socket socket_;

    beast::flat_buffer buffer_{};
    bool close_{};
    beast::error_code ec_{};
};

Api::Api(td::actor::ActorShared<App> parent, td::int16 port)
    : parent_{std::move(parent)}
{
    const auto address = net::ip::make_address("127.0.0.1");
}

void Api::start_up()
{
    Actor::start_up();
}

void Api::tear_down()
{
    Actor::tear_down();
}

void Api::tick()
{
}

}  // namespace app

#endif
