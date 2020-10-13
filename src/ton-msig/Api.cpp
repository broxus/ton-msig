#include "Api.hpp"

#ifdef MSIG_WITH_API

#include "App.hpp"

namespace app
{
namespace
{
enum class Method {
    GET,
    POST,
};

constexpr auto MAX_POST_SIZE = 64u << 10u;

auto url_decode(td::Slice from, bool decode_plus_sign_as_space) -> std::string
{
    td::BufferSlice x{from.size()};
    auto to = x.as_slice();

    size_t to_i = 0;
    for (size_t from_i = 0, n = from.size(); from_i < n; ++from_i) {
        if (from[from_i] == '%' && from_i + 2 < n) {
            int high = td::hex_to_int(from[from_i + 1]);
            int low = td::hex_to_int(from[from_i + 2]);
            if (high < 16 && low < 16) {
                to[to_i++] = static_cast<char>(high * 16 + low);
                from_i += 2;
                continue;
            }
        }

        if (const auto c = from[from_i]; decode_plus_sign_as_space && c == '+') {
            to[to_i] = ' ';
        }

        ++to_i;
    }

    return to.truncate(to_i).str();
}

}  // namespace

class HttpQueryRunner {
public:
    HttpQueryRunner(td::actor::Scheduler* scheduler, std::function<void(td::Promise<MHD_Response*>)> func)
    {
        auto P = td::PromiseCreator::lambda([Self = this](td::Result<MHD_Response*> R) {
            if (R.is_ok()) {
                Self->finish(R.move_as_ok());
            }
            else {
                Self->finish(nullptr);
            }
        });
        mutex_.lock();
        scheduler->run_in_context_external([&]() { func(std::move(P)); });
    }

    void finish(MHD_Response* response)
    {
        response_ = response;
        mutex_.unlock();
    }

    MHD_Response* wait()
    {
        mutex_.lock();
        mutex_.unlock();
        return response_;
    }

private:
    std::function<void(td::Promise<MHD_Response*>)> func_;
    MHD_Response* response_;
    std::mutex mutex_;
};

class HttpRequestExtra {
public:
    HttpRequestExtra(MHD_Connection* connection, Method method)
    {
        if (method == Method::POST) {
            post_processor_ = MHD_create_post_processor(connection, 1u << 14u, reinterpret_cast<MHD_PostDataIterator>(iterate_post), static_cast<void*>(this));
        }
    }
    ~HttpRequestExtra()
    {
        if (post_processor_ != nullptr) {
            MHD_destroy_post_processor(post_processor_);
        }
    }

    [[nodiscard]] auto post_processor() -> MHD_PostProcessor* { return post_processor_; }
    [[nodiscard]] auto options() -> std::map<std::string, std::string> { return options_; }

    static int iterate_post(
        void* connection_info,
        MHD_ValueKind kind,
        const char* key,
        const char* filename,
        const char* content_type,
        const char* transfer_encoding,
        const char* data,
        uint64_t off,
        size_t size)
    {
        auto self = static_cast<HttpRequestExtra*>(connection_info);
        self->total_size += std::strlen(key) + size;
        if (self->total_size > MAX_POST_SIZE) {
            return MHD_NO;
        }
        std::string k = key;
        if (self->options_[k].size() < off + size) {
            self->options_[k].resize(off + size);
        }
        td::MutableSlice{self->options_[k]}.remove_prefix(off).copy_from(td::Slice{data, size});
        return MHD_YES;
    }

private:
    MHD_PostProcessor* post_processor_{};
    std::map<std::string, std::string> options_{};
    td::uint64 total_size{};
};

void Api::start_up()
{
    self_id_ = actor_id(this);
    daemon_ = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, http_port_, nullptr, nullptr, );
}

void Api::tear_down()
{
    if (daemon_) {
        MHD_stop_daemon(daemon_);
        daemon_ = nullptr;
    }
}

void Api::alarm()
{
}

int Api::process_http_request(
    void* /*cls*/,
    struct MHD_Connection* connection,
    const char* url,
    const char* method_name,
    const char* /*version*/,
    const char* upload_data,
    size_t* upload_data_size,
    void** ptr)
{
    MHD_Response* response = nullptr;
    int ret;

    std::map<std::string, std::string> options;
    if (std::strcmp(method_name, "GET") == 0) {
        if (*ptr == nullptr) {
            *ptr = static_cast<void*>(new HttpRequestExtra{connection, Method::GET});
            return MHD_YES;
        }
        if (upload_data_size != nullptr && *upload_data_size != 0) {
            return MHD_NO;
        }
    }
    else if (std::strcmp(method_name, "POST") == 0) {
        if (*ptr == nullptr) {
            *ptr = static_cast<void*>(new HttpRequestExtra{connection, Method::POST});
            return MHD_YES;
        }

        auto extra = static_cast<HttpRequestExtra*>(*ptr);
        if (upload_data_size != nullptr && *upload_data_size != 0) {
            auto post_processor = extra->post_processor();
            CHECK(post_processor)
            MHD_post_process(post_processor, upload_data, *upload_data_size);
            *upload_data_size = 0;
            return MHD_YES;
        }

        options = std::move(extra->options());
    }
    else {
        return MHD_NO;
    }
    *ptr = nullptr;

    std::string_view url_view{url};

    auto pos = url_view.rfind('/');
    std::string prefix, command;
    if (pos == std::string::npos) {
        prefix = "";
        command = url_view;
    }
    else {
        prefix = url_view.substr(0, pos + 1);
        command = url_view.substr(pos + 1);
    }

    MHD_get_connection_values(connection, MHD_GET_ARGUMENT_KIND, reinterpret_cast<MHD_KeyValueIterator>(get_arg_iterate), static_cast<void*>(&options));

    // TODO

    return 0;
}

void Api::request_completed(void* /*cls*/, MHD_Connection* /*connection*/, void** ptr, MHD_RequestTerminationCode /*code*/)
{
    auto extra = static_cast<HttpRequestExtra*>(*ptr);
    delete extra;
}

void Api::get_arg_iterate(void* cls, MHD_ValueKind /*kind*/, const char* key, const char* value)
{
    auto options = static_cast<std::map<std::string, std::string>*>(cls);
    if (key && value && *key > 0 && *value > 0) {
        options->emplace(key, url_decode(td::Slice{value}, false));
    }
}

}  // namespace app

#endif
