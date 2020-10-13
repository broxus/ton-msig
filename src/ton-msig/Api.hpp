#pragma once

#ifdef MSIG_WITH_API

#include <microhttpd.h>
#include <td/actor/actor.h>

namespace app
{
class Api final : public td::actor::Actor {
public:
private:
    void start_up() final;
    void tear_down() final;

    void alarm() final;

    static int process_http_request(
        void* cls,
        MHD_Connection* connection,
        const char* url,
        const char* method_name,
        const char* version,
        const char* upload_data,
        size_t* upload_data_size,
        void** ptr);
    static void request_completed(void* cls, MHD_Connection* connection, void** ptr, MHD_RequestTerminationCode code);
    static void get_arg_iterate(void* cls, MHD_ValueKind kind, const char* key, const char* value);

    td::uint16 http_port_{80};
    MHD_Daemon* daemon_{};
    td::int32 attempt_{};
    td::int32 waiting_{};

    td::actor::ActorId<Api> self_id_;
};

}  // namespace app

#endif
