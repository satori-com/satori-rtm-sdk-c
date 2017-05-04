#ifndef TEST_CONFIG_H__INCLUDED
#define TEST_CONFIG_H__INCLUDED

#include <string>
#include <fstream>
#include <nlohmann_json/json.hpp>

using json = nlohmann::json;

const char *endpoint = nullptr;
const char *appkey = nullptr;
const char *role_name = nullptr;
const char *role_secret = nullptr;
const char *restricted_channel = nullptr;

void load_credentials(void) {
    try {
        std::ifstream creds_stream("credentials.json");
        std::stringstream buffer;
        buffer << creds_stream.rdbuf();
        json const creds = json::parse(buffer);

        std::string const endpoint_s = creds["endpoint"];
        std::string const appkey_s = creds["appkey"];
        std::string const role_name_s = creds["auth_role_name"];
        std::string const role_secret_s = creds["auth_role_secret_key"];
        std::string const restricted_channel_s = creds["auth_restricted_channel"];

        endpoint = strdup(endpoint_s.c_str());
        appkey = strdup(appkey_s.c_str());
        role_name = strdup(role_name_s.c_str());
        role_secret = strdup(role_secret_s.c_str());
        restricted_channel = strdup(restricted_channel_s.c_str());
    } catch (...) {
        puts("Could not get test credentials from credentials.json");
        throw;
    }
}

#endif // TEST_CONFIG_H__INCLUDED
