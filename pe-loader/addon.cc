#include <string>

#include <node_api.h>

#include "Loader.h"

static std::string ValueToString(napi_env env, napi_value value)
{
	size_t length = 0;
	napi_get_value_string_utf8(env, value, nullptr, 0, &length);

	std::string output(length, '\0');
	napi_get_value_string_utf8(env, value, output.data(), length + 1, &length);

	return output;
}

static napi_value RunWrapped(napi_env env, napi_callback_info info)
{
	size_t argc = 2;
	napi_value argv[2];
	napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);

	if (argc < 1)
	{
		napi_throw_type_error(env, nullptr, "run(path, args?) requires at least one argument");
		return nullptr;
	}

	napi_valuetype valueType;
	napi_typeof(env, argv[0], &valueType);
	if (valueType != napi_string)
	{
		napi_throw_type_error(env, nullptr, "path must be a string");
		return nullptr;
	}

	std::string path = ValueToString(env, argv[0]);
	std::string args;

	if (argc >= 2)
	{
		napi_typeof(env, argv[1], &valueType);
		if (valueType != napi_string)
		{
			napi_throw_type_error(env, nullptr, "args must be a string");
			return nullptr;
		}
		args = ValueToString(env, argv[1]);
	}

	if (RunFromFile(path, args) != EXIT_SUCCESS)
	{
		napi_throw_error(env, nullptr, "Failed to load or execute target PE");
		return nullptr;
	}

	napi_value result;
	napi_get_boolean(env, true, &result);
	return result;
}

static napi_value Init(napi_env env, napi_value exports)
{
	napi_value runFn;
	napi_create_function(env, "run", NAPI_AUTO_LENGTH, RunWrapped, nullptr, &runFn);
	napi_set_named_property(env, exports, "run", runFn);
	return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
