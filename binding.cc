#include <node.h>
#include <cap-ng.h>
#include <bitset>

using namespace v8;

bool CheckCapType(Isolate *isolate, const Handle<Value>& arg, capng_type_t& type, bool multiple = false) {
	if(!arg->IsUint32()) {
		isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Invalid captype type")));
		return false;
	}

	uint32_t val = arg->Uint32Value();
	std::bitset<3> bs(val);
	if((uint32_t)bs.to_ulong() != val) {
		isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Invalid captype value")));
		return false;
	}
	if(!bs.count() || (!multiple && bs.count() != 1)) {
		isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Invalid captype value")));
		return false;
	}

	type = static_cast<capng_type_t>(val);
	return true;
}

bool CheckCap(Isolate *isolate, const Handle<Value>& arg, unsigned int& cap) {
	if(!arg->IsUint32()) {
		isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Invalid cap type")));
		return false;
	}

	uint32_t val = arg->Uint32Value();
	if(val > CAP_LAST_CAP) {
		isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Invalid cap value")));
		return false;
	}

	cap = static_cast<unsigned int>(val);
	return true;
}

void HaveCapability(const v8::FunctionCallbackInfo<v8::Value>& info) {
	Isolate *isolate = info.GetIsolate();
	if(info.Length() < 2) {
		isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
		return;
	}

	unsigned int cap;
	capng_type_t type;
	if(!CheckCap(isolate, info[0], cap) || !CheckCapType(isolate, info[1], type)) {
		return;
	}

	info.GetReturnValue().Set((bool)capng_have_capability(type, cap));
}

void SetCapability(const v8::FunctionCallbackInfo<v8::Value>& info) {
	Isolate *isolate = info.GetIsolate();
	EscapableHandleScope scope(isolate);
	if(info.Length() < 3) {
		isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
		return;
	}

	unsigned int cap;
	capng_type_t type;
	if(!CheckCap(isolate, info[0], cap) || !CheckCapType(isolate, info[1], type, true) || !info[2]->IsBoolean()) {
		isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong arguments")));
		return;
	}

	capng_act_t action = info[2]->BooleanValue() ? CAPNG_ADD : CAPNG_DROP;

	if(capng_get_caps_process()) {
		isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Could not retrieve current caps")));
		return;
	}
	if(capng_update(action, type, cap)) {
		isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Could not update caps")));
		return;
	}

	bool success = !capng_apply(CAPNG_SELECT_BOTH);
	info.GetReturnValue().Set(success);
}

void ClearCapabilities(const v8::FunctionCallbackInfo<v8::Value>& info) {
	capng_clear(CAPNG_SELECT_BOTH);
	bool success = !capng_apply(CAPNG_SELECT_BOTH);
	info.GetReturnValue().Set(success);
}

void GetCapabilities(const v8::FunctionCallbackInfo<v8::Value>& info) {
	Isolate *isolate = info.GetIsolate();
	EscapableHandleScope scope(isolate);

	if(info.Length() < 1) {
		isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
		return;
	}

	capng_type_t type;
	if(!CheckCapType(isolate, info[0], type)) {
		return;
	}

	if(capng_get_caps_process()) {
		isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Could not retrieve current caps")));
		return;
	}

	char *buf = capng_print_caps_text(CAPNG_PRINT_BUFFER, type);
	if(!buf) {
		isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Could not get cap string")));
		return;
	}
	Local<String> str = String::NewFromUtf8(isolate, buf);
	delete buf;
	info.GetReturnValue().Set(scope.Escape(str));
}

void Init(Handle<Object> target) {
	Isolate *isolate = Isolate::GetCurrent();
	// functions
	target->Set(String::NewFromUtf8(isolate, "has_cap", String::kInternalizedString), FunctionTemplate::New(isolate, HaveCapability)->GetFunction());
	target->Set(String::NewFromUtf8(isolate, "set_cap", String::kInternalizedString), FunctionTemplate::New(isolate, SetCapability)->GetFunction());
	target->Set(String::NewFromUtf8(isolate, "clear_caps", String::kInternalizedString), FunctionTemplate::New(isolate, ClearCapabilities)->GetFunction());
	target->Set(String::NewFromUtf8(isolate, "get_caps", String::kInternalizedString), FunctionTemplate::New(isolate, GetCapabilities)->GetFunction());
	// types
	target->Set(String::NewFromUtf8(isolate, "EFFECTIVE", String::kInternalizedString), Uint32::New(isolate, CAPNG_EFFECTIVE));
	target->Set(String::NewFromUtf8(isolate, "PERMITTED", String::kInternalizedString), Uint32::New(isolate, CAPNG_PERMITTED));
	target->Set(String::NewFromUtf8(isolate, "INHERITABLE", String::kInternalizedString), Uint32::New(isolate, CAPNG_INHERITABLE));
	target->Set(String::NewFromUtf8(isolate, "ALL", String::kInternalizedString), Uint32::New(isolate, CAPNG_EFFECTIVE | CAPNG_PERMITTED | CAPNG_INHERITABLE));
	// caps
	#define DEFINE_CAP(CAP) target->Set(String::NewFromUtf8(isolate, #CAP, String::kInternalizedString), Uint32::New(isolate, CAP))
	DEFINE_CAP(CAP_CHOWN);
	DEFINE_CAP(CAP_DAC_OVERRIDE);
	DEFINE_CAP(CAP_DAC_READ_SEARCH);
	DEFINE_CAP(CAP_FOWNER);
	DEFINE_CAP(CAP_FSETID);
	DEFINE_CAP(CAP_KILL);
	DEFINE_CAP(CAP_SETGID);
	DEFINE_CAP(CAP_SETUID);
	DEFINE_CAP(CAP_SETPCAP);
	DEFINE_CAP(CAP_LINUX_IMMUTABLE);
	DEFINE_CAP(CAP_NET_BIND_SERVICE);
	DEFINE_CAP(CAP_NET_BROADCAST);
	DEFINE_CAP(CAP_NET_ADMIN);
	DEFINE_CAP(CAP_NET_RAW);
	DEFINE_CAP(CAP_IPC_LOCK);
	DEFINE_CAP(CAP_IPC_OWNER);
	DEFINE_CAP(CAP_SYS_MODULE);
	DEFINE_CAP(CAP_SYS_RAWIO);
	DEFINE_CAP(CAP_SYS_CHROOT);
	DEFINE_CAP(CAP_SYS_PTRACE);
	DEFINE_CAP(CAP_SYS_PACCT);
	DEFINE_CAP(CAP_SYS_ADMIN);
	DEFINE_CAP(CAP_SYS_BOOT);
	DEFINE_CAP(CAP_SYS_NICE);
	DEFINE_CAP(CAP_SYS_RESOURCE);
	DEFINE_CAP(CAP_SYS_TIME);
	DEFINE_CAP(CAP_SYS_TTY_CONFIG);
	DEFINE_CAP(CAP_MKNOD);
	DEFINE_CAP(CAP_LEASE);
	DEFINE_CAP(CAP_AUDIT_WRITE);
	DEFINE_CAP(CAP_AUDIT_CONTROL);
	DEFINE_CAP(CAP_SETFCAP);
	DEFINE_CAP(CAP_MAC_OVERRIDE);
	DEFINE_CAP(CAP_MAC_ADMIN);
	DEFINE_CAP(CAP_SYSLOG);
	DEFINE_CAP(CAP_WAKE_ALARM);
}

NODE_MODULE(binding, Init)
