#define BUILDING_NODE_EXTENSION
#include <node.h>
#include <cap-ng.h>
#include <bitset>

using namespace v8;

bool CheckCapType(const Handle<Value>& arg, capng_type_t& type, bool multiple = false) {
	if(!arg->IsUint32()) {
		ThrowException(Exception::TypeError(String::New("Invalid captype type")));
		return false;
	}

	uint32_t val = arg->Uint32Value();
	std::bitset<3> bs(val);
	if((uint32_t)bs.to_ulong() != val) {
		ThrowException(Exception::TypeError(String::New("Invalid captype value")));
		return false;
	}
	if(!bs.count() || (!multiple && bs.count() != 1)) {
		ThrowException(Exception::TypeError(String::New("Invalid captype value")));
		return false;
	}

	type = static_cast<capng_type_t>(val);
	return true;
}

bool CheckCap(const Handle<Value>& arg, unsigned int& cap) {
	if(!arg->IsUint32()) {
		ThrowException(Exception::TypeError(String::New("Invalid cap type")));
		return false;
	}

	uint32_t val = arg->Uint32Value();
	if(val > CAP_LAST_CAP) {
		ThrowException(Exception::TypeError(String::New("Invalid cap value")));
		return false;
	}

	cap = static_cast<unsigned int>(val);
	return true;
}

Handle<Value> HaveCapability(const Arguments& args) {
	HandleScope scope;
	if(args.Length() < 2) {
		ThrowException(Exception::TypeError(String::New("Wrong number of arguments")));
		return scope.Close(Undefined());
	}

	unsigned int cap;
	capng_type_t type;
	if(!CheckCap(args[0], cap) || !CheckCapType(args[1], type)) {
		return scope.Close(Undefined());
	}

	return scope.Close(Boolean::New((bool)capng_have_capability(type, cap)));
}

Handle<Value> SetCapability(const Arguments& args) {
	HandleScope scope;
	if(args.Length() < 3) {
		ThrowException(Exception::TypeError(String::New("Wrong number of arguments")));
		return scope.Close(Undefined());
	}

	unsigned int cap;
	capng_type_t type;
	if(!CheckCap(args[0], cap) || !CheckCapType(args[1], type, true) || !args[2]->IsBoolean()) {
		ThrowException(Exception::TypeError(String::New("Wrong arguments")));
		return scope.Close(Undefined());
	}

	capng_act_t action = args[2]->BooleanValue() ? CAPNG_ADD : CAPNG_DROP;

	if(capng_get_caps_process()) {
		ThrowException(Exception::Error(String::New("Could not retrieve current caps")));
		return scope.Close(Undefined());
	}
	if(capng_update(action, type, cap)) {
		ThrowException(Exception::Error(String::New("Could not update caps")));
		return scope.Close(Undefined());
	}
	if(capng_apply(CAPNG_SELECT_BOTH)) {
		return scope.Close(False());
	}
	return scope.Close(True());
}

Handle<Value> ClearCapabilities(const Arguments& args) {
	HandleScope scope;
	capng_clear(CAPNG_SELECT_BOTH);
	if(capng_apply(CAPNG_SELECT_BOTH)) {
		return scope.Close(False());
	}
	return scope.Close(True());
}

Handle<Value> GetCapabilities(const Arguments& args) {
	HandleScope scope;

	if(args.Length() < 1) {
		ThrowException(Exception::TypeError(String::New("Wrong number of arguments")));
		return scope.Close(Undefined());
	}

	capng_type_t type;
	if(!CheckCapType(args[0], type)) {
		return scope.Close(Undefined());
	}

	if(capng_get_caps_process()) {
		ThrowException(Exception::Error(String::New("Could not retrieve current caps")));
		return scope.Close(Undefined());
	}

	char *buf = capng_print_caps_text(CAPNG_PRINT_BUFFER, type);
	if(!buf) {
		ThrowException(Exception::Error(String::New("Could not get cap string")));
		return scope.Close(Undefined());
	}
	Local<String> str = String::New(buf);
	delete buf;
	return scope.Close(str);
}

void Init(Handle<Object> target) {
	// functions
	target->Set(String::NewSymbol("has_cap"), FunctionTemplate::New(HaveCapability)->GetFunction());
	target->Set(String::NewSymbol("set_cap"), FunctionTemplate::New(SetCapability)->GetFunction());
	target->Set(String::NewSymbol("clear_caps"), FunctionTemplate::New(ClearCapabilities)->GetFunction());
	target->Set(String::NewSymbol("get_caps"), FunctionTemplate::New(GetCapabilities)->GetFunction());
	// types
	target->Set(String::NewSymbol("EFFECTIVE"), Uint32::New(CAPNG_EFFECTIVE));
	target->Set(String::NewSymbol("PERMITTED"), Uint32::New(CAPNG_PERMITTED));
	target->Set(String::NewSymbol("INHERITABLE"), Uint32::New(CAPNG_INHERITABLE));
	target->Set(String::NewSymbol("ALL"), Uint32::New(CAPNG_EFFECTIVE | CAPNG_PERMITTED | CAPNG_INHERITABLE));
	// caps
	#define DEFINE_CAP(CAP) target->Set(String::NewSymbol(#CAP), Uint32::New(CAP))
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
