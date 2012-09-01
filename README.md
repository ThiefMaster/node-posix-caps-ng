This is a node.js module that provides libcap-ng bindings to modify the
capabilities of the current process.

The most likely use for this is obviously setting `CAP_NET_BIND_SERVICE`
to enable binding to privileged ports such as 80 or 443.

To use a capability this the user running the program needs to have the
capability, too. This can be achieved by using `pam_cap` and granting the
capability via the `/etc/security/capability.conf` file.

Unfortunately the node binary *also* needs the capability - but only in its
*inheritable* set. Executing `setcap cap_net_bind_service+i /usr/bin/node` as
root does the job.

# Usage:

    var caps = require('posix-caps-ng');
    caps.set_cap(caps.CAP_NET_BIND_SERVICE, caps.EFFECTIVE, true);

If the application does not start any child processes which also need this cap,
it is a good idea to clear it from the *inheritable* set after enabling it and
possibly also removing the cap altogether after binding to the privileged port:

    caps.set_cap(caps.CAP_NET_BIND_SERVICE, caps.ALL, false);

# Functions

* `bool has_cap(cap, type)` - check if the given cap is set
* `bool set_cap(cap, types, set)` - set/remove the given cap
* `bool clear_caps()` - remove all caps
* `string get_caps(type)` - get a string containing all set caps

`type` can be one of `caps.EFFECTIVE`, `caps.PERMITTED`, `caps.INHERITABLE`.
`types` can be any combination (binary OR) of those flags.
