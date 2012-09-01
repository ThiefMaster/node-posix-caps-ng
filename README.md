This is a node.js module that provides libcap-ng bindings to modify the
capabilities of the current process.

The most likely use for this is obviously setting `CAP_NET_BIND_SERVICE`
to enable binding to privileged ports such as 80 or 443.

To use a capability this the user running the program needs to have the
capability, too. This can be achieved by using `pam_cap` and granting the
capability via the `/etc/security/capability.conf` file.
