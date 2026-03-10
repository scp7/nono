# Task

**Run:** `20260310_183550_632283`
**Branch:** `swarm/job-20260310_183550_632283`
**Repo:** `git@github.com:scp7/nono-copy.git`
**Issue:** `https://github.com/scp7/nono-copy/issues/6`

---

## GitHub Issue: https://github.com/scp7/nono-copy/issues/6

Endpoint Security Entitlement - MacOS

> Imported from https://github.com/always-further/nono/issues/315

### What problem are you trying to solve?

Intercepting I/O events on MacOS and allow users to approve of the I/O event on-demand

### What would you like to see?

I believe we can likely leverage [Endpoint Security](https://developer.apple.com/documentation/endpointsecurity) on MacOS to facilitate intercepting I/O calls and prompting the user to allow/deny. ([sample project](https://developer.apple.com/documentation/EndpointSecurity/monitoring-system-events-with-endpoint-security))

I believe this would get us closer to what is supported out of the box with Linux's [seccomp](https://docs.kernel.org/userspace-api/seccomp_filter.html#userspace-notification) feature.

Right now, this capability doesn't exist through Seatbelt, so the best we can do is be aware that an I/O operation failed and prompt the user to retry or record those failures as part of the existing `learn` command we have.

I believe in order to use Endpoint Security, we have to get an entitlement from Apple. ([request form](https://developer.apple.com/contact/request/system-extension/))

----

I think this would significantly improve the user experience if implemented properly, but it would require the user installing a system extension, so perhaps it could be opt-in? 

Just something for us to think about.  

### What have you tried instead?

I've tried just leveraging Seatbelt on MacOS, but it seems it does not support this type of capability presently.

### How is this blocking you?

None

### Additional context

_No response_

---

assess this
