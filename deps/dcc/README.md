daemons-cc
===

daemons-cc is the FreeBSD's congestion control implementation extracted as a userspace library.

At the moment, NewReno and Cubic have been ported.
Since the changes to the modular API is kept minimum, it is anticipated that other algorithms can be ported fairly easily.

Goals
---
* create a congestion control implementation that can be used for QUIC
* retain the modular API provided by mod_cc

Notable Changes
---
Stated below are the differences from the original version found in the FreeBSD kernel.
* adjustments to minimize exposure (e.g., introduction of cc_int.h)
* eliminate dependency on `tcpcb`; values are supplied as arguments to public function (e.g., `cc_ack_received`, `cc_cong_signal`)
* `cc_get_cwnd` to obtain the congestion window size
* new type `CC_FIRST_RTO` to signal first RTO. Exit of recovery mode is signalled using the last argument of `cc_ack_received`.
