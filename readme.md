# Parser H.265 video stream from pcap sample file

Simple parser with a lot of hard-coded values. Sample pcap file with H.265 video stream:

https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=1920x1080_H.265.pcapng

Note: you must covert it to .pcap file (not .pcapng) using Wireshark

**UPDATE**: This project is a *limited* example of RTP H.265 depacketization. A full implementation with tests can be found in [Tau WebRTC streaming library](https://github.com/dkozyr/tau), along with a usage example in the [pcap-parser](https://github.com/dkozyr/tau/tree/main/apps/pcap-parser) tool

## Usefull links

1. How to read a PCap file from Wireshark with C++

   https://www.rhyous.com/2011/11/13/how-to-read-a-pcap-file-from-wireshark-with-c/

2. H.265 payload structure (RFC-7798)

   https://tools.ietf.org/html/rfc7798#section-4.4

