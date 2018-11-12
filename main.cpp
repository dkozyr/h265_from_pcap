#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <fstream>
#include "pcap.h"
using namespace std;

const vector<char> ANNEX_B = { 0, 0, 0, 1 };
const char H265_PTYPE = 96; // hard-coded value
const int RTP_OFFSET = 42;  // hard-coded offset to RTP header
const int RTP_PAYLOAD_OFFSET = 54;  // hard-coded offset to RTP payload
const int NAL_UNIT_FU = 49;

const u_char* rtp_payload(const u_char* packet, u_int packet_lenth, char ptype, u_int& payload_length) {
    payload_length = 0;

    if (packet_lenth <= RTP_PAYLOAD_OFFSET) // check packet size
        return nullptr;
    if ((packet[RTP_OFFSET] >> 6) != 2) // check RFC 1889 version 2
        return nullptr;
    if ((packet[RTP_OFFSET + 1] & 0x7F) != ptype) // check ptype
        return nullptr;

    const bool has_padding = !!(packet[RTP_OFFSET] & 0x20);
    const int padding = has_padding ? static_cast<int>(packet[packet_lenth - 1]) : 0;

    payload_length = packet_lenth - RTP_PAYLOAD_OFFSET - padding;
    return &packet[RTP_PAYLOAD_OFFSET];
}

int main(int argc, char *argv[]) {
    string file;
    if (argc >= 2)
    {
        // read parameter: full path to .pcap file
        file = string(argv[1]);
    }
    cout << file << endl;

    ofstream h265file;
    h265file.open("video.h265", ios::out | ios::binary);

    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_offline(file.c_str(), errbuff);

    u_int packet_count = 0;
    while (pcap)
    {
        struct pcap_pkthdr *header;
        const u_char *data;

        if (pcap_next_ex(pcap, &header, &data) < 0)
            break;

        // Show a warning if the length captured is different
        if (header->len != header->caplen)
            cout << "Warning! Capture size different than packet size: " << header->len << " bytes" << endl;

        /*
        // Show the packet number
        cout << "Packet #" << (++packet_count) << endl;

        // Show the size in bytes of the packet
        cout << "Packet size: " << header->len << " bytes" << endl;

        // Show Epoch Time
        cout << "Epoch Time: " << header->ts.tv_sec << ":" << header->ts.tv_usec << " seconds" << endl;
        */

        u_int payload_size = 0;
        const u_char* payload = rtp_payload(data, header->caplen, H265_PTYPE, payload_size);
        if (payload_size)
        {
            const int nal_unit_type = (payload[0] & 0x7F) >> 1;
            cout << "nal unit: " << nal_unit_type << ", payload_size: " << payload_size << " ";

            if (nal_unit_type == NAL_UNIT_FU)
            {
                const char fu_header = payload[2];
                const bool fu_s = !!(fu_header & 0x80);
                const bool fu_e = !!(fu_header & 0x40);
                const char fu_type = fu_header & 0x3F;
                cout << "FU : " << fu_s << " " << fu_e << " " << (int)fu_type;

                if (fu_s)
                {
                    h265file.write(ANNEX_B.data(), 4);

                    const vector<char> nal_unit = { fu_type << 1, 1 }; // very simple implementation
                    h265file.write(nal_unit.data(), 2);
                }
                h265file.write(reinterpret_cast<const char*>(&payload[3]), payload_size - 3);
            }
            else
            {
                h265file.write(ANNEX_B.data(), 4);
                h265file.write(reinterpret_cast<const char*>(payload), payload_size);
            }
            cout << endl;
        }
    }

    system("pause");
    return 0;
}

