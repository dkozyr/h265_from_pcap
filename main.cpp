#include "pcap.h"
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
using namespace std;

const vector<char> ANNEX_B = { 0, 0, 0, 1 };
const uint8_t H265_PTYPE = 96; // hard-coded value
const int RTP_OFFSET = 42;  // hard-coded offset to RTP header
const int RTP_PAYLOAD_OFFSET = 54;  // hard-coded offset to RTP payload
const int NAL_UNIT_HEADER_SIZE = sizeof(uint16_t);
const int NAL_UNIT_FU = 49;
const int NAL_UNIT_AP = 48;
const int NAL_UNIT_AP_NALU_SIZE = sizeof(uint16_t);

const uint8_t* rtp_payload(const uint8_t* packet, uint32_t packet_length, uint8_t ptype, uint32_t& payload_length) {
    payload_length = 0;

    if (packet_length <= RTP_PAYLOAD_OFFSET) // check packet size
        return nullptr;
    if ((packet[RTP_OFFSET] >> 6) != 2) // check RFC 1889 version 2
        return nullptr;
    if ((packet[RTP_OFFSET + 1] & 0x7F) != ptype) // check ptype
        return nullptr;

    const bool has_padding = !!(packet[RTP_OFFSET] & 0x20);
    const int padding = has_padding ? static_cast<int>(packet[packet_length - 1]) : 0;

    payload_length = packet_length - RTP_PAYLOAD_OFFSET - padding;
    return &packet[RTP_PAYLOAD_OFFSET];
}

uint16_t read_16bit(const uint8_t* data) {
    return (static_cast<uint16_t>(data[0]) << 8) | data[1];
}

uint32_t read_32bit(const uint8_t* data) {
    return (static_cast<uint32_t>(read_16bit(data)) << 16) | read_16bit(data + 2);
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

    uint32_t packet_count = 0;
    while (pcap)
    {
        struct pcap_pkthdr *header;
        const uint8_t *data;

        if (pcap_next_ex(pcap, &header, &data) < 0)
            break;

        if (header->len != header->caplen)
            cout << "Warning! Capture size different than packet size: " << header->len << " bytes" << endl;

        // cout << "Packet #" << (++packet_count) << ", "
        //      << "size: " << header->len << " bytes, "
        //      << "epoch time: " << header->ts.tv_sec << "." << header->ts.tv_usec << " seconds, "
        //      << endl;

        uint32_t payload_size = 0;
        const uint8_t* payload = rtp_payload(data, header->caplen, H265_PTYPE, payload_size);
        if (payload_size > NAL_UNIT_HEADER_SIZE)
        {
            cout << "RTP seq num: " << read_16bit(data + RTP_OFFSET + 2) << ", ";
            cout << "RTP timestamp: " << read_32bit(data + RTP_OFFSET + 4) << ", ";

            const uint8_t nal_unit_type = (payload[0] & 0x7F) >> 1;
            cout << "nal unit: " << (int)nal_unit_type << ", payload_size: " << payload_size;

            if (nal_unit_type == NAL_UNIT_FU)
            {
                const auto fu_header = payload[2];
                const bool fu_s = !!(fu_header & 0x80);
                const bool fu_e = !!(fu_header & 0x40);
                const auto fu_type = fu_header & 0x3F;
                cout << ", FU: " << (fu_s ? "s" : " ") << (fu_e ? "e" : " ") << " fu_type: " << (int)fu_type;

                if (fu_s)
                {
                    h265file.write(ANNEX_B.data(), 4);

                    vector<uint8_t> nal_unit = {payload[0], payload[1]};
                    nal_unit[0] &= 0x81;
                    nal_unit[0] |= fu_type << 1;
                    h265file.write(reinterpret_cast<const char*>(nal_unit.data()), 2);
                }
                h265file.write(reinterpret_cast<const char*>(&payload[3]), payload_size - 3);
            }
            else if (nal_unit_type == NAL_UNIT_AP)
            {
                cout << ", AP nal units size: ";
                auto offset = NAL_UNIT_HEADER_SIZE;
                while (offset + NAL_UNIT_AP_NALU_SIZE < payload_size)
                {
                    const auto nal_unit_size = read_16bit(payload + offset);
                    cout << nal_unit_size << ", ";
                    if (offset + NAL_UNIT_AP_NALU_SIZE + nal_unit_size > payload_size)
                    {
                        break;
                    }
                    h265file.write(ANNEX_B.data(), 4);
                    h265file.write(reinterpret_cast<const char*>(&payload[offset]), nal_unit_size);
                    offset += NAL_UNIT_AP_NALU_SIZE + nal_unit_size;
                }
                if (offset != payload_size)
                {
                    cout << "malformed!";
                }
            }
            else
            {
                h265file.write(ANNEX_B.data(), 4);
                h265file.write(reinterpret_cast<const char*>(payload), payload_size);
            }
            cout << endl;
        }
    }

    return 0;
}
