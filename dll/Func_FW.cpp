#include "pch.h"
#include "Func_FW.h"


// ������� ��� ��������� sniffer
void stopSniffing() {
    pcap_breakloop(handle);  // ������������� ���� ������� �������
}

std::vector<std::string> list_device() {
    pcap_if_t* allDevs;
    pcap_if_t* dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    std::vector<std::string> devices;

    // �������� ��� ��������� ����������
    if (pcap_findalldevs(&allDevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return devices;
    }

    // ���������, ���� �� ����������
    if (!allDevs) {
        std::cout << "No devices found!" << std::endl;
        return devices;
    }

    // ��������� ����� ��������� � ������
    for (dev = allDevs; dev; dev = dev->next) {
        devices.emplace_back(dev->name);
    }

    // ����������� ������ ����� ������ � ������������
    pcap_freealldevs(allDevs);

    return devices;
}

// ���������� �������
void packetHandler(u_char* userData, const struct pcap_pkthdr* packetHeader, const u_char* packetData) {
    struct ether_header {
        u_char ether_dhost[6];
        u_char ether_shost[6];
        u_short ether_type;
    };

    const ether_header* ethHeader = (ether_header*)packetData;
    if (ntohs(ethHeader->ether_type) == 0x0800) { // IPv4
        struct ip_header {
            u_char version_ihl;
            u_char tos;
            u_short tlen;
            u_short identification;
            u_short flags_fo;
            u_char ttl;
            u_char proto;
            u_short crc;
            u_char saddr[4];
            u_char daddr[4];
        };

        const ip_header* ipHeader = (ip_header*)(packetData + 14);
        char srcIp[INET_ADDRSTRLEN];
        char destIp[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, ipHeader->saddr, srcIp, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, ipHeader->daddr, destIp, INET_ADDRSTRLEN);

        std::string protocol;
        if (ipHeader->proto == 6) {
            protocol = "TCP";
        }
        else if (ipHeader->proto == 17) {
            protocol = "UDP";
        }
        else {
            protocol = "Other";
        }

        // ��������� ������ ��� �������� � �������� �����
        std::string packetInfo = "IP Source: " + std::string(srcIp) + " -> Destination: " + std::string(destIp) +
            " Protocol: " + protocol + " Size: " + std::to_string(ntohs(ipHeader->tlen)) + " bytes\n";

        // �������� callback ��� �������� ������
        TrafficCallback callback = reinterpret_cast<TrafficCallback>(userData);
        callback(packetInfo);
    }
}

// ������ ������� � ��������� ������ ����� callback
void monitorDeviceTraffic(const char* deviceName, TrafficCallback callback) {
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(deviceName, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "Error opening device: " << errbuf << std::endl;
        return;
    }
    std::cout << "Listening on " << deviceName << "...\n";

    // ��������� ��������� ������� � ��������� callback
    pcap_loop(handle, 0, packetHandler, reinterpret_cast<u_char*>(callback));

    // ��������� ������ ����������
    pcap_close(handle);

}
