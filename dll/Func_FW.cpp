#include "pch.h"
#include "Func_FW.h"


// Функция для остановки sniffer
void stopSniffing() {
    pcap_breakloop(handle);  // Останавливаем цикл захвата пакетов
}

std::vector<std::string> list_device() {
    pcap_if_t* allDevs;
    pcap_if_t* dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    std::vector<std::string> devices;

    // Получаем все доступные устройства
    if (pcap_findalldevs(&allDevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return devices;
    }

    // Проверяем, есть ли устройства
    if (!allDevs) {
        std::cout << "No devices found!" << std::endl;
        return devices;
    }

    // Добавляем имена устройств в вектор
    for (dev = allDevs; dev; dev = dev->next) {
        devices.emplace_back(dev->name);
    }

    // Освобождаем память после работы с устройствами
    pcap_freealldevs(allDevs);

    return devices;
}

// Обработчик пакетов
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

        // Формируем строку для передачи в обратный вызов
        std::string packetInfo = "IP Source: " + std::string(srcIp) + " -> Destination: " + std::string(destIp) +
            " Protocol: " + protocol + " Size: " + std::to_string(ntohs(ipHeader->tlen)) + " bytes\n";

        // Вызываем callback для передачи данных
        TrafficCallback callback = reinterpret_cast<TrafficCallback>(userData);
        callback(packetInfo);
    }
}

// Захват трафика с возвратом данных через callback
void monitorDeviceTraffic(const char* deviceName, TrafficCallback callback) {
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(deviceName, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "Error opening device: " << errbuf << std::endl;
        return;
    }
    std::cout << "Listening on " << deviceName << "...\n";

    // Запускаем обработку пакетов с передачей callback
    pcap_loop(handle, 0, packetHandler, reinterpret_cast<u_char*>(callback));

    // Закрываем захват устройства
    pcap_close(handle);

}
