#pragma once
#define _WINSOCKAPI_    
#include <iostream>
#include <pcap.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <vector>
#include <string>
#include <sstream>

// Подключаем библиотеку
#pragma comment(lib, "Ws2_32.lib")

typedef void(*TrafficCallback)(const std::string& packetInfo);
static pcap_t* handle = nullptr; 


#ifdef func_pcap
#define func_pcap __declspec(dllexport)
#else
#define func_pcap __declspec(dllexport)
#endif


func_pcap std::vector<std::string> list_device();
func_pcap void packetHandler(u_char* userData, const struct pcap_pkthdr* packetHeader, const u_char* packetData);
func_pcap void monitorDeviceTraffic(const char* deviceName, TrafficCallback callback);
func_pcap void stopSniffing();