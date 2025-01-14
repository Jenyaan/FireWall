#include "Func_FW.h"
#include <windows.h>
#include <fstream>
#include <thread>
#include <atomic>
#include <unordered_map>

#define IOCTL_ADD_RULE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_DEL_RULE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

HWND hStartSniffer, hStopSniffer, hLog, hAddRule, hAddRuleInput, hDelRule, hDelRuleInput, hViewRule;
HINSTANCE hInst; 
HANDLE driverHandle;
LPCTSTR szWindowClass = "QWERTY";
LPCTSTR szTitle = "FireWall";


const std::string fileName = "rule_FW.ini";
std::atomic<bool> is_Sniffing(false);
std::thread snifferThread;

void AddLog(const std::string& message) {
	int len = GetWindowTextLength(hLog);
	SendMessage(hLog, EM_SETSEL, (WPARAM)len, (LPARAM)len);
	SendMessage(hLog, EM_REPLACESEL, 0, (LPARAM)message.c_str());

}

//driver WFP
void InitDriver() {
    driverHandle = CreateFile(
        "\\\\.\\KMDF_ICMP",  // Replace with the actual device name
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    if (driverHandle == INVALID_HANDLE_VALUE) {
        AddLog("Failed to open driver");
    }
}

ULONG SendAddRule(ULONG ipAddress) {
    ULONG filterIdLower;

    DeviceIoControl(
        driverHandle,
        IOCTL_ADD_RULE,
        &ipAddress,
        sizeof(ULONG),
        &filterIdLower, 
        sizeof(filterIdLower),
        0,
        NULL
    );

    return filterIdLower;
}

BOOL SendDelRule(UINT64 filterId) {
    BOOL success = DeviceIoControl(
        driverHandle,
        IOCTL_DEL_RULE,
        &filterId,             
        sizeof(filterId),      
        NULL,                   
        0,                      
        0,                      
        NULL                    
    );
    return success;
}


//Sniffer
void startSnifferThread(const std::string& device) {
	is_Sniffing = true;
	snifferThread = std::thread([device]() {
		monitorDeviceTraffic(device.c_str(), [](const std::string& packetInfo) {
			AddLog(packetInfo);
			});
		});
}

void stopSnifferThread() {
	if (is_Sniffing) {
		is_Sniffing = false;
		stopSniffing();
		AddLog("Stop Sniffer");
		if (snifferThread.joinable()) {
			snifferThread.join();
		}
	}
}

void trafficCallback(const std::string& packetInfo) {
	AddLog(packetInfo);
}

//File

void checkiFile(){
    DWORD dwFileAttrib = GetFileAttributes(fileName.c_str());
    if (dwFileAttrib == INVALID_FILE_ATTRIBUTES) {
        std::ofstream file(fileName);
        if (!file) {
            AddLog("File rule no create!");
        }
        file.close();
        AddLog("File rule create!");
    }
}

std::unordered_map<std::string, ULONG> readIniFile() {
    std::unordered_map<std::string, ULONG> rules;
    std::ifstream file(fileName);

    std::string line;

    while (std::getline(file, line)) {
        size_t pos = line.find(":");  
        if (pos != std::string::npos) {
            std::string ipAddress = line.substr(0, pos);  
            ULONG filterId = std::stoul(line.substr(pos + 1));  

            rules[ipAddress] = filterId;  
        }
    }

    file.close();
    return rules;
}

void addRuleFile(const std::string& rule) {
    if (rule.empty()) {
        MessageBox(NULL, "Input field is empty. Please enter a value.", "Error", MB_OK | MB_ICONERROR);
        return;
    }
    std::unordered_map<std::string, ULONG> rules = readIniFile();
    auto it = rules.find(rule);
    if (it == rules.end()) {
        std::vector<ULONG> ipParts;
        std::string segment;
        size_t start = 0, end;
        ULONG filterIdLower;
        for (size_t i = 0; i < 4; ++i) {
            end = rule.find('.', start);
            if (end == std::string::npos && i < 3) {
                MessageBox(NULL, "Incorrect IP address format.", "Error", MB_OK | MB_ICONERROR);
                return;
            }
            segment = rule.substr(start, end - start);
            ipParts.push_back(std::stoul(segment));
            start = end + 1;
        }
        if (ipParts.size() != 4) {
            MessageBox(NULL, "Incorrect IP address format.", "Error", MB_OK | MB_ICONERROR);
            return;
        }
        ULONG ipAddress = (ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3];

        if (filterIdLower = SendAddRule(ipAddress)) {
            AddLog("Rule added successfully\n");
        }
        else {
            AddLog("Failed to add rule: " + GetLastError());
            return;
        }

        std::ofstream file(fileName, std::ios::app);
        if (!file) {
            checkiFile();
            MessageBox(NULL, "There was a problem", "Error", MB_OK | MB_ICONERROR);
            file.close();
            return;
        }

        file << rule + ":" + std::to_string(filterIdLower) << "\n";
        file.close();
        MessageBox(NULL, "Rule added successfully.", "Information", MB_OK | MB_ICONINFORMATION);
    }
    else {
        MessageBox(NULL, "Rule already exists", "Error", MB_OK | MB_ICONERROR);
    }
}


bool removeRuleFromFile(const std::string& rule) {
    if (rule.empty()) {
        MessageBox(NULL, "Input field is empty. Please enter a value.", "Error", MB_OK | MB_ICONERROR);
        return false;
    }

    std::unordered_map<std::string, ULONG> rules = readIniFile();

    auto it = rules.find(rule);
    if (it == rules.end()) {
        MessageBox(NULL, "Rule not found.", "Error", MB_OK | MB_ICONERROR);
        return false;
    }

    UINT64 filterId = static_cast<UINT64>(it->second);

    if (!SendDelRule(filterId)) {
        MessageBox(NULL, "Error while deleting rule.", "Error", MB_OK | MB_ICONERROR);
    }

    rules.erase(it);

    std::ofstream file(fileName, std::ios::trunc);
    if (!file) {
        MessageBox(NULL, "Failed to open file for writing.", "Error", MB_OK | MB_ICONERROR);
        return false;
    }

    for (const auto& pair : rules) {
        file << pair.first << ":" << pair.second << "\n";
    }

    file.close();

    MessageBox(NULL, "Rule successfully deleted.", "Information", MB_OK | MB_ICONINFORMATION);
    return true;
}


void viewRuleFile() {
    std::unordered_map<std::string, ULONG> rules = readIniFile();

    std::string allRules;
    for (const auto& r : rules) {
        allRules += "IP: " + r.first + " FilterId: " + std::to_string(r.second) + "\n";
    }
    MessageBox(NULL, allRules.c_str(), "All rules", MB_OK | MB_ICONINFORMATION);
}

