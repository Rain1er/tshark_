#include <iostream>
#include <fstream>
#include <vector>

// PCAP全局文件头
struct PcapHeader {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

// 每一个数据报文前面的头
struct PacketHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t caplen;
    uint32_t len;
};

int main(){
    std::ifstream file("/Users/long/code/mycode/tshark_/capture.pcap", std::ios::binary);
    if (!file) {
        std::cerr << "无法打开文件！\n";
        return 0;
    }

    // 读取文件头,指针移动到Frame
    PcapHeader pcapHeader;
    file.read(reinterpret_cast<char*>(&pcapHeader), sizeof(PcapHeader));

    // 循环读取每一个数据报文
    while (file) {

        // 先读取这一个报文的头
        PacketHeader packetHeader;
        file.read(reinterpret_cast<char*>(&packetHeader), sizeof(PacketHeader));

        if (!file) break;   // 读到末尾退出

        // 然后读取这一个报文的内容
        std::vector<unsigned char> data(packetHeader.caplen);
        file.read(reinterpret_cast<char*>(data.data()), packetHeader.caplen);

        printf("数据包[时间：%d  长度：%d]：", packetHeader.ts_sec, packetHeader.caplen);
        for (unsigned char byte : data) {
            printf("%02X ", byte);
        }
        std::cout << "\n";
    }
    file.close();
    return 0;
}