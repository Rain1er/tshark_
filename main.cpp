#include <iostream>
#include <stdio.h>
#include <vector>
#include <sstream>
#include <fstream>
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"

// 设计思路： 获得每行的输出，封装成一个对象，使用rapidjson转成json格式.
struct Packet {
    int frame_number;
    std::string time;
    uint32_t cap_len;   // 数据包长度的字段cap_len
    std::string src_ip;
    uint16_t src_port;
    std::string dst_ip;
    uint16_t dst_port;
    std::string protocol;
    std::string info;
    uint32_t file_offset;   // 数据包在PCAP文件中的偏移
};

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


// 将tshark的输出封装为Packet对象
bool parseLine(std::string line, Packet &packet);
void printPacket(const Packet &packet);
bool readPacketHex(const std::string& filePath, uint32_t offset, uint32_t length, std::vector<unsigned char> &buffer);


int main(){
    std::string packet_file = "/Users/long/code/mycode/tshark_/capture.pcap";
    std::string command = "/Applications/Wireshark.app/Contents/MacOS/tshark -r " + packet_file +
                          " -T fields -e frame.number -e frame.time -e frame.cap_len -e ip.src -e ipv6.src -e ip.dst -e ipv6.dst -e tcp.srcport -e udp.srcport -e tcp.dstport -e udp.dstport -e _ws.col.Protocol -e _ws.col.Info";
    FILE *pipe = popen(command.c_str(), "r");

    if (!pipe) {
        std::cerr << "Failed to run tshark command!" << std::endl;
        return 1;
    }

    std::vector<Packet> packets;

    char buffer[4096];
    uint32_t file_offset = sizeof(PcapHeader);      // 当前处理的报文在文件中的偏移，第一个报文的偏移就是全局文件头24(也就是sizeof(PcapHeader))字节
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        Packet packet;

        if(parseLine(buffer, packet)){
            // 计算当前报文的偏移，然后记录在Packet对象中
            packet.file_offset = file_offset + sizeof(PacketHeader);

            // 更新偏移游标，指向下一个PacketHeader
            file_offset = file_offset + sizeof(PacketHeader)  + packet.cap_len;

            packets.push_back(packet);
        }else{
            assert(false); // 通过一个断言，走到这里方便排错
        }


    }
    pclose(pipe);


    for (auto &p: packets) {
        printPacket(p);

        // 读取这个报文的原始十六进制数据
        // 向量（Vector）是一个封装了动态大小数组的顺序容器（Sequence Container）。跟任意其它类型容器一样，它能够存放各种类型的对象
        std::vector<unsigned char> buffer;
        readPacketHex(packet_file, p.file_offset, p.cap_len, buffer);

         //打印读取到的数据：
        printf("Packet Hex: ");
        for (unsigned char byte : buffer) {
            printf("%02X ", byte);
        }
        printf("\n\n");
    }

    return 0;
}

// 把每一行的输出封装成一个对象
bool parseLine(std::string line, Packet& packet) {

    if (line.back() == '\n') {
        line.pop_back();
    }
    std::stringstream ss(line);
    std::string field;
    std::vector<std::string> fields;

    // 自己实现字符串拆分
    size_t start = 0, end;
    while ((end = line.find('\t', start)) != std::string::npos) {
        fields.push_back(line.substr(start, end - start));
        start = end + 1;
    }
    fields.push_back(line.substr(start)); // 添加最后一个子串

    // 字段顺序：-e frame.number -e frame.time -e frame.cap_len -e ip.src -e ipv6.src -e ip.dst -e ipv6.dst
    // -e tcp.srcport -e udp.srcport -e tcp.dstport -e udp.dstport -e _ws.col.Protocol -e _ws.col.Info
    // 0: frame.number
    // 1: frame.time
    // 2: frame.cap_len
    // 3: ip.src
    // 4: ipv6.src
    // 5: ip.dst
    // 6: ipv6.dst
    // 7: tcp.srcport
    // 8: udp.srcport
    // 9: tcp.dstport
    // 10: udp.dstport
    // 11: _ws.col.Protocol
    // 12: _ws.col.Info

    if (fields.size() >= 13) {
        packet.frame_number = std::stoi(fields[0]);
        packet.time = fields[1];
        packet.cap_len = std::stoi(fields[2]);
        packet.src_ip = fields[3].empty() ? fields[4] : fields[3];
        packet.dst_ip = fields[5].empty() ? fields[6] : fields[5];
        if (!fields[7].empty() || !fields[8].empty()) {
            packet.src_port = std::stoi(fields[7].empty() ? fields[8] : fields[7]);
        }

        if (!fields[9].empty() || !fields[10].empty()) {
            packet.dst_port = std::stoi(fields[9].empty() ? fields[10] : fields[9]);
        }
        packet.protocol = fields[11];
        packet.info = fields[12];
        return true;
    }
    else {
        printf("error!\n");
        return false;
    }
}

void printPacket(const Packet &packet) {

    // 构建JSON对象
    rapidjson::Document pktObj;
    rapidjson::Document::AllocatorType &allocator = pktObj.GetAllocator();

    // 设置JSON为Object对象类型
    pktObj.SetObject();

    // 添加JSON字段
    pktObj.AddMember("frame_number", packet.frame_number, allocator);   // 整数可以直接传
    pktObj.AddMember("time", rapidjson::Value(packet.time.c_str(), allocator), allocator); // 字符串需要用Value()函数
    pktObj.AddMember("src_ip", rapidjson::Value(packet.src_ip.c_str(), allocator), allocator);
    pktObj.AddMember("src_port", packet.src_port, allocator);
    pktObj.AddMember("dst_ip", rapidjson::Value(packet.dst_ip.c_str(), allocator), allocator);
    pktObj.AddMember("dst_port", packet.dst_port, allocator);
    pktObj.AddMember("protocol", rapidjson::Value(packet.protocol.c_str(), allocator), allocator);
    pktObj.AddMember("info", rapidjson::Value(packet.info.c_str(), allocator), allocator);
    pktObj.AddMember("file_offset", packet.file_offset, allocator);
    pktObj.AddMember("cap_len", packet.cap_len, allocator);

    // 序列化为 JSON 字符串
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    pktObj.Accept(writer);

    // 打印JSON输出
    std::cout << buffer.GetString() << std::endl;
}

// 根据指定的偏移和长度，读取指定文件的数据到一个vector容器中
bool readPacketHex(const std::string &filePath, uint32_t offset, uint32_t length, std::vector<unsigned char> &buffer){
    std::ifstream file(filePath, std::ios::binary);
    if(!file){
        std::cerr << "无法打开文件！\n";
        return false;
    }
    // 将文件指针移动到指定的偏移位置
    file.seekg(offset, std::ios::beg);

    // 读取指定长度的数据到 buffer 中
    buffer.resize(length);
    file.read(reinterpret_cast<char*>(buffer.data()), length);

    file.close();
    return true;
}