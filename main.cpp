#include <iostream>
#include <stdio.h>
#include <vector>
#include <sstream>
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"

// 设计思路： 获得每行的输出，封装成一个对象，使用rapidjson转成json格式
//221     Feb 19, 2025 13:03 : 36.279927000 中国标准时间    192.168.0.197   64502   180.188.47.51   17008   TCP     64502 → 17008[SYN] Seq = 0 Win = 64240 Len = 0 MSS = 1460 WS = 256 SACK_PERM
//222     Feb 19, 2025 13 : 03 : 36.301429000 中国标准时间                                                  ARP     Gratuitous ARP for 192.168.100.1 (Request)

struct Packet {
    int frame_number;			// 数据包编号
    std::string time;			// 数据包的时间戳
    std::string src_ip;			// 源IP地址
    std::string src_port;       // 源端口
    std::string dst_ip;			// 目的IP地址
    std::string dst_port;       // 目的端口
    std::string protocol;		// 协议
    std::string info;			// 数据包的概要信息
};

// 将tshark的输出封装为Packet对象
void parseLine(std::string line, Packet &packet);
void printPacket(const Packet &packet);

int main()
{

    const char* command = "tshark -r /tmp/capture.pcap -T fields -e frame.number -e frame.time -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e _ws.col.Protocol -e _ws.col.Info";
    FILE* pipe = popen(command, "r");

    if (!pipe) {
        std::cerr << "Failed to run tshark command!" << std::endl;
        return 1;
    }

    std::vector<Packet> packets;

    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        Packet packet;
        parseLine(buffer, packet);
        packets.push_back(packet);
    }
    pclose(pipe);


    for (auto &p : packets) {
        printPacket(p);
    }

    return 0;
}

// 把每一行的输出封装成一个对象
void parseLine(std::string line, Packet &packet) {

    if (line.back() == '\n') {
        line.pop_back();
    }
    std::stringstream ss(line);
    std::string field;
    std::vector<std::string> fields;

    while (std::getline(ss, field, '\t')) {  // tshark输出的字段用 tab 分隔
        fields.push_back(field);
    }

    // only judge size is ok
    if (fields.size()) {
        packet.frame_number = std::stoi(fields[0]); // The stoi() is a standard library function that turns a string into an integer
        packet.time = fields[1];
        packet.src_ip = fields[2];
        packet.src_port = fields[3];
        packet.dst_ip = fields[4];
        packet.dst_port = fields[5];
        packet.protocol = fields[6];
        packet.info = fields[7];

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
    pktObj.AddMember("src_port", rapidjson::Value(packet.src_port.c_str(), allocator), allocator);
    pktObj.AddMember("dst_ip", rapidjson::Value(packet.dst_ip.c_str(), allocator), allocator);
    pktObj.AddMember("dst_port", rapidjson::Value(packet.dst_port.c_str(), allocator), allocator);
    pktObj.AddMember("protocol", rapidjson::Value(packet.protocol.c_str(), allocator), allocator);
    pktObj.AddMember("info", rapidjson::Value(packet.info.c_str(), allocator), allocator);

    // 序列化为 JSON 字符串
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    pktObj.Accept(writer);

    // 打印JSON输出
    std::cout << buffer.GetString() << std::endl;
}