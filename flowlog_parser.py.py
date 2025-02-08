#!/usr/bin/env python3
"""
flowlog_parser.py

This program parses an AWS VPC flow log file (version 2 default format) and applies tags based on a lookup CSV.
It outputs two sections:
  1. Tag Counts – the count of rows that matched each tag (or "Untagged" for no match).
  2. Port/Protocol Combination Counts – the count of occurrences for each port/protocol pair (using the
     destination port and protocol derived from the log record).

Usage:
    python3 flowlog_parser.py <flow_log_file> <lookup_csv_file> [<output_file>]

If <output_file> is not provided, the program writes to "output.txt" in the current directory.
"""

import sys
import csv
from collections import defaultdict

# Standard mapping from protocol number to protocol name.
PROTOCOL_MAP = {
    6: "tcp",
    17: "udp",
    1: "icmp",
    # Add more mappings if needed.
}

class FlowLogParser:
    def __init__(self, flow_log_file, lookup_csv_file):
        """
        初始化时指定流日志文件和查找表CSV文件。
        同时初始化内部数据结构：
          - self.lookup 存储查找映射，键为 (dstport, protocol)
          - self.tag_counts 用于统计每个 tag 的匹配行数
          - self.port_proto_counts 用于统计每个端口/协议组合的出现次数
        """
        self.flow_log_file = flow_log_file
        self.lookup_csv_file = lookup_csv_file
        self.lookup = {}
        self.tag_counts = defaultdict(int)
        self.port_proto_counts = defaultdict(int)
    
    def load_lookup(self):
        """
        加载查找表CSV文件，要求文件中有标题行，列为：dstport,protocol,tag
        其中 dstport 转换为整数，protocol 转为小写以保证不区分大小写。
        """
        with open(self.lookup_csv_file, "r", encoding="ascii") as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                try:
                    port = int(row["dstport"].strip())
                    proto = row["protocol"].strip().lower()
                    tag = row["tag"].strip()
                    self.lookup[(port, proto)] = tag
                except Exception as e:
                    print(f"Skipping lookup row due to error: {e}", file=sys.stderr)
    
    def parse_flow_logs(self):
        """
        处理流日志文件。
        假设日志为 AWS VPC flow log version 2 默认格式，按空格分隔的各字段：
          0: version
          1: account-id
          2: interface-id
          3: srcaddr
          4: dstaddr
          5: srcport
          6: dstport
          7: protocol
          8: packets
          9: bytes
         10: start
         11: end
         12: action
         13: log-status
        根据 (dstport, protocol) 进行查找匹配标签，若无对应则计为 "Untagged"。
        同时统计各端口/协议组合的出现次数。
        """
        with open(self.flow_log_file, "r", encoding="ascii") as infile:
            for line in infile:
                if not line.strip():
                    continue
                fields = line.strip().split()
                if len(fields) < 8:
                    print(f"Skipping malformed line: {line}", file=sys.stderr)
                    continue
                try:
                    # dstport 是第7个字段（索引6），protocol（数字）是第8个字段（索引7）
                    dstport = int(fields[6])
                    proto_num = int(fields[7])
                except ValueError as ve:
                    print(f"Error parsing numeric values in line: {line} ({ve})", file=sys.stderr)
                    continue
                # 将数字协议转换为字符串协议名；若未找到则直接转换为字符串
                proto = PROTOCOL_MAP.get(proto_num, str(proto_num)).lower()
                self.port_proto_counts[(dstport, proto)] += 1
                tag = self.lookup.get((dstport, proto), "Untagged")
                self.tag_counts[tag] += 1

    def write_output(self, output_filename):
        """
        将结果写入输出文件，包括：
          1. Tag Counts – 按标签统计匹配计数
          2. Port/Protocol Combination Counts – 各端口/协议组合的计数
        """
        with open(output_filename, "w", encoding="ascii") as outfile:
            outfile.write("Tag Counts:\n")
            outfile.write("Tag,Count\n")
            for tag in sorted(self.tag_counts.keys()):
                outfile.write(f"{tag},{self.tag_counts[tag]}\n")
            
            outfile.write("\nPort/Protocol Combination Counts:\n")
            outfile.write("Port,Protocol,Count\n")
            for port, proto in sorted(self.port_proto_counts.keys(), key=lambda x: (x[0], x[1])):
                outfile.write(f"{port},{proto},{self.port_proto_counts[(port, proto)]}\n")
    
    def run(self, output_file="output.txt"):
        """
        主流程：加载查找表、解析日志、写入输出文件。
        """
        self.load_lookup()
        self.parse_flow_logs()
        self.write_output(output_file)
        print(f"Output written to {output_file}")

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 flowlog_parser.py <flow_log_file> <lookup_csv_file> [<output_file>]")
        sys.exit(1)
    flow_log_file = sys.argv[1]
    lookup_csv_file = sys.argv[2]
    output_file = sys.argv[3] if len(sys.argv) > 3 else "output.txt"
    
    parser = FlowLogParser(flow_log_file, lookup_csv_file)
    parser.run(output_file)

if __name__ == "__main__":
    main()
