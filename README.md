# Reference For flowlog_parser

## Assumptions
1. flowlog_parser supports default log format, not custom and the only version that is supported is 2.
2. flowlog_parser only support lookup_table.csv with first line is "dstport,protocol,tag", and is not blankspace tolarent.
3. For convenience, here we only use some of most common used protocol, add more protocol if needed.
    ```
    6: "tcp",
    17: "udp",
    1: "icmp",
    ```
4. Usage: Python 3.12.4
        ```
        python3 flowlog_parser.py <flow_log_file> <lookup_csv_file> [<output_file>]
        ```
## AWS Flow records2 (version)
https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-records-examples.html

a sample log entry is: 
```
[2 123456789012 eni-abc123de 10.0.0.1 198.51.100.1 12345 80 6 10 840 1620140761 1620140821 ACCEPT OK]
```
```
index 0 is the version number (2)
index 1 is the account id
index 2 is the interface id
index 3 is the source address
index 4 is the destination address
index 5 is the source port
index 6 is the destination port
index 7 is the protocol (map to protocol number)
index 8 is the packet count
index 9 is the byte count
index 10 is the start time
index 11 is the end time
index 12 is the action
index 13 is the log status
```

## Portocol number to name mapping
https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

## Lookup table format
```
    ["dst_port","protocol"],
    "tag"
```
