// port-sentinel.cpp
// High-performance C++ network connection anomaly detector and triage tool
// Inspired by Kaite's security toolkit (net-pulse, GuardAIn, logsentinel)

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <set>
#include <map>
#include <cassert>

struct ConnectionRecord {
    std::string protocol;
    std::string local_address;
    int local_port;
    std::string remote_address;
    int remote_port;
    std::string state;
    int pid;
    std::string process_name;
};

struct TriageAlert {
    std::string severity;
    std::string description;
    ConnectionRecord connection;
};

class PortSentinel {
private:
    std::set<int> trusted_listening_ports;
    std::set<int> high_risk_ports = {4444, 1337, 31337, 6666, 23, 445};

public:
    PortSentinel() {
        trusted_listening_ports = {80, 443, 22, 53, 3000, 8080};
    }

    void add_trusted_port(int port) {
        trusted_listening_ports.insert(port);
    }

    bool parse_line(const std::string& line, ConnectionRecord& out_record) {
        if (line.empty() || line[0] == '#' || line[0] == '-') return false;
        
        std::istringstream iss(line);
        std::string proto, local, remote, state, pid_proc;
        
        if (!(iss >> proto >> local >> remote >> state >> pid_proc)) {
            return false;
        }

        out_record.protocol = proto;

        auto last_colon = local.find_last_of(':');
        if (last_colon == std::string::npos) return false;
        out_record.local_address = local.substr(0, last_colon);
        try {
            out_record.local_port = std::stoi(local.substr(last_colon + 1));
        } catch (...) {
            return false;
        }

        last_colon = remote.find_last_of(':');
        if (last_colon == std::string::npos) return false;
        out_record.remote_address = remote.substr(0, last_colon);
        try {
            out_record.remote_port = std::stoi(remote.substr(last_colon + 1));
        } catch (...) {
            out_record.remote_port = 0;
        }

        out_record.state = state;

        auto colon_pos = pid_proc.find(':');
        if (colon_pos != std::string::npos) {
            try {
                out_record.pid = std::stoi(pid_proc.substr(0, colon_pos));
            } catch (...) {
                out_record.pid = 0;
            }
            out_record.process_name = pid_proc.substr(colon_pos + 1);
        } else {
            try {
                out_record.pid = std::stoi(pid_proc);
            } catch (...) {
                out_record.pid = 0;
            }
            out_record.process_name = "unknown";
        }

        return true;
    }

    std::vector<TriageAlert> analyze(const std::vector<std::string>& log_lines) {
        std::vector<TriageAlert> alerts;

        for (const auto& line : log_lines) {
            ConnectionRecord conn;
            if (!parse_line(line, conn)) continue;

            if (high_risk_ports.count(conn.local_port) || high_risk_ports.count(conn.remote_port)) {
                alerts.push_back({
                    "HIGH",
                    "Activity detected on known high-risk / backdoor port (" + std::to_string(std::max(conn.local_port, conn.remote_port)) + ")",
                    conn
                });
            }

            if (conn.state == "LISTENING" && !trusted_listening_ports.count(conn.local_port)) {
                alerts.push_back({
                    "MEDIUM",
                    "Untrusted listening port detected (" + std::to_string(conn.local_port) + ") by process " + conn.process_name,
                    conn
                });
            }

            if (conn.state == "ESTABLISHED" && conn.remote_port == 23) {
                alerts.push_back({
                    "HIGH",
                    "Unencrypted Telnet connection established with remote host",
                    conn
                });
            }
        }

        return alerts;
    }

    void print_report(const std::vector<TriageAlert>& alerts) {
        std::cout << "=== PORT-SENTINEL SECURITY TRIAGE REPORT ===\n";
        std::cout << "Total Anomalies Detected: " << alerts.size() << "\n\n";

        for (size_t i = 0; i < alerts.size(); ++i) {
            const auto& alert = alerts[i];
            std::cout << "[" << (i + 1) << "] SEVERITY: " << alert.severity << "\n";
            std::cout << "    Description : " << alert.description << "\n";
            std::cout << "    Protocol    : " << alert.connection.protocol << "\n";
            std::cout << "    Local       : " << alert.connection.local_address << ":" << alert.connection.local_port << "\n";
            std::cout << "    Remote      : " << alert.connection.remote_address << ":" << alert.connection.remote_port << "\n";
            std::cout << "    State       : " << alert.connection.state << "\n";
            std::cout << "    Process     : " << alert.connection.process_name << " (PID: " << alert.connection.pid << ")\n";
            std::cout << "--------------------------------------------------\n";
        }
    }
};

void run_tests() {
    PortSentinel sentinel;

    ConnectionRecord rec;
    bool success = sentinel.parse_line("TCP 127.0.0.1:8080 0.0.0.0:0 LISTENING 1234:python.exe", rec);
    assert(success);
    assert(rec.protocol == "TCP");
    assert(rec.local_address == "127.0.0.1");
    assert(rec.local_port == 8080);
    assert(rec.state == "LISTENING");
    assert(rec.pid == 1234);
    assert(rec.process_name == "python.exe");

    std::vector<std::string> sample_logs = {
        "TCP 0.0.0.0:80 0.0.0.0:0 LISTENING 800:nginx",
        "TCP 0.0.0.0:4444 0.0.0.0:0 LISTENING 9999:nc",
        "TCP 192.168.1.50:52100 203.0.113.5:23 ESTABLISHED 4512:telnet"
    };

    auto alerts = sentinel.analyze(sample_logs);
    std::cout << "Debug sample_logs alerts size: " << alerts.size() << "\n";
    assert(alerts.size() == 4);
    assert(alerts[0].severity == "HIGH");

    std::cout << "[+] All PortSentinel unit tests passed successfully!\n";
}

int main(int argc, char* argv[]) {
    if (argc > 1 && std::string(argv[1]) == "--test") {
        run_tests();
        return 0;
    }

    std::cout << "PortSentinel C++ Security Triage Tool\n";
    std::cout << "Running built-in verification suite...\n";
    run_tests();

    std::cout << "\nAnalyzing sample connection telemetry...\n";
    PortSentinel sentinel;
    std::vector<std::string> live_sample = {
        "TCP 0.0.0.0:22 0.0.0.0:0 LISTENING 512:sshd",
        "TCP 127.0.0.1:9050 0.0.0.0:0 LISTENING 3333:tor",
        "TCP 0.0.0.0:31337 0.0.0.0:0 LISTENING 777:backdoor",
        "TCP 192.168.1.105:49152 198.51.100.2:443 ESTABLISHED 1042:firefox"
    };

    auto alerts = sentinel.analyze(live_sample);
    sentinel.print_report(alerts);

    return 0;
}
