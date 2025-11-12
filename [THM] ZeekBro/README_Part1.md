## 🗓️ Overview

**Room Name:** [ZeekBro](https://tryhackme.com/room/zeekbro)  

**Date:** 2025-11-10

**Difficulty:** Medium

**Category:** PCAP Analysis / Networking / Linux

**Tools Used:** Zeek

**Objective:** Introduction to hands-on network monitoring and threat detection with Zeek (formerly Bro).

  

---

  

## 🎯 Learning Goals

- Introductory knowledge and comfort with a *new to me* network monitoring and analysis tool.

- General network monitoring overview and work with Zeek to investigate captured traffic. 

-  Wireshark tends to be more for detailed, in-depth analysis of individual packets and specific conversations. Zeek is ideal for large-scale analysis and threat hunting, creating logs from which users can quickly identify events.

  
---
 

## 🔍 0. Notes

### Network Monitoring vs Network Security Monitoring
**Network Monitoring** tends to be more geared towards network administrators and doesn't cover in depth analysis and is usually not with the SOC scope. Instead it focuses on IT assets such as:
- availability
- performance
- configuration
- Monitor and visualize network traffic, troubleshooting and root cause analysis.

**Network Security Monitoring** is part of the SOC and is helpful for security analysts/incident responders, security issues within a set of rules, signatures and patterns. Focus is on network anomalies:
- rogue hosts
- encrypted traffic
- suspicious service or port usage
- malicious / suspicious traffic 

## 1. What is ZEEK?
According to Zeek.org Zeek is described as:

> [!NOTE]
> *Zeek is an open-source software platform that generates compact, high-fidelity transaction logs, file content, and fully customizable outputs, providing analysts with actionable data. Whether for a small home office or the largest research and commercial networks, Zeek helps organizations understand how their networks are being used, supporting security, performance, audit, and capacity goals.*
> 
>*With its powerful, network-optimized programming language, vibrant open-source community, and global adoption, Zeek offers the insights needed to tackle the toughest network challenges across enterprise, cloud, and industrial computing environments.*

According to the room, there is a comparison to Snort however I am not familiar with it so I will not speak further on it.

### 1.1 Zeek Architecture
Zeek has two primary layers **Event Engine** and **Policy Script Interpreter**.
**Event Engine**
- This is where the packets are processed.
- Also called the core.
	- Describes the event without focusing on details.
- Divides it into parts such as:
	- Source Address
	- Destination Address
	- Protocol Identification
	- Session Analysis
	- File Extraction
 
**Policy Script Interpreter**
- Where semantic analysis is conducted.
- Describes the event correlations by using Zeek scripts.

### 1.2 Zeek Frameworks
Frameworks provide extended functionality in the scripting layer. This enhances the flexibility and compatibility with other network components. They focus on specific use cases and run with Zeek installation.
**Available Frameworks**
- [Logging](https://docs.zeek.org/en/master/frameworks/logging.html) (The focus of this room)
- [Broker Communication](https://docs.zeek.org/en/master/frameworks/broker.html)
- [Cluster](https://docs.zeek.org/en/master/frameworks/cluster.html)
- [Configuration](https://docs.zeek.org/en/master/frameworks/configuration.html)
- [File Analysis](https://docs.zeek.org/en/master/frameworks/file-analysis.html)
- [Input](https://docs.zeek.org/en/master/frameworks/input.html)
- [Intelligence](https://docs.zeek.org/en/master/frameworks/intel.html)
- [Management](https://docs.zeek.org/en/master/frameworks/management.html)
- [NetControl](https://docs.zeek.org/en/master/frameworks/netcontrol.html)
- [Notice](https://docs.zeek.org/en/master/frameworks/notice.html)
- [Packet Analysis](https://docs.zeek.org/en/master/frameworks/packet-analysis.html)
- [Signature](https://docs.zeek.org/en/master/frameworks/signatures.html)
- [Storage](https://docs.zeek.org/en/master/frameworks/storage.html)
- [Summary](https://docs.zeek.org/en/master/frameworks/sumstats.html)
- [Supervisor](https://docs.zeek.org/en/master/frameworks/supervisor.html)
- [Telemetry Framework](https://docs.zeek.org/en/master/frameworks/telemetry.html)
- [TLS Decryption](https://docs.zeek.org/en/master/frameworks/tls-decryption.html)

### 1.3 Zeek Outputs
Zeek provides 50+ log files under seven categories in areas such as traffic monitoring, intrusion detection, threat hunting and web analytics. Zeek automatically creates logs in the working directory when you process a PCAP file. If run as a service, Zeek will create logs in the default log path `/opt/zeek/logs`.

### 1.4 Working with Zeek
**Useful Commands**
- `-C` Ignores checksum errors
- `-r` Reading option. Read / Process a PCAP file.
- `-v` Version information
- `zeekctl` Opens the ZeekControl Module
	- `status`
	- `start`
	- `stop`

We can run Zeek as a service by entering `sudo zeekctl`. Since we will be needing to use Superuser for majority of this, we can go ahead and run `sudo su` to keep superuser for the duration of the session. This method is not really a best practice, but it is more out of convenience. 

### Part 1 Questions
>[!IMPORTANT]
>What is the installed Zeek instance version number?
>``` 
>zeek -v
>```
Answer [^1]

>[!IMPORTANT]
>What is the version of the ZeekControl module?
>```
>zeekctl
>```
Answer [^2]

>[!IMPORTANT]
>What is the version of the ZeekControl module?
>```
>ls -l . | wc -l
>zeek -C -r sample.pcap
>ls -l . | wc -l
>```
>*Note: The ls commands are not necessary but count the number of files before and then after the command is run. The difference is the answer.*

Answer [^3]

---

## 2 Zeek Logs
Zeek generates logs based on the traffic connection. Every connection generates logs. Zeek is capable of identifying over 50 logs and then categorizing them into 7 categories. These logs are described as "well structured and tab-separated ASCII files." This makes them easy to read and process but still requires effort. Being familiar with networking and protocols will help to correlate logs in an investigation.

Each log has multiple fields, which each hold a different part of the traffic data. Correlation is done through a Unique Identifier (UID) assigned to each session.

The following is taken directly from TryHackMe. I felt it best represented the data.

**Zeek logs in a nutshell**

| Category             | Description                                                              | **Log Files**                                                                                                                                                                                                                                                                                                                      |
| -------------------- | ------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Network              | Network protocol logs.                                                   | _conn.log, dce_rpc.log, dhcp.log, dnp3.log, dns.log, ftp.log, http.log, irc.log, kerberos.log, modbus.log, modbus_register_change.log, mysql.log, ntlm.log, ntp.log, radius.log, rdp.log, rfb.log, sip.log, smb_cmd.log, smb_files.log, smb_mapping.log, smtp.log, snmp.log, socks.log, ssh.log, ssl.log, syslog.log, tunnel.log._ |
| Files                | File analysis result logs.                                               | _files.log, ocsp.log, pe.log, x509.log._                                                                                                                                                                                                                                                                                           |
| NetControl           | Network control and flow logs.                                           | _netcontrol.log, netcontrol_drop.log, netcontrol_shunt.log, netcontrol_catch_release.log, openflow.log._                                                                                                                                                                                                                           |
| Detection            | Detection and possible indicator logs.                                   | _intel.log, notice.log, notice_alarm.log, signatures.log, traceroute.log._                                                                                                                                                                                                                                                         |
| Network Observations | Network flow logs.                                                       | _known_certs.log, known_hosts.log, known_modbus.log, known_services.log, software.log._                                                                                                                                                                                                                                            |
| Miscellaneous        | Additional logs cover external alerts, inputs and failures.              | _barnyard2.log, dpd.log, unified2.log, unknown_protocols.log, weird.log, weird_stats.log._                                                                                                                                                                                                                                         |
| Zeek Diagnostic      | Zeek diagnostic logs cover system messages, actions and some statistics. | _broker.log, capture_loss.log, cluster.log, config.log, loaded_scripts.log, packet_filter.log, print.log, prof.log, reporter.log, stats.log, stderr.log, stdout.log._                                                                                                                                                              |

Awesome poster style cheat sheet: [Corelight Cheatsheet](https://corelight.com/products/zeek-data/)

The files are updated at different frequencies. See the below chart from TryHackMe for futher:

| **Update Frequency** | **Log Name  <br>**   | **Description**                                 |
| -------------------- | -------------------- | ----------------------------------------------- |
| **Daily**            | _known_hosts.log_    | List of hosts that completed TCP handshakes.    |
| **Daily**            | _known_services.log_ | List of services used by hosts.                 |
| **Daily**            | _known_certs.log_    | List of SSL certificates.                       |
| **Daily**            | _software.log_       | List of software used on the network.           |
| **Per Session**      | _notice.log_         | Anomalies detected by Zeek.                     |
| **Per Session**      | _intel.log_          | Traffic contains malicious patterns/indicators. |
| Per Session          | _signatures.log_     | List of triggered signatures.                   |

**Brief log usage primer table**

Here is another way to categorize the logs:

| **Overall Info**     | **Protocol Based** | **Detection**    | **Observation**      |
| -------------------- | ------------------ | ---------------- | -------------------- |
| _conn.log_           | _http.log_         | _notice.log_     | _known_host.log_     |
| _files.log_          | _dns.log_          | _signatures.log_ | _known_services.log_ |
| _intel.log_          | _ftp.log_          | _pe.log_         | _software.log_       |
| _loaded_scripts.log_ | _ssh.log_          | _traceroute.log_ | _weird.log_          |

There are more logs than what is in the table. These logs can vary in importance based on the investigation. They can be categorized prior to starting the investigation to locate the evidence/anomaly easier.

**Overall Info**
- *The goal here is to review the overall connections, shared files, loaded scripts and indicators all at once. This should be the first step in the investigation.*

**Protocol Based**
- *After reviewing the overall traffic and finding the suspicious indicators or if you want to conduct a more thorough investigation, you should focus on a specific protocol. *

**Detection**
- *Use prebuilt or custom scripts and signature outcomes to support your findings by having additional indicators or linked actions.*

**Observation**
- *The summary of the hosts, services, software and unexpected activity statistics will assist in discovering possible missing points and hopefully concluding the investigation.*

### Recall Information
- 1: Zeek logs are *well structured and tab-separated ASCII files*
- 2: Investigating the logs will require command-line tools such as cat, cut, grep, sort, uniq as well as additional tools such as zeek-cut.

### 2.1 **Opening a Zeek log with a text editor and built-in commands**

Simply using `cat` is not good enough to spot the anomalies quickly. Other tools such as ELK and Splunk can be used to visualize data but this room will focus on using and processing logs with a hands-on approach. 

We mentioned `zeek-cut` earlier but didn't explain it well. Zeek-Cut reduces the effort of extracting specific columns from log files. It does this by cutting specific columns from zeek logs. Each log file provides *field names* in the beginning. This is important when using `zeek-cut`. Make sure that you use *fields* and not *types*.

---

#### Part 2 Questions
*Prior to answering the questions, you should first navigate to the correct folder and go into super user for the session.*

```
sudo su
cd Desktop/Exercise-Files/TASK-3/
```

>[!IMPORTANT]
>Investigate the **sample.pcap** file. Investigate the **dhcp.log** file. What is the available hostname?
>``` 
>zeek -C -r sample.pcap
>```
>*This creates the log files*
>```
>cat dhcp.log
>```
>*This will show the data. It is important to note that the correct column name is host_name even though the question asks for hostname*
>```
>cat dhcp.log | zeek-cut host_name
>```

#### Answer [^4]

---

> [!IMPORTANT]
>Investigate the dns.log file. What is the number of unique DNS queries?
>```
>cat dns.log | zeek-cut query | uniq | wc -l
>```

> [!TIP]
> Explanation of Code:
> - `cat dns.log` outputs the contents of dns.log
> - `zeek-cut query` - only outputs the query column
> - `uniq` - Only returns unique values
> - `wc -l` -  Counts the return lines

#### Answer: [^5]

---

>[!IMPORTANT]
>Investigate the **conn.log** file. What is the longest connection duration?
>```
>cat conn.log | zeek-cut duration | sort -h -r | head -n 1
>```

>[!TIP]
>Explanation of Code
>- `cat conn.log` - outputs the contents of conn.log
>- `zeek-cut duration` - only outputs the duration column
>- `sort -h -r` - Sorts the information in reverse order, in human readable form.
>- *Computers like to sort each place individually so you will get incorrect returns like: 10.192, 168.99, 2.11, 26.84*
>- `head -n 1` - returns only the top line 

Answer: [^6]

---

### **CLI Kung-Fu Recall: Processing Zeek Logs**
This section goes a little deeper into using Linux commands to manipulate the data to get the expected return values, similar to what I have shown above.

---

Due to the length of post, I decided to break this into two parts. Stay tuned for part 2.

---

[^1]: 4.2.1
[^2]: 2.4.0
[^3]: 8
[^4]: Microknoppix
[^5]: 2
[^6]: 332.319364
