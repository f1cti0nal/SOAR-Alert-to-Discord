# 🛡️ SOAR Security Automation Platform
### *Automated Threat Detection & Response with Wazuh, TheHive & Shuffle*

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security](https://img.shields.io/badge/Security-SOAR-red.svg)](https://github.com/your-username/soar-automation)
[![Platform](https://img.shields.io/badge/Platform-Linux-blue.svg)](https://www.linux.org/)

---

## 🎯 **Project Overview**

This project implements a comprehensive **Security Orchestration, Automation and Response (SOAR)** platform that integrates multiple security tools to create an automated incident response pipeline. The system automatically detects threats, enriches alerts with threat intelligence, creates incidents, and provides real-time notifications.

### 🏗️ **Architecture**

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│      VM 1       │    │      VM 2       │    │   External APIs │
│  ┌───────────┐  │    │  ┌───────────┐  │    │  ┌───────────┐  │
│  │   Wazuh   │──┼────┼──│  Shuffle  │──┼────┼──│VirusTotal │  │
│  │   SIEM    │  │    │  │   SOAR    │  │    │  │           │  │
│  └───────────┘  │    │  └───────────┘  │    │  └───────────┘  │
│  ┌───────────┐  │    │                 │    │  ┌───────────┐  │
│  │ TheHive   │  │    │                 │    │  │AbuseIPDB  │  │
│  │Case Mgmt  │  │    │                 │    │  │           │  │
│  └───────────┘  │    │                 │    │  └───────────┘  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌─────────────────┐
                       │     Discord     │
                       │  Notifications  │
                       └─────────────────┘
```

---

## 🚀 **Features**

| Feature | Description | Status |
|---------|-------------|--------|
| 🔍 **Real-time Monitoring** | Continuous security event monitoring with Wazuh SIEM | ✅ |
| 🤖 **Automated Response** | Intelligent workflow automation via Shuffle SOAR | ✅ |
| 🧠 **Threat Intelligence** | Automatic enrichment with VirusTotal & AbuseIPDB | ✅ |
| 📋 **Case Management** | Structured incident tracking through TheHive | ✅ |
| 💬 **Real-time Alerts** | Instant Discord notifications for security events | ✅ |
| 📊 **MITRE ATT&CK** | Threat categorization using MITRE framework | ✅ |
| 🔐 **Vulnerability Management** | Automated vulnerability detection and reporting | ✅ |

---

## 🛠️ **Technology Stack**

### Core Components
- **🛡️ Wazuh v4.12.0** - SIEM & XDR Platform
- **🔍 TheHive v5.4.10** - Security Incident Response Platform  
- **⚡ Shuffle v1.4.0** - Security Orchestration Platform
- **💬 Discord** - Real-time Communication & Alerting

### Integration APIs
- **🦠 VirusTotal API** - File & URL Reputation Analysis
- **🚫 AbuseIPDB API** - IP Address Threat Intelligence
- **🔗 Webhook Integration** - Real-time event streaming

---

## 🏁 **Quick Start**

### 📋 Prerequisites

- **2 Linux VMs** (Ubuntu 20.04+ recommended)
- **Minimum 8GB RAM** per VM
- **50GB Storage** per VM
- **Network connectivity** between VMs
- **Internet access** for API integrations

### 🖥️ **VM Architecture**

#### **VM 1: Security Stack** 🛡️
```bash
# Specifications
- OS: Ubuntu 22.04 LTS
- RAM: 8GB minimum
- Storage: 50GB
- Services: Wazuh Manager + TheHive
```

#### **VM 2: Orchestration Engine** ⚡
```bash
# Specifications  
- OS: Ubuntu 22.04 LTS
- RAM: 4GB minimum
- Storage: 30GB
- Services: Shuffle SOAR Platform
```

---

## 📥 **Installation Guide**

### **Step 1: VM 1 Setup (Wazuh + TheHive)**

#### 🛡️ **Install Wazuh SIEM**

One CLick Install: https://documentation.wazuh.com/current/quickstart.html

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Wazuh repository
curl -sO https://packages.wazuh.com/4.12/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.12/config.yml

# Configure installation
sudo bash wazuh-install.sh -a

# Start services
sudo systemctl enable wazuh-manager
sudo systemctl start wazuh-manager
```
![Screenshot 2025-06-29 163038](https://github.com/user-attachments/assets/98a84111-63b4-464c-be12-0c1442c6fe28)

#### 🔍 **Install TheHive**

Step-by-Step Guide: https://docs.strangebee.com/thehive/installation/step-by-step-installation-guide/

1. **Install Dependencies:**
   ```bash
   apt install wget gnupg apt-transport-https git ca-certificates ca-certificates-java curl  software-properties-common python3-pip lsb-release
   ```

2. **Install Java:**
   ```bash
   wget -qO- https://apt.corretto.aws/corretto.key | sudo gpg --dearmor  -o /usr/share/keyrings/corretto.gpg
   echo "deb [signed-by=/usr/share/keyrings/corretto.gpg] https://apt.corretto.aws stable main" |  sudo tee -a /etc/apt/sources.list.d/corretto.sources.list
   sudo apt update
   sudo apt install java-common java-11-amazon-corretto-jdk
   echo JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto" | sudo tee -a /etc/environment 
   export JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto"
   ```

3. **Install Cassandra:**
   ```bash
   wget -qO -  https://downloads.apache.org/cassandra/KEYS | sudo gpg --dearmor  -o /usr/share/keyrings/cassandra-archive.gpg
   echo "deb [signed-by=/usr/share/keyrings/cassandra-archive.gpg] https://debian.cassandra.apache.org 40x main" |  sudo tee -a /etc/apt/sources.list.d/cassandra.sources.list
   sudo apt update
   sudo apt install cassandra
   ```

4. **Install ElasticSearch:**
   ```bash
   wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch |  sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
   sudo apt-get install apt-transport-https
   echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" |  sudo tee /etc/apt/sources.list.d/elastic-7.x.list
   sudo apt update
   sudo apt install elasticsearch
   ```

5. **Install TheHive:**
   ```bash
   wget -O- https://archives.strangebee.com/keys/strangebee.gpg | sudo gpg --dearmor -o /usr/share/keyrings/strangebee-archive-keyring.gpg
   echo 'deb [signed-by=/usr/share/keyrings/strangebee-archive-keyring.gpg] https://deb.strangebee.com thehive-5.2 main' | sudo tee -a /etc/apt/sources.list.d/strangebee.list
   sudo apt-get update
   sudo apt-get install -y thehive
   ```

6. **Default Credentials for TheHive:**
   - **Port:** 9000
   - **Credentials:** 'admin@thehive.local' with a password of 'secret'

![Screenshot 2025-06-29 163053](https://github.com/user-attachments/assets/cad0a720-0cf9-4cd1-9ffd-054154b81532)


### **Step 2: VM 2 Setup (Shuffle SOAR)**

#### ⚡ **Install Shuffle**
INstallation Guide: https://shuffler.io/docs/configuration

```bash
# Install Docker & Docker Compose
sudo apt update
sudo apt install docker.io docker-compose -y
sudo systemctl enable docker
sudo systemctl start docker

# Clone Shuffle repository
git clone https://github.com/Shuffle/Shuffle
cd Shuffle

# Configure environment
cp .env_example .env
# Edit .env file with your configurations

# Deploy Shuffle
sudo docker-compose up -d

# Access Shuffle at http://VM2_IP:3001
```

![Screenshot 2025-06-29 163008](https://github.com/user-attachments/assets/b2bd1f67-cebe-4c68-b6eb-b2048625f50f)


---

## ⚙️ **Configuration**

### **1. Wazuh Configuration** 🛡️

Edit `/var/ossec/etc/ossec.conf`:

```xml
<ossec_config>
  <integration>
    <name>shuffle</name>
    <hook_url>http://VM2_IP:3001/api/v1/hooks/webhook_id</hook_url>
    <level>3</level>
    <alert_format>json</alert_format>
  </integration>
</ossec_config>
```

### **2. Shuffle Workflow Configuration** ⚡

Create automation workflow:

```json
{
  "name": "Wazuh Alert Processing",
  "triggers": [
    {
      "type": "webhook",
      "name": "Fetch Log From Wazuh"
    }
  ],
  "actions": [
    {
      "app": "VirusTotal",
      "action": "get_file_report"
    },
    {
      "app": "AbuseIPDB", 
      "action": "check_ip"
    },
    {
      "app": "TheHive",
      "action": "create_case"
    },
    {
      "app": "Discord",
      "action": "send_message"
    }
  ]
}
```

### **3. Discord Integration** 💬

Create a Discord Webhook**  
1. Go to your **Discord Server** → **Settings** → **Integrations** → **Webhooks**  
2. Click **New Webhook** → Name it **Security Alert**   

```python
# Discord Webhook Configuration
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_TOKEN"

# Alert Template
alert_message = {
    "content": f"🚨 **Suspicious Activity Detected on Wazuh**\n"
               f"**Rule:** {rule_description}\n"
               f"**Level:** {alert_level}\n" 
               f"**Source IP:** {source_ip}\n"
               f"**Timestamp:** {timestamp}"
}
```

![Screenshot 2025-06-29 162950](https://github.com/user-attachments/assets/afe1785d-11e6-4bfe-8b5b-198296b744c6)


---

## 🔧 **API Integrations**

### **VirusTotal Setup** 🦠

```bash
# Get API key from https://www.virustotal.com/gui/my-apikey
export VT_API_KEY="your_virustotal_api_key"
```

### **AbuseIPDB Setup** 🚫

```bash
# Get API key from https://www.abuseipdb.com/account/api
export ABUSEIPDB_API_KEY="your_abuseipdb_api_key"
```

---
## Configuration for TheHive

### Configure Cassandra

1. **Edit Cassandra Config File:**
   ```bash
   nano /etc/cassandra/cassandra.yaml
   ```

2. **Change Cluster Name:**
   ```yaml
   cluster_name: 'SOAR-Flow'
   ```

3. **Update Listen Address:**
   ```yaml
   listen_address: <public IP of TheHive>
   ```

4. **Update RPC Address:**
   ```yaml
   rpc_address: <public IP of TheHive>
   ```

5. **Update Seed Provider:**
   ```yaml
   - seeds: "<Public IP Of the TheHive>:7000"
   ```

6. **Stop Cassandra Service:**
   ```bash
   systemctl stop cassandra.service
   ```

7. **Remove Old Files:**
   ```bash
   rm -rf /var/lib/cassandra/*
   ```

8. **Restart Cassandra Service:**
   ```bash
   systemctl start cassandra.service
   ```

### Configure ElasticSearch

1. **Edit ElasticSearch Config File:**
   ```bash
   nano /etc/elasticsearch/elasticsearch.yml
   ```

2. **Update Cluster Name and Host:**
   ```yaml
   cluster.name: thehive
   node.name: node-1
   network.host: <Public IP of your TheHive instance>
   http.port: 9200
   discovery.seed_hosts: ["127.0.0.1"]
   cluster.initial_master_nodes: ["node-1"]
   ```

3. **Start ElasticSearch Service:**
   ```bash
   systemctl start elasticsearch
   systemctl enable elasticsearch
   systemctl status elasticsearch
   ```

## Configure TheHive

1. **Ensure Proper Ownership:**
   ```bash
   ls -la /opt/thp
   chown -R thehive:thehive /opt/thp
   ```

2. **Edit TheHive Configuration File:**
   ```bash
   nano /etc/thehive/application.conf
   ```

3. **Update Database and Index Configuration:**
   ```conf
   db.janusgraph {
     storage {
       backend = cql
       hostname = ["<Public IP of TheHive>"]
       cql {
         cluster-name = SOAR-Flow
         keyspace = thehive
       }
     }
   }

   index.search {
     backend = elasticsearch
     hostname = ["<Public IP of TheHive>"]
     index-name = thehive
   }

   application.baseUrl = "http://<Public IP of TheHive>:9000"
   ```

4. **Start TheHive Services:**
   ```bash
   systemctl start thehive
   systemctl enable thehive
   systemctl status thehive
   ```

---

## 🚦 **Usage**

### **Starting the System**

```bash
# VM 1: Start Wazuh & TheHive
sudo systemctl start wazuh-manager
sudo systemctl start thehive

# VM 2: Start Shuffle
cd Shuffle && sudo docker-compose up -d
```

### **Monitoring Dashboard Access**

| Service | URL | Default Credentials |
|---------|-----|-------------------|
| 🛡️ **Wazuh Dashboard** | `https://VM1_IP` | admin/password will be shown on installation screen on terminal |
| 🔍 **TheHive Interface** | `http://VM1_IP:9000` | admin@thehive.local/secret |
| ⚡ **Shuffle Platform** | `http://VM2_IP:3001` | Create a New Account |

### **Testing the Pipeline**

```bash
# Generate test alert in Wazuh
sudo /var/ossec/bin/ossec-logtest

# Monitor workflow execution in Shuffle
# Check Discord channel for notifications
# Verify case creation in TheHive
```

---

## 📊 **Monitoring & Metrics**

### **Key Performance Indicators**

- **🕐 Mean Time to Detection (MTTD):** < 5 minutes
- **⚡ Mean Time to Response (MTTR):** < 15 minutes  
- **🎯 Alert Accuracy Rate:** > 95%
- **🔄 Automation Coverage:** > 80%

### **Dashboard Widgets**

- 📈 Events count evolution
- 🎯 MITRE ATT&CK tactics mapping
- 🔒 Compliance status overview
- 🚨 Critical vulnerability tracking
- 📋 Active incident status

---

## 🔍 **Troubleshooting**

### **Common Issues**

#### **Issue: Wazuh alerts not reaching Shuffle**
```bash
# Check Wazuh integration logs
tail -f /var/ossec/logs/ossec.log | grep -i shuffle

# Verify webhook connectivity
curl -X POST http://VM2_IP:3001/api/v1/hooks/webhook_id \
  -H "Content-Type: application/json" \
  -d '{"test": "connection"}'
```

#### **Issue: Discord notifications not working**
```bash
# Test Discord webhook
curl -X POST $DISCORD_WEBHOOK_URL \
  -H "Content-Type: application/json" \
  -d '{"content": "Test message from SOAR platform"}'
```

#### **Issue: TheHive case creation failing**
```bash
# Check TheHive logs
sudo journalctl -u thehive -f

# Verify API connectivity
curl -X GET http://VM1_IP:9000/api/status
```

---

## 🛡️ **Security Considerations**

### **Network Security**
- 🔒 Configure firewall rules between VMs
- 🌐 Use HTTPS for all web interfaces
- 🔑 Implement strong authentication
- 📱 Enable MFA where possible

### **API Security**
- 🔐 Store API keys in environment variables
- 🔄 Rotate credentials regularly
- 📊 Monitor API usage limits
- 🚫 Restrict API access by IP

---

## 📈 **Future Enhancements**

- [ ] 🤖 **Machine Learning Integration** - AI-powered threat detection
- [ ] 📱 **Mobile App Integration** - Push notifications for critical alerts
- [ ] ☁️ **Cloud SIEM Integration** - Multi-cloud security monitoring
- [ ] 🔄 **Advanced Playbooks** - Complex response automation
- [ ] 📊 **Custom Dashboards** - Tailored security metrics
- [ ] 🌐 **Multi-tenant Support** - Organization isolation

---

## 🤝 **Contributing**

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

1. 🍴 Fork the repository
2. 🌟 Create a feature branch
3. 💻 Make your changes  
4. ✅ Add tests
5. 📝 Update documentation
6. 🚀 Submit a pull request

---

## 📜 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 📞 **Support**

- 📧 **Email:** support@soar-automation.com
- 💬 **Discord:** [Join our community](https://discord.gg/soar-automation)
- 🐛 **Issues:** [GitHub Issues](https://github.com/your-username/soar-automation/issues)
- 📖 **Documentation:** [Wiki](https://github.com/your-username/soar-automation/wiki)

---

## 🙏 **Acknowledgments**

- **Wazuh Team** for the outstanding SIEM platform
- **TheHive Project** for the incident response framework  
- **Shuffle Team** for the automation platform
- **Security Community** for continuous feedback and support

---

<div align="center">

**⭐ Star this repository if you find it helpful!**

[![GitHub stars](https://img.shields.io/github/stars/your-username/soar-automation.svg?style=social&label=Star)](https://github.com/your-username/soar-automation)
[![GitHub forks](https://img.shields.io/github/forks/your-username/soar-automation.svg?style=social&label=Fork)](https://github.com/your-username/soar-automation/fork)

</div>

---

*Last updated: June 2025*
