# AudiThor-AWS ⚡️

**A security auditing tool for AWS, with a focus on PCI DSS compliance.**
AudiThor is a local web application that provides a unified dashboard for conducting read-only security audits in AWS environments. It allows auditors, administrators, and security teams to get a quick and comprehensive overview of an account's security posture, identify potential risks, and verify policy compliance, especially those related to the PCI DSS standard.

## 🎯 Who Is This Tool For?

AudiThor-AWS is specifically designed for **audit teams and security professionals** who need to assess AWS environments for compliance purposes. Traditionally, audit teams have faced significant challenges in:

- **Limited AWS Visibility**: Gaining comprehensive oversight of complex cloud environments across multiple regions and services
- **Evidence Collection Bottlenecks**: Manually gathering security evidence from dozens of AWS services for compliance frameworks
- **Time-Intensive Audits**: Spending weeks collecting basic configuration data instead of analyzing security posture
- **Compliance Gap Identification**: Quickly identifying non-compliance with standards like PCI DSS, SOC 2, SWIFT, and ISO 27001
- **Cross-Service Correlation**: Understanding how security configurations interact across different AWS services

This tool addresses these pain points by providing:
- **Automated Evidence Collection**: Gather security configurations from 20+ AWS services in minutes
- **Compliance-Focused Analysis**: Built-in rules for PCI DSS 3.2.1/4.0.1, CIS Benchmark, and AWS security best practices
- **Comprehensive Reporting**: AI-powered executive summaries and detailed technical findings
- **Risk Prioritization**: Severity-based findings to focus on critical security gaps first

Whether you're conducting PCI DSS assessments, SOC 2 audits, SWIFT compliance reviews, or general security assessments, AudiThor-AWS transforms weeks of manual evidence gathering into automated, comprehensive analysis.

The majority of this project was developed with the assistance of an AI language model (Google's Gemini), which helped accelerate the implementation of various checks and the creation of the dashboard.

<img width="1839" height="396" alt="image" src="https://github.com/user-attachments/assets/d890814c-e0a9-4fbe-8f95-8a5455dce423" />

## 🚀 Key Features

AudiThor offers a wide range of auditing modules in a single place:

* **🩺 Healthy Status & AI Reporting:** A centralized rules engine that analyzes the collected data and presents clear, actionable findings.
    * **AI Report Generation (Gemini):** Uses Google's AI to automatically generate a draft of an executive email summarizing critical findings, ideal for communicating with stakeholders.
* **👤 Identity & Access (IAM):** Detailed analysis of users, groups, roles, password policies, privileged users, traditional federation (SAML/OIDC), and **AWS Identity Center (SSO)** configuration.
* **🌐 Internet Exposure:** Detection of internet-exposed resources, such as public S3 buckets, EC2 instances, load balancers, open Security Groups, and more. Now includes **multi-threaded analysis** for improved performance and **detailed network port scanning** across Security Groups and NACLs.
* **🔗 Network Connectivity:** Inventory and analysis of network connectivity components, including **VPC Peering**, **Transit Gateway** attachments, **VPN** connections, and **VPC Endpoints**.
* **🛡️ GuardDuty & WAF:** Review of GuardDuty status and findings, and the configuration of Web ACLs and IP Sets in WAF.
* **✉️ CloudTrail & CloudWatch:** Advanced auditing of Trail configurations with **TrailGuard Analysis** that maps complete data flow from trails to their destinations (S3 notifications, CloudWatch subscription filters, metric filters). Visualization of relevant security events and review of alarms and SNS notifications.
* **🔍 Inspector & ACM:** Enhanced visualization of Amazon Inspector v2 vulnerability service with **EC2 instance name resolution**, **severity-based prioritization**, and **age-based risk assessment** for vulnerabilities. Complete AWS Certificate Manager analysis with **expiration tracking** and multi-region coverage.
* **⚙️ Compute & Databases:** Advanced inventory of compute resources (EC2, Lambda, EKS, ECS) with **detailed IAM role mapping**, **privileged role detection**, and **operating system information**. Database analysis includes **comprehensive KMS encryption mapping** with human-readable key aliases for RDS, Aurora, DynamoDB, and DocumentDB.
* **🔐 KMS & Network Policies:** Complete review of encryption keys with **automatic rotation status** and **policy analysis**. Network policies analysis includes VPCs, ACLs, and Security Groups with **interactive network diagram** and **formatted rule visualization**.
* **📊 Config & Security Hub:** Comprehensive module with **40+ security rules**, **multi-standard compliance** (PCI DSS 3.2.1/4.0.1, CIS Benchmark, AWS Foundational), **severity-based findings**, and **automated compliance percentage calculations**.
* **🎮 Interactive Playground:**
    * **Advanced Network Path Analyzer:** Multi-layer analysis (Security Groups, NACLs, route tables) between AWS resources with **detailed decision tables** and **comprehensive rule visualization**
    * **Enhanced SSL Scan:** Multi-threaded SSL/TLS analysis with **concurrent target processing**
    * **IAM Permission Simulator:** Real-time permission testing for users and Lambda functions using AWS simulation API
* **🔥/📤 Import & Export:** Save your audit results to a JSON file for later analysis or to share with your team.

## 🆕 Enhanced Features

### Advanced Security Analysis Engine
- **Comprehensive Rules Engine:** 40+ security rules covering IAM, GuardDuty, Config, Security Hub, Inspector, CloudTrail, and more
- **PCI DSS Compliance Focus:** Specialized rules for PCI DSS 3.2.1 and 4.0.1 compliance validation
- **Multi-Standard Support:** CIS AWS Foundations Benchmark and AWS Foundational Security Best Practices integration
- **Automated Severity Assessment:** Critical, High, Medium, Low, and Informational risk categorization

### Advanced IAM Security Analysis
- **Privilege Escalation Detection:** Identifies users and roles with dangerous policy combinations
- **MFA Compliance Analysis:** Advanced CLI/programmatic access MFA requirement validation
- **AWS Identity Center Integration:** Complete SSO configuration analysis and privileged assignment detection
- **Access Analyzer Integration:** External and public access finding correlation
- **Critical Permission Simulation:** Uses IAM simulation API to test dangerous permissions across network, CloudTrail, database, and WAF actions

### Enhanced GuardDuty Intelligence
- **Advanced Feature Detection:** S3 logs, Kubernetes audit logs, EC2 malware protection, and EKS runtime monitoring status
- **Severity-Based Analysis:** Intelligent finding processing with resource-specific context extraction
- **Multi-Resource Support:** Access keys, EC2 instances, EKS clusters, and S3 bucket analysis
- **Regional Coverage:** Complete multi-region detector status and finding aggregation

### Advanced CloudTrail Analysis
- **TrailGuard Analysis:** Maps complete data flow from CloudTrail trails to destinations
- **S3 Destination Analysis:** Identifies bucket notifications (Lambda, SQS, SNS triggers)
- **CloudWatch Integration:** Tracks subscription filters and metric filters with associated alarms
- **Security Event Tracking:** Searches for critical security events from the last 7 days

### Enhanced Internet Exposure Detection
- **Multi-threaded Analysis:** Parallel processing for faster security scanning across services
- **Network Port Analysis:** Comprehensive scanning of Security Groups and NACLs for exposed ports
- **Advanced Load Balancer Analysis:** Detailed SSL/TLS policy analysis with outdated protocol detection
- **Comprehensive Service Coverage:** S3 buckets, EC2 instances, Lambda URLs, API Gateway, and IAM roles

### Advanced Database Security Analysis
- **KMS Key Mapping:** Automatic mapping of KMS Key IDs to human-readable aliases
- **Comprehensive Encryption Analysis:** Detailed encryption status for RDS, Aurora, DynamoDB, and DocumentDB
- **Cross-Service Integration:** Links database encryption to specific KMS keys across all regions

### Enhanced Compute Analysis
- **Lambda Role Analysis:** Detailed IAM execution role mapping for security assessment
- **Operating System Detection:** AMI-based OS identification for EC2 instances
- **VPC Integration Analysis:** Complete VPC configuration details for Lambda functions

### Network Connectivity Intelligence
- **VPC Peering Analysis:** Active peering connection inventory and analysis
- **Transit Gateway Mapping:** Comprehensive TGW attachment tracking
- **VPN Connection Analysis:** Site-to-site VPN connection monitoring
- **VPC Endpoint Inventory:** Complete endpoint analysis for private service access

### Advanced Vulnerability Management
- **Inspector v2 Integration:** Complete EC2, ECR, and Lambda vulnerability scanning status
- **EC2 Instance Name Resolution:** Automatic resolution of instance names from tags for better reporting
- **Severity-Based Prioritization:** Critical, High, Medium, Low vulnerability classification
- **Age-Based Risk Assessment:** Identifies vulnerabilities over 30 days old for prioritized remediation

### Container Security (ECR)
- **Repository Policy Analysis:** Automated detection of public access policies
- **Scan Configuration Audit:** Verification of scan-on-push settings
- **Lifecycle Policy Review:** Analysis of image lifecycle configurations
- **Tag Mutability Assessment:** Security review of tag immutability settings

### Advanced WAF Analysis
- **CloudWatch Metrics Integration:** Top blocked rules analysis over the last 3 days
- **Dual-Scope Coverage:** Both CloudFront (global) and regional WAF ACLs
- **Resource Association Mapping:** Detailed view of protected resources per Web ACL
- **Logging Configuration Analysis:** Full logging destination verification

### Interactive Security Playground
- **Network Path Analysis:** Advanced connectivity testing between AWS resources (EC2, RDS, Lambda)
- **Multi-Layer Security Validation:** Security Groups, NACLs, and route table analysis
- **SSL/TLS Analysis:** Integration with sslscan for external SSL configuration testing
- **Permission Simulation:** IAM policy simulation for users and Lambda functions

## 🛠️ Tech Stack

* **Backend (audithor.py):** Python 3, Flask, Boto3
* **Frontend:** HTML, Tailwind CSS, Chart.js

## 📋 Prerequisites

Before you begin, ensure you have the following installed:

1.  **Python 3.8+** and `pip`.
2.  The **`sslscan`** command-line tool. It is used by the "SSL Scan" module in the Playground.
    * **On Debian/Ubuntu:** `sudo apt-get update && sudo apt-get install sslscan`
    * **On macOS (with Homebrew):** `brew install sslscan`
    * **On Windows:** You can download the binaries from the [official sslscan repository on GitHub](https://github.com/rbsec/sslscan/releases).
3.  **(Optional) A Google Gemini API Key:** To use the AI report generation feature, you will need an API key.
    * You can get a free key at [Google AI Studio](https://aistudio.google.com/app/apikey).
    * **Important:** The key is used directly from your browser to communicate with the Google API and is **never stored on the local server**.

## ⚙️ Installation and Setup

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/audithor.git
    cd audithor
    ```
   

2.  **Create and activate a virtual environment (recommended):**
    ```bash
    # Create the environment
    python -m venv venv

    # Activate it
    # On Linux/macOS:
    source venv/bin/activate
    # On Windows:
    .\venv\Scripts\activate
    ```
   

3.  **Install the dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
   

## ▶️ Usage

1.  **Run the Flask server:**
    ```bash
    python audithor.py
    ```
    The application will start and automatically open a new tab in your browser at `http://127.0.0.1:5001/dashboard.html`.

2.  **Enter your AWS credentials:**
    * You will need an **Access Key ID** and a **Secret Access Key** from an IAM user or role.
    * If you are using temporary credentials, you must also provide the **Session Token**.

    > **⚠️ Note on Permissions:**
    > For the tool to work correctly, the provided credentials must have read-only permissions for the services to be audited. A good starting point is to attach the AWS-managed policies `SecurityAudit` and `ViewOnlyAccess` to the IAM user or role.

3.  **Click "Analyze Account"** and explore the results in the different modules.

4.  **(Optional) Generate an AI Report:**
    * Navigate to the **"Healthy Status"** module and select the **"Generate Report"** tab.
    * Paste your **Google Gemini API Key** into the corresponding field.
    * Adjust the prompt if you wish and click **"Generate Email Draft"**.

### 🔒 Important! Credential Handling

This tool runs **entirely locally on your machine**. The credentials you enter in the browser are sent only to your local server (the `audithor.py` script) and never leave your computer. However, it is always a good practice to:
* Use temporary credentials (Session Tokens) whenever possible.
* Do not save your credentials in insecure locations.
* Run the tool in a trusted environment.

## 🔄 Performance Improvements

The latest version includes significant performance enhancements:
- **Multi-threaded analysis** for internet exposure detection
- **Optimized region scanning** with intelligent error handling
- **Parallel processing** for large-scale AWS environments
- **Efficient API pagination** to handle accounts with thousands of resources

## 📄 License

This project is licensed under the MIT License. See the `LICENSE` file for details.