# AudiThor-AWS ⚡️

**A security auditing tool for AWS, with a focus on PCI DSS compliance.**

AudiThor is a local web application that provides a unified dashboard for performing read-only security audits in AWS environments. It allows auditors, administrators, and security teams to get a quick and comprehensive view of an account's security posture, identify potential risks, and verify policy compliance, especially those related to the PCI DSS standard.

Most of this project was developed with the assistance of an AI language model (Google's Gemini), which helped accelerate the implementation of the various checks and the creation of the dashboard.

## 🚀 Key Features

AudiThor offers a wide range of audit modules in one single place:

* **👤 Identity & Access (IAM):** Detailed analysis of users, groups, roles, password policies, privileged users, and federation.
* **🌐 Internet Exposure:** Detection of resources exposed to the internet, such as public S3 buckets, EC2 instances, load balancers, open Security Groups, and more.
* **🛡️ GuardDuty & WAF:** Review of GuardDuty's status and findings, and the configuration of Web ACLs and IP Sets in WAF.
* **✍️ CloudTrail & CloudWatch:** Audit of Trail configurations, visualization of relevant security events, and review of alarms and SNS notifications.
* **🔍 Inspector & ACM:** Visualization of the status and findings of the Amazon Inspector vulnerability service and management of certificates from AWS Certificate Manager.
* **⚙️ Compute & Databases:** Inventory of compute resources (EC2, Lambda, EKS, ECS) and databases (RDS, Aurora, DynamoDB, DocumentDB).
* **🔐 KMS & Network Policies:** Review of encryption keys in KMS and network policies such as VPCs, ACLs, and Security Groups.
* **📊 Config & Security Hub:** A centralized module to check the status of these services and perform a deep analysis of compliance findings.
* **🎮 Interactive Playground:**
    * **Can we see each other?:** A tool to analyze network connectivity between two specific resources (e.g., an EC2 instance and an RDS database) at the Security Group, NACL, and route table level.
    * **SSL Scan:** A wrapper for the popular `sslscan` to analyze the SSL/TLS configuration of public domains or IPs.
* **📥/📤 Import & Export:** Save your audit results to a JSON file for later analysis or share them with your team.

## 🛠️ Tech Stack

* **Backend (audithor.py):** Python 3, Flask, Boto3
* **Frontend:** HTML, Tailwind CSS, Chart.js

## 📋 Prerequisites

Before you begin, make sure you have the following installed:

1.  **Python 3.8+** and `pip`.
2.  The **`sslscan`** command-line tool. It is used by the "SSL Scan" module in the Playground.
    * **On Debian/Ubuntu:** `sudo apt-get update && sudo apt-get install sslscan`
    * **On macOS (with Homebrew):** `brew install sslscan`
    * **On Windows:** You can download the binaries from the [official sslscan GitHub repository](https://github.com/rbsec/sslscan/releases).

## ⚙️ Installation and Setup

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/your-username/audithor.git](https://github.com/your-username/audithor.git)
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

    > **⚠️ Note on permissions:**
    > For the tool to work correctly, the provided credentials must have read-only permissions for the services to be audited. A good starting point is to attach the AWS managed policies `SecurityAudit` and `ViewOnlyAccess` to the IAM user or role.

3.  **Click on "Analyze Account"** and explore the results in the different modules.

### 🔒 Important! Credential Handling

This tool runs **entirely locally on your machine**. The credentials you enter in the browser are sent only to your local server (the `audithor.py` script) and never leave your computer. However, it is always good practice to:
* Use temporary credentials (Session Tokens) whenever possible.
* Do not save your credentials in unsecured locations.
* Run the tool in a trusted environment.

## 📄 License

This project is licensed under the MIT License. See the `LICENSE` file for more details.
