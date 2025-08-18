# AudiThor-AWS ⚡️

**Una herramienta de auditoría de seguridad para AWS, con un enfoque en el cumplimiento de PCI DSS.**

AudiThor es una aplicación web local que proporciona un dashboard unificado para realizar auditorías de seguridad de solo lectura en entornos de AWS. Permite a auditores, administradores y equipos de seguridad obtener una visión rápida y completa de la postura de seguridad de una cuenta, identificar riesgos potenciales y verificar el cumplimiento de políticas, especialmente las relacionadas con el estándar PCI DSS.

La mayor parte de este proyecto se desarrolló con la asistencia de un modelo de lenguaje de IA (Gemini de Google), que ayudó a acelerar la implementación de los diversos chequeos y la creación del dashboard.

## 🚀 Características Principales

AudiThor ofrece una amplia gama de módulos de auditoría en un único lugar:

* **🩺 Healthy Status & Informes con IA:** Un motor de reglas centralizado que analiza los datos recopilados y presenta "hallazgos" claros y accionables.
    * **Generación de Informes con Gemini:** Utiliza la IA de Google para generar automáticamente un borrador de correo electrónico ejecutivo resumiendo los hallazgos críticos, ideal para la comunicación con stakeholders.
* **👤 Identidad y Acceso (IAM):** Análisis detallado de usuarios, grupos, roles, políticas de contraseña, usuarios privilegiados, federación tradicional (SAML/OIDC) y configuración de **AWS Identity Center (SSO)**.
* **🌐 Exposición a Internet:** Detección de recursos expuestos a internet, como buckets S3 públicos, instancias EC2, balanceadores de carga, Security Groups abiertos y más.
* **🔗 Conectividad de Red:** Inventario y análisis de los componentes de conectividad de red, incluyendo **VPC Peering**, adjuntos de **Transit Gateway**, conexiones **VPN** y **VPC Endpoints**.
* **🛡️ GuardDuty & WAF:** Revisión del estado y hallazgos de GuardDuty, y la configuración de Web ACLs y IP Sets en WAF.
* **✍️ CloudTrail & CloudWatch:** Auditoría de la configuración de Trails, visualización de eventos de seguridad relevantes y revisión de alarmas y notificaciones SNS.
* **🔍 Inspector & ACM:** Visualización del estado y hallazgos del servicio de vulnerabilidades Amazon Inspector y gestión de certificados de AWS Certificate Manager.
* **⚙️ Compute & Bases de Datos:** Inventario de recursos de cómputo (EC2, Lambda, EKS, ECS) y bases de datos (RDS, Aurora, DynamoDB, DocumentDB).
* **🔐 KMS & Políticas de Red:** Revisión de claves de cifrado en KMS y políticas de red como VPCs, ACLs y Security Groups, incluyendo un **diagrama de red interactivo**.
* **📊 Config & Security Hub:** Un módulo centralizado para comprobar el estado de estos servicios y realizar un análisis profundo de los hallazgos de cumplimiento, verificando estándares como **PCI DSS**, **CIS Benchmark** y **AWS Foundational Security Best Practices**.
* **🎮 Playground Interactivo:**
    * **¿Nos vemos?:** Una herramienta para analizar la conectividad de red entre dos recursos específicos (ej: una instancia EC2 y una base de datos RDS) a nivel de Security Group, NACL y tablas de enrutamiento.
    * **SSL Scan:** Un wrapper para el popular `sslscan` que analiza la configuración SSL/TLS de dominios o IPs públicas.
* **📥/📤 Importar y Exportar:** Guarda los resultados de tu auditoría en un fichero JSON para un análisis posterior o para compartirlos con tu equipo.

## 🛠️ Stack Tecnológico

* **Backend (audithor.py):** Python 3, Flask, Boto3
* **Frontend:** HTML, Tailwind CSS, Chart.js

## 📋 Requisitos Previos

Antes de empezar, asegúrate de tener lo siguiente instalado:

1.  **Python 3.8+** y `pip`.
2.  La herramienta de línea de comandos **`sslscan`**. Es utilizada por el módulo "SSL Scan" del Playground.
    * **En Debian/Ubuntu:** `sudo apt-get update && sudo apt-get install sslscan`
    * **En macOS (con Homebrew):** `brew install sslscan`
    * **En Windows:** Puedes descargar los binarios desde el [repositorio oficial de sslscan en GitHub](https://github.com/rbsec/sslscan/releases).
3.  **(Opcional) Una API Key de Google Gemini:** Para utilizar la funcionalidad de generación de informes con IA, necesitarás una clave de API.
    * Puedes obtener una clave gratuita en [Google AI Studio](https://aistudio.google.com/app/apikey).
    * **Importante:** La clave se utiliza directamente desde tu navegador para comunicarse con la API de Google y **nunca se almacena en el servidor local**.

## ⚙️ Instalación y Configuración

1.  **Clona el repositorio:**
    ```bash
    git clone [https://github.com/your-username/audithor.git](https://github.com/your-username/audithor.git)
    cd audithor
    ```

2.  **Crea y activa un entorno virtual (recomendado):**
    ```bash
    # Crear el entorno
    python -m venv venv

    # Activarlo
    # En Linux/macOS:
    source venv/bin/activate
    # En Windows:
    .\venv\Scripts\activate
    ```

3.  **Instala las dependencias:**
    ```bash
    pip install -r requirements.txt
    ```

## ▶️ Uso

1.  **Ejecuta el servidor Flask:**
    ```bash
    python audithor.py
    ```
    La aplicación se iniciará y abrirá automáticamente una nueva pestaña en tu navegador en `http://127.0.0.1:5001/dashboard.html`.

2.  **Introduce tus credenciales de AWS:**
    * Necesitarás un **Access Key ID** y un **Secret Access Key** de un usuario o rol de IAM.
    * Si estás utilizando credenciales temporales, también debes proporcionar el **Session Token**.

    > **⚠️ Nota sobre los permisos:**
    > Para que la herramienta funcione correctamente, las credenciales proporcionadas deben tener permisos de solo lectura para los servicios que se van a auditar. Un buen punto de partida es adjuntar las políticas gestionadas por AWS `SecurityAudit` y `ViewOnlyAccess` al usuario o rol de IAM.

3.  **Haz clic en "Analizar Cuenta"** y explora los resultados en los diferentes módulos.

4.  **(Opcional) Generar un Informe con IA:**
    * Navega al módulo **"Healthy Status"** y selecciona la pestaña **"Generar Informe"**.
    * Pega tu **API Key de Google Gemini** en el campo correspondiente.
    * Ajusta el prompt si lo deseas y haz clic en **"Generar Borrador de Correo"**.

### 🔒 ¡Importante! Manejo de Credenciales

Esta herramienta se ejecuta **completamente en local en tu máquina**. Las credenciales que introduces en el navegador se envían únicamente a tu servidor local (el script `audithor.py`) y nunca abandonan tu ordenador. Sin embargo, siempre es una buena práctica:
* Usar credenciales temporales (Session Tokens) siempre que sea posible.
* No guardar tus credenciales en ubicaciones no seguras.
* Ejecutar la herramienta en un entorno de confianza.

## 📄 Licencia

Este proyecto está bajo la Licencia MIT. Consulta el fichero `LICENSE` para más detalles.