# AudiThor-AWS ⚡️

**Una herramienta de auditoría de seguridad para AWS, con un enfoque en el cumplimiento de la normativa PCI DSS.**

AudiThor es una aplicación web local que proporciona un dashboard unificado para realizar auditorías de seguridad de solo lectura en entornos de AWS. Permite a los auditores, administradores y equipos de seguridad obtener una visión rápida y completa de la postura de seguridad de una cuenta, identificar posibles riesgos y verificar el cumplimiento de políticas, especialmente aquellas relacionadas con el estándar PCI DSS.

La mayor parte de este proyecto fue desarrollada con la asistencia de un modelo de lenguaje de IA (Gemini de Google), lo que permitió acelerar la implementación de las diversas comprobaciones y la creación del dashboard.


## 🚀 Características Principales

AudiThor ofrece una amplia gama de módulos de auditoría en un único lugar:

* **👤 Identity & Access (IAM):** Análisis detallado de usuarios, grupos, roles, políticas de contraseñas, usuarios privilegiados y federación.
* **🌐 Internet Exposure:** Detección de recursos expuestos a Internet, como buckets S3 públicos, instancias EC2, balanceadores, Security Groups abiertos y más.
* **🛡️ GuardDuty & WAF:** Revisión del estado y los hallazgos de GuardDuty y de la configuración de Web ACLs y IP Sets en WAF.
* **✍️ CloudTrail & CloudWatch:** Auditoría de la configuración de Trails, visualización de eventos de seguridad relevantes y revisión de alarmas y notificaciones SNS.
* **🔍 Inspector & ACM:** Visualización del estado y los hallazgos del servicio de vulnerabilidades Amazon Inspector y gestión de certificados de AWS Certificate Manager.
* **⚙️ Compute & Databases:** Inventario de recursos de cómputo (EC2, Lambda, EKS, ECS) y bases de datos (RDS, Aurora, DynamoDB, DocumentDB).
* **🔐 KMS & Network Policies:** Revisión de claves de cifrado en KMS y de políticas de red como VPCs, ACLs y Security Groups.
* **📊 Config & Security Hub:** Módulo centralizado para verificar el estado de estos servicios y realizar un análisis profundo de hallazgos de cumplimiento.
* **🎮 Playground Interactivo:**
    * **¿Nos vemos?:** Una herramienta para analizar la conectividad de red entre dos recursos específicos (ej. una EC2 y una RDS) a nivel de Security Group, NACL y tablas de rutas.
    * **SSL Scan:** Un wrapper del popular `sslscan` para analizar la configuración SSL/TLS de dominios o IPs públicas.
* **📥/📤 Importar y Exportar:** Guarda los resultados de tu auditoría en un fichero JSON para su posterior análisis o compártelos con tu equipo.

## 🛠️ Stack Tecnológico

* **Backend:** Python 3, Flask, Boto3
* **Frontend:** HTML, Tailwind CSS, Chart.js

## 📋 Prerrequisitos

Antes de empezar, asegúrate de tener instalado lo siguiente:

1.  **Python 3.8+** y `pip`.
2.  La herramienta de línea de comandos **`sslscan`**. Es utilizada por el módulo "SSL Scan" en el Playground.
    * **En Debian/Ubuntu:** `sudo apt-get update && sudo apt-get install sslscan`
    * **En macOS (con Homebrew):** `brew install sslscan`
    * **En Windows:** Puedes descargar los binarios desde el [repositorio oficial de sslscan en GitHub](https://github.com/rbsec/sslscan/releases).

## ⚙️ Instalación y Puesta en Marcha

1.  **Clona el repositorio:**
    ```bash
    git clone [https://github.com/tu-usuario/audithor.git](https://github.com/tu-usuario/audithor.git)
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

1.  **Ejecuta el servidor de Flask:**
    ```bash
    python backend.py
    ```
    La aplicación se iniciará y abrirá automáticamente una pestaña en tu navegador en `http://127.0.0.1:5001/dashboard.html`.

2.  **Introduce tus credenciales de AWS:**
    * Necesitarás un **Access Key ID** y un **Secret Access Key** de un usuario o rol IAM.
    * Si usas credenciales temporales, también deberás proporcionar el **Session Token**.

    >**⚠️ Nota sobre los permisos:**
    >Para que la herramienta funcione correctamente, las credenciales proporcionadas deben tener permisos de solo lectura sobre los servicios que se van a auditar. Un buen punto de partida es asociar las políticas gestionadas por AWS `SecurityAudit` y `ViewOnlyAccess` al usuario o rol IAM.

3.  **Haz clic en "Analizar Cuenta"** y explora los resultados en los diferentes módulos.

### 🔒 ¡Importante! Manejo de Credenciales

Esta herramienta se ejecuta de forma **totalmente local en tu máquina**. Las credenciales que introduces en el navegador se envían únicamente a tu servidor local (el script `backend.py`) y nunca abandonan tu ordenador. Sin embargo, siempre es una buena práctica:
* Utilizar credenciales temporales (Session Tokens) siempre que sea posible.
* No guardar tus credenciales en lugares no seguros.
* Ejecutar la herramienta en un entorno de confianza.

## 📄 Licencia

Este proyecto está bajo la Licencia MIT. Consulta el fichero `LICENSE` para más detalles.
