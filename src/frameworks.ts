import type { Framework } from "./types.js";

export const FRAMEWORKS: Record<string, Framework> = {
  owasp: {
    name: "OWASP Top 10",
    version: "2021",
    description: "The 10 most critical web application security risks, used by 90% of security teams worldwide.",
    items: [
      { id: "A01", title: "Broken Access Control", description: "Are access controls enforced on all endpoints and functions? Are there privilege escalation paths or IDOR vulnerabilities?", risk: "CRITICAL" },
      { id: "A02", title: "Cryptographic Failures", description: "Is sensitive data encrypted in transit and at rest? Are weak or deprecated algorithms (MD5, SHA1, DES) in use?", risk: "CRITICAL" },
      { id: "A03", title: "Injection", description: "Is user input validated and sanitized? Are parameterized queries used for all database interactions?", risk: "CRITICAL" },
      { id: "A04", title: "Insecure Design", description: "Has the system been threat-modeled? Are secure design patterns and principles followed during development?", risk: "HIGH" },
      { id: "A05", title: "Security Misconfiguration", description: "Are default credentials changed? Are unnecessary features, ports, and services disabled? Are error messages exposing stack traces?", risk: "HIGH" },
      { id: "A06", title: "Vulnerable and Outdated Components", description: "Are all dependencies up to date? Is there a process for tracking CVEs in third-party libraries and frameworks?", risk: "HIGH" },
      { id: "A07", title: "Identification and Authentication Failures", description: "Is MFA enabled? Are session tokens properly managed? Are accounts locked after failed attempts?", risk: "HIGH" },
      { id: "A08", title: "Software and Data Integrity Failures", description: "Is the CI/CD pipeline secured against tampering? Are software updates and plugins verified before installation?", risk: "MEDIUM" },
      { id: "A09", title: "Security Logging and Monitoring Failures", description: "Are security events logged with sufficient detail? Is there alerting for suspicious activity and failed logins?", risk: "MEDIUM" },
      { id: "A10", title: "Server-Side Request Forgery (SSRF)", description: "Are outgoing requests from the server validated and allowlisted? Is access to internal resources restricted?", risk: "HIGH" },
    ],
  },
  nist: {
    name: "NIST SP 800-53",
    version: "Rev 5",
    description: "Federal security and privacy controls, required for US government systems and widely adopted in enterprise.",
    items: [
      { id: "AC-1",  title: "Access Control Policy",              description: "Is a formal access control policy documented, approved, and communicated to all personnel?",                                          risk: "HIGH" },
      { id: "AC-2",  title: "Account Management",                 description: "Are user accounts formally managed with defined roles? Are unused accounts disabled within 30 days?",                              risk: "HIGH" },
      { id: "AC-6",  title: "Least Privilege",                    description: "Are users and processes granted only the minimum permissions required to perform their functions?",                                 risk: "CRITICAL" },
      { id: "AU-2",  title: "Audit Events",                       description: "Are security-relevant events identified and logged consistently across all systems?",                                               risk: "HIGH" },
      { id: "AU-9",  title: "Protection of Audit Information",     description: "Are audit logs protected from unauthorized access, modification, or deletion?",                                                   risk: "MEDIUM" },
      { id: "CA-7",  title: "Continuous Monitoring",              description: "Is there a continuous monitoring strategy? Are security controls assessed on an ongoing basis?",                                   risk: "HIGH" },
      { id: "CM-6",  title: "Configuration Settings",             description: "Are security configuration settings documented and enforced for all systems and applications?",                                    risk: "MEDIUM" },
      { id: "IA-2",  title: "Identification and Authentication",   description: "Is multi-factor authentication required for all privileged accounts and remote access sessions?",                                risk: "CRITICAL" },
      { id: "IR-4",  title: "Incident Handling",                  description: "Is there a documented incident response plan? Has it been tested in the last 12 months?",                                        risk: "HIGH" },
      { id: "SC-8",  title: "Transmission Confidentiality",       description: "Is all data in transit encrypted using current standards (TLS 1.2+ or TLS 1.3)?",                                               risk: "HIGH" },
      { id: "SC-28", title: "Protection of Information at Rest",   description: "Is sensitive data encrypted at rest using AES-256 or equivalent?",                                                               risk: "HIGH" },
      { id: "SI-3",  title: "Malicious Code Protection",          description: "Is anti-malware deployed and updated on all endpoints? Are scheduled scans configured?",                                         risk: "HIGH" },
      { id: "SI-10", title: "Information Input Validation",        description: "Is all input validated for type, length, format, and range before processing?",                                                  risk: "MEDIUM" },
    ],
  },
  iso27001: {
    name: "ISO 27001",
    version: "2022",
    description: "International standard for information security management systems (ISMS), required for ISO certification.",
    items: [
      { id: "A.5.1",  title: "Policies for Information Security",   description: "Are information security policies defined, approved by management, and communicated to all staff?",                             risk: "HIGH" },
      { id: "A.5.15", title: "Access Control",                      description: "Are rules for access control defined and implemented based on business and information security requirements?",               risk: "CRITICAL" },
      { id: "A.6.1",  title: "Screening",                           description: "Are background verification checks conducted on all employees and contractors prior to onboarding?",                          risk: "HIGH" },
      { id: "A.7.9",  title: "Security of Assets Off-Premises",     description: "Are assets used outside organizational premises protected with controls accounting for the increased risk?",                risk: "MEDIUM" },
      { id: "A.8.2",  title: "Privileged Access Rights",            description: "Are privileged access rights restricted, reviewed regularly, and granted on a need-to-use basis only?",                     risk: "CRITICAL" },
      { id: "A.8.5",  title: "Secure Authentication",               description: "Are secure authentication procedures implemented, including MFA for all sensitive and privileged systems?",                 risk: "CRITICAL" },
      { id: "A.8.7",  title: "Protection Against Malware",          description: "Are controls against malware implemented and supported by regular user awareness training?",                                 risk: "HIGH" },
      { id: "A.8.13", title: "Information Backup",                  description: "Are backup copies of information maintained, tested regularly for recoverability, and stored securely off-site?",             risk: "HIGH" },
      { id: "A.8.16", title: "Monitoring Activities",               description: "Are networks, systems, and applications monitored for anomalous behaviour and potential security incidents?",                 risk: "HIGH" },
      { id: "A.8.24", title: "Use of Cryptography",                 description: "Is cryptography used appropriately and consistently to protect confidentiality and integrity of information?",                risk: "HIGH" },
      { id: "A.8.28", title: "Secure Coding",                       description: "Are secure coding principles applied across all development? Is security testing performed at every stage?",               risk: "MEDIUM" },
      { id: "A.8.32", title: "Change Management",                   description: "Are changes to information processing facilities and systems managed via a formal change management procedure?",           risk: "MEDIUM" },
    ],
  },
  pcidss: {
    name: "PCI-DSS",
    version: "v4.0",
    description: "Payment Card Industry Data Security Standard, required for handling credit card information.",
    items: [
      { id: "1.1", title: "Network Security Controls", description: "Are network security controls configured and maintained to protect cardholder data?", risk: "CRITICAL" },
      { id: "3.2", title: "Protect Stored Account Data", description: "Is storage of account data kept to a minimum and securely encrypted?", risk: "CRITICAL" },
      { id: "4.1", title: "Protect Data in Transit", description: "Is strong cryptography used to protect cardholder data during transmission over open, public networks?", risk: "CRITICAL" },
      { id: "6.2", title: "Develop Secure Software", description: "Are software vulnerabilities addressed and secure software development practices followed?", risk: "HIGH" },
      { id: "8.2", title: "User Authentication Management", description: "Are all users assigned a unique ID and is multi-factor authentication (MFA) used for secure access?", risk: "CRITICAL" }
    ],
  },
  soc2: {
    name: "SOC 2",
    version: "Type II",
    description: "Service Organization Control 2, focusing on security, availability, processing integrity, confidentiality, and privacy.",
    items: [
      { id: "CC6.1", title: "Logical Access Security", description: "Does the entity implement logical access security software, infrastructure, and architectures over protected information assets to protect them from security events?", risk: "CRITICAL" },
      { id: "CC6.6", title: "Boundary Protection", description: "Does the entity implement logical access security measures to protect against threats from sources outside its system boundaries?", risk: "HIGH" },
      { id: "CC7.1", title: "Vulnerability Scans and Penetration Tests", description: "Does the entity conduct vulnerability scans and penetration tests to detect vulnerabilities?", risk: "HIGH" },
      { id: "CC7.2", title: "Security Event Monitoring", description: "Does the entity monitor system components and the operation of those components for anomalies that are indicative of malicious acts, natural disasters, and errors affecting the entity's ability to meet its objectives?", risk: "HIGH" },
      { id: "CC8.1", title: "Change Management", description: "Does the entity authorize, design, develop or acquire, configure, document, test, approve, and implement changes to infrastructure, data, software, and procedures?", risk: "MEDIUM" }
    ],
  },
  hipaa: {
    name: "HIPAA",
    version: "Security Rule",
    description: "Health Insurance Portability and Accountability Act, establishing national standards to protect individuals' medical records.",
    items: [
      { id: "164.308(a)(1)", title: "Security Management Process", description: "Is there a process to prevent, detect, contain, and correct security violations (including risk analysis and risk management)?", risk: "CRITICAL" },
      { id: "164.308(a)(5)", title: "Security Awareness and Training", description: "Is there a security awareness and training program for all members of the workforce?", risk: "MEDIUM" },
      { id: "164.312(a)(1)", title: "Access Control", description: "Are technical policies and procedures implemented for electronic information systems that maintain electronic protected health information to allow access only to those persons or software programs that have been granted access rights?", risk: "CRITICAL" },
      { id: "164.312(c)(1)", title: "Integrity", description: "Are policies and procedures implemented to protect electronic protected health information from improper alteration or destruction?", risk: "HIGH" },
      { id: "164.312(e)(1)", title: "Transmission Security", description: "Are technical security measures implemented to guard against unauthorized access to electronic protected health information that is being transmitted over an electronic communications network?", risk: "CRITICAL" }
    ],
  },
  cisv8: {
    name: "CIS Controls",
    version: "v8",
    description: "Center for Internet Security Controls, a prioritized set of actions to protect organizations and data from known cyber attack vectors.",
    items: [
      { id: "1", title: "Inventory and Control of Enterprise Assets", description: "Actively manage (inventory, track, and correct) all enterprise assets (end-user devices, including portable and mobile; network devices; non-computing/Internet of Things (IoT) devices; and servers) connected to the infrastructure physically, virtually, remotely, and those within cloud environments.", risk: "HIGH" },
      { id: "3", title: "Data Protection", description: "Develop processes and technical controls to identify, classify, securely handle, retain, and dispose of data.", risk: "CRITICAL" },
      { id: "4", title: "Secure Configuration of Enterprise Assets and Software", description: "Establish and maintain the secure configuration of enterprise assets and software.", risk: "HIGH" },
      { id: "5", title: "Account Management", description: "Use processes and tools to assign and manage authorization to credentials for user accounts, including administrator accounts, as well as service accounts, to enterprise assets and software.", risk: "CRITICAL" },
      { id: "16", title: "Application Software Security", description: "Manage the security life cycle of all in-house developed and hosted software to prevent, detect, and remediate security weaknesses before they can impact the enterprise.", risk: "HIGH" }
    ],
  },
};
