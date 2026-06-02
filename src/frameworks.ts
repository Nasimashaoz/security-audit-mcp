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
    description: "Payment Card Industry Data Security Standard. Required for any organization that handles branded credit cards.",
    items: [
      { id: "Req 1", title: "Network Security Controls", description: "Are network security controls configured and maintained to protect the cardholder data environment?", risk: "CRITICAL" },
      { id: "Req 2", title: "Secure Configuration", description: "Are vendor-supplied defaults changed? Are system configurations secure?", risk: "HIGH" },
      { id: "Req 3", title: "Protect Stored Account Data", description: "Is stored cardholder data protected? Is PAN unreadable wherever it is stored?", risk: "CRITICAL" },
      { id: "Req 4", title: "Cryptography during Transmission", description: "Is cardholder data encrypted using strong cryptography across open, public networks?", risk: "CRITICAL" },
      { id: "Req 5", title: "Protect against Malicious Software", description: "Are anti-malware solutions deployed, actively running, and kept up to date?", risk: "HIGH" },
      { id: "Req 6", title: "Develop and Maintain Secure Systems", description: "Are bespoke and custom software developed securely? Are critical security patches installed promptly?", risk: "HIGH" },
      { id: "Req 7", title: "Restrict Access to Data", description: "Is access to cardholder data restricted by business need-to-know?", risk: "HIGH" },
      { id: "Req 8", title: "Identify Users and Authenticate Access", description: "Are users identified uniquely and authenticated before access is granted? Is MFA implemented?", risk: "CRITICAL" },
      { id: "Req 9", title: "Restrict Physical Access", description: "Is physical access to the cardholder data environment restricted?", risk: "MEDIUM" },
      { id: "Req 10", title: "Log and Monitor Access", description: "Are all access to network resources and cardholder data logged and monitored?", risk: "HIGH" },
      { id: "Req 11", title: "Test Security of Systems", description: "Are security of systems and networks tested regularly (vulnerability scans and penetration testing)?", risk: "HIGH" },
      { id: "Req 12", title: "Information Security Policies", description: "Is a policy that addresses information security maintained and disseminated to all personnel?", risk: "MEDIUM" }
    ]
  },
  soc2: {
    name: "SOC 2",
    version: "Type II",
    description: "Service Organization Control 2, based on Trust Services Criteria. Crucial for B2B SaaS and service providers.",
    items: [
      { id: "CC1", title: "Control Environment", description: "Does the organization demonstrate a commitment to integrity and ethical values? Is oversight of the system's development maintained?", risk: "HIGH" },
      { id: "CC2", title: "Communication and Information", description: "Are relevant internal and external communications supporting the functioning of internal control generated and used?", risk: "MEDIUM" },
      { id: "CC3", title: "Risk Assessment", description: "Are risks to the achievement of objectives identified, analyzed, and managed?", risk: "HIGH" },
      { id: "CC4", title: "Monitoring Activities", description: "Are ongoing and/or separate evaluations performed to ascertain whether components of internal control are present and functioning?", risk: "HIGH" },
      { id: "CC5", title: "Control Activities", description: "Are control activities selected and developed to mitigate risks to acceptable levels?", risk: "HIGH" },
      { id: "CC6", title: "Logical and Physical Access Controls", description: "Is access to systems, data, and physical facilities restricted to authorized users only?", risk: "CRITICAL" },
      { id: "CC7", title: "System Operations", description: "Are system operations monitored to detect deviations from defined procedures? Is incident response implemented?", risk: "HIGH" },
      { id: "CC8", title: "Change Management", description: "Are changes to infrastructure, data, software, and procedures authorized, tested, and approved?", risk: "HIGH" },
      { id: "CC9", title: "Risk Mitigation", description: "Are activities implemented to mitigate business disruption risks (e.g., environmental events)?", risk: "MEDIUM" }
    ]
  },
  hipaa: {
    name: "HIPAA Security Rule",
    version: "Current",
    description: "Health Insurance Portability and Accountability Act. Sets national standards to protect individuals' electronic personal health information (ePHI).",
    items: [
      { id: "164.308(a)(1)", title: "Security Management Process", description: "Are policies and procedures implemented to prevent, detect, contain, and correct security violations?", risk: "HIGH" },
      { id: "164.308(a)(3)", title: "Workforce Security", description: "Are procedures implemented to ensure that all members of the workforce have appropriate access to ePHI?", risk: "HIGH" },
      { id: "164.308(a)(4)", title: "Information Access Management", description: "Are policies and procedures implemented for authorizing access to ePHI?", risk: "CRITICAL" },
      { id: "164.308(a)(5)", title: "Security Awareness and Training", description: "Is a security awareness and training program implemented for all members of the workforce?", risk: "MEDIUM" },
      { id: "164.308(a)(6)", title: "Security Incident Procedures", description: "Are policies and procedures implemented to address security incidents?", risk: "HIGH" },
      { id: "164.308(a)(7)", title: "Contingency Plan", description: "Are policies and procedures established for responding to an emergency or other occurrence that damages systems containing ePHI?", risk: "HIGH" },
      { id: "164.310(a)(1)", title: "Facility Access Controls", description: "Are physical access to electronic information systems and the facility or facilities in which they are housed limited?", risk: "MEDIUM" },
      { id: "164.310(d)(1)", title: "Device and Media Controls", description: "Are policies and procedures implemented that govern the receipt and removal of hardware and electronic media that contain ePHI?", risk: "MEDIUM" },
      { id: "164.312(a)(1)", title: "Access Control", description: "Are technical policies and procedures implemented for electronic information systems that maintain ePHI to allow access only to those persons or software programs that have been granted access rights?", risk: "CRITICAL" },
      { id: "164.312(b)", title: "Audit Controls", description: "Are hardware, software, and/or procedural mechanisms implemented that record and examine activity in information systems that contain or use ePHI?", risk: "HIGH" },
      { id: "164.312(c)(1)", title: "Integrity", description: "Are policies and procedures implemented to protect ePHI from improper alteration or destruction?", risk: "HIGH" },
      { id: "164.312(e)(1)", title: "Transmission Security", description: "Are technical security measures implemented to guard against unauthorized access to ePHI that is being transmitted over an electronic communications network?", risk: "CRITICAL" }
    ]
  },
  cisv8: {
    name: "CIS Controls v8",
    version: "v8",
    description: "Center for Internet Security Controls. A prioritized set of safeguards to mitigate the most prevalent cyber attacks.",
    items: [
      { id: "CIS 1", title: "Inventory and Control of Enterprise Assets", description: "Are all enterprise assets actively managed (inventoried, tracked, and corrected) so that only authorized devices are given access?", risk: "HIGH" },
      { id: "CIS 2", title: "Inventory and Control of Software Assets", description: "Are all software on the network actively managed so that only authorized software is installed and can execute?", risk: "HIGH" },
      { id: "CIS 3", title: "Data Protection", description: "Are processes and technical controls developed to identify, classify, securely handle, retain, and dispose of data?", risk: "CRITICAL" },
      { id: "CIS 4", title: "Secure Configuration of Enterprise Assets and Software", description: "Are secure configurations established and maintained for enterprise assets (end-user devices, network devices, non-computing/IoT devices, and servers) and software?", risk: "HIGH" },
      { id: "CIS 5", title: "Account Management", description: "Are processes and tools used to assign and manage authorization to credentials for user accounts?", risk: "CRITICAL" },
      { id: "CIS 6", title: "Access Control Management", description: "Are processes and tools used to create, assign, manage, and revoke access credentials and privileges for user, administrator, and service accounts?", risk: "CRITICAL" },
      { id: "CIS 7", title: "Continuous Vulnerability Management", description: "Is new information assessed and tracked to remediate vulnerabilities? Are system updates and patching performed promptly?", risk: "HIGH" },
      { id: "CIS 8", title: "Audit Log Management", description: "Are audit logs collected, alerted on, reviewed, and retained?", risk: "HIGH" },
      { id: "CIS 9", title: "Email and Web Browser Protections", description: "Are protections improved and protections maintained to reduce opportunities for attackers to manipulate human behavior through email and web browsers?", risk: "MEDIUM" },
      { id: "CIS 10", title: "Malware Defenses", description: "Is the installation, spread, and execution of malicious applications, code, or scripts prevented or controlled?", risk: "HIGH" }
    ]
  },
  gdpr: {
    name: "GDPR",
    version: "Current",
    description: "General Data Protection Regulation. The toughest privacy and security law in the world, drafted and passed by the European Union.",
    items: [
      { id: "Art 5", title: "Principles relating to processing of personal data", description: "Is personal data processed lawfully, fairly and in a transparent manner? Is data collected for specified, explicit and legitimate purposes?", risk: "HIGH" },
      { id: "Art 25", title: "Data protection by design and by default", description: "Are appropriate technical and organisational measures implemented to ensure data protection principles are met by design and default?", risk: "HIGH" },
      { id: "Art 28", title: "Processor", description: "Where processing is carried out on behalf of a controller, are only processors providing sufficient guarantees to implement appropriate technical and organisational measures used?", risk: "MEDIUM" },
      { id: "Art 32", title: "Security of processing", description: "Are appropriate technical and organisational measures implemented to ensure a level of security appropriate to the risk, including pseudonymisation and encryption?", risk: "CRITICAL" },
      { id: "Art 33", title: "Notification of a personal data breach to the supervisory authority", description: "In the case of a personal data breach, is the supervisory authority notified without undue delay and, where feasible, not later than 72 hours after having become aware of it?", risk: "CRITICAL" },
      { id: "Art 34", title: "Communication of a personal data breach to the data subject", description: "When the personal data breach is likely to result in a high risk to the rights and freedoms of natural persons, is the data subject communicated the breach without undue delay?", risk: "HIGH" },
      { id: "Art 35", title: "Data protection impact assessment", description: "Where a type of processing is likely to result in a high risk to the rights and freedoms of natural persons, is an assessment of the impact of the envisaged processing operations on the protection of personal data carried out?", risk: "HIGH" }
    ]
  }
};
