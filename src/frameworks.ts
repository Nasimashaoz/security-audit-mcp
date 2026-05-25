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
    description: "Payment Card Industry Data Security Standard, required for all entities that store, process, or transmit cardholder data.",
    items: [
      { id: "Req-1", title: "Network Security Controls", description: "Are network security controls (NSCs) installed and maintained? Are configurations reviewed every 6 months?", risk: "HIGH" },
      { id: "Req-2", title: "Secure Configurations", description: "Are default passwords changed? Are unused services and accounts disabled?", risk: "CRITICAL" },
      { id: "Req-3", title: "Protect Account Data", description: "Is stored account data kept to a minimum? Is Primary Account Number (PAN) unreadable anywhere it is stored?", risk: "CRITICAL" },
      { id: "Req-4", title: "Cryptography in Transit", description: "Is strong cryptography used to protect PAN during transmission over open, public networks?", risk: "CRITICAL" },
      { id: "Req-5", title: "Malware Defenses", description: "Are anti-malware solutions deployed on all systems commonly affected by malicious software?", risk: "HIGH" },
      { id: "Req-6", title: "Secure Systems and Software", description: "Are vulnerabilities identified and assigned a risk ranking? Are critical patches installed within one month?", risk: "CRITICAL" },
      { id: "Req-7", title: "Access Based on Need-to-Know", description: "Is access to system components and cardholder data restricted to only those individuals whose job requires such access?", risk: "HIGH" },
      { id: "Req-8", title: "Identify Users and Authenticate Access", description: "Is multi-factor authentication (MFA) required for all access to the CDE?", risk: "CRITICAL" },
      { id: "Req-9", title: "Physical Access", description: "Is physical access to the CDE restricted and monitored? Are media backups stored securely?", risk: "HIGH" },
      { id: "Req-10", title: "Log and Monitor", description: "Are audit logs implemented for all system components? Are logs reviewed regularly to identify anomalies?", risk: "HIGH" },
      { id: "Req-11", title: "Test Security of Systems", description: "Are internal and external vulnerability scans performed at least quarterly? Are penetration tests performed annually?", risk: "HIGH" },
      { id: "Req-12", title: "Information Security Policy", description: "Is an information security policy published, maintained, and disseminated to all personnel?", risk: "MEDIUM" }
    ]
  },
  soc2: {
    name: "SOC 2 Type II",
    version: "Current",
    description: "Service Organization Control 2, focusing on Security, Availability, Processing Integrity, Confidentiality, and Privacy.",
    items: [
      { id: "CC1", title: "Control Environment", description: "Does the entity demonstrate a commitment to integrity and ethical values? Is board of directors independence maintained?", risk: "MEDIUM" },
      { id: "CC2", title: "Communication and Information", description: "Is relevant, quality information generated and used to support the functioning of internal control?", risk: "MEDIUM" },
      { id: "CC3", title: "Risk Assessment", description: "Are risks to the achievement of objectives identified and analyzed? Are changes that could impact internal control assessed?", risk: "HIGH" },
      { id: "CC4", title: "Monitoring Activities", description: "Are ongoing or separate evaluations conducted to ascertain whether the components of internal control are present and functioning?", risk: "MEDIUM" },
      { id: "CC5", title: "Control Activities", description: "Are control activities selected and developed to mitigate risks to acceptable levels?", risk: "HIGH" },
      { id: "CC6", title: "Logical and Physical Access", description: "Is access to IT infrastructure, data, and software restricted to authorized personnel? Is MFA enforced?", risk: "CRITICAL" },
      { id: "CC7", title: "System Operations", description: "Are systems monitored for anomalies? Are incident response procedures defined and executed when necessary?", risk: "HIGH" },
      { id: "CC8", title: "Change Management", description: "Are changes to systems, infrastructure, and software authorized, tested, and approved before migration to production?", risk: "HIGH" },
      { id: "CC9", title: "Risk Mitigation", description: "Are business disruption risks mitigated through disaster recovery and business continuity plans?", risk: "HIGH" }
    ]
  },
  hipaa: {
    name: "HIPAA Security Rule",
    version: "Current",
    description: "Health Insurance Portability and Accountability Act, required for protecting electronic protected health information (ePHI).",
    items: [
      { id: "164.308(a)(1)", title: "Security Management Process", description: "Is a formal risk analysis conducted? Are risk management policies implemented to reduce risks to a reasonable and appropriate level?", risk: "CRITICAL" },
      { id: "164.308(a)(3)", title: "Workforce Security", description: "Are policies in place to ensure all members of the workforce have appropriate access to ePHI and to prevent those who should not have access from obtaining it?", risk: "HIGH" },
      { id: "164.308(a)(4)", title: "Information Access Management", description: "Are policies in place for authorizing access to ePHI consistent with the Privacy Rule?", risk: "HIGH" },
      { id: "164.308(a)(5)", title: "Security Awareness and Training", description: "Is security awareness and training provided for all workforce members, including management?", risk: "MEDIUM" },
      { id: "164.308(a)(6)", title: "Security Incident Procedures", description: "Are policies and procedures implemented to address security incidents, including identifying, responding to, and mitigating harmful effects?", risk: "HIGH" },
      { id: "164.308(a)(7)", title: "Contingency Plan", description: "Is a data backup plan, disaster recovery plan, and emergency mode operation plan established and tested?", risk: "HIGH" },
      { id: "164.310(a)(1)", title: "Facility Access Controls", description: "Are policies and procedures implemented to limit physical access to electronic information systems?", risk: "MEDIUM" },
      { id: "164.310(d)(1)", title: "Device and Media Controls", description: "Are policies in place for the receipt, removal, and secure disposal of hardware and electronic media containing ePHI?", risk: "HIGH" },
      { id: "164.312(a)(1)", title: "Access Control", description: "Are technical policies implemented to allow access only to those persons or software programs that have been granted access rights?", risk: "CRITICAL" },
      { id: "164.312(b)", title: "Audit Controls", description: "Are hardware, software, or procedural mechanisms implemented that record and examine activity in information systems?", risk: "HIGH" },
      { id: "164.312(c)(1)", title: "Integrity", description: "Are policies implemented to protect ePHI from improper alteration or destruction?", risk: "HIGH" },
      { id: "164.312(e)(1)", title: "Transmission Security", description: "Are technical security measures implemented to guard against unauthorized access to ePHI that is being transmitted over an electronic communications network (e.g., encryption)?", risk: "CRITICAL" }
    ]
  },
  cisv8: {
    name: "CIS Controls",
    version: "v8",
    description: "Center for Internet Security Controls, a prioritized set of actions to protect organizations and data from known cyber attack vectors.",
    items: [
      { id: "IG1-1", title: "Inventory and Control of Enterprise Assets", description: "Is there an active inventory of all enterprise assets (hardware, software, data)?", risk: "HIGH" },
      { id: "IG1-2", title: "Inventory and Control of Software Assets", description: "Is there an active inventory of all software assets, ensuring only authorized software executes?", risk: "HIGH" },
      { id: "IG1-3", title: "Data Protection", description: "Are processes and tools developed to identify, classify, securely handle, retain, and dispose of data?", risk: "CRITICAL" },
      { id: "IG1-4", title: "Secure Configuration of Enterprise Assets", description: "Are secure configurations established and maintained for enterprise assets and software?", risk: "HIGH" },
      { id: "IG1-5", title: "Account Management", description: "Are processes and tools used to assign and manage authorization to credentials for user accounts, including administrator accounts?", risk: "CRITICAL" },
      { id: "IG1-6", title: "Access Control Management", description: "Are tools and processes used to create, assign, manage, and revoke access credentials and privileges?", risk: "CRITICAL" },
      { id: "IG1-7", title: "Continuous Vulnerability Management", description: "Is a continuous vulnerability management process implemented to track and remediate vulnerabilities?", risk: "HIGH" },
      { id: "IG1-8", title: "Audit Log Management", description: "Are audit logs collected, analyzed, and retained securely for all critical systems?", risk: "MEDIUM" },
      { id: "IG1-9", title: "Email and Web Browser Protections", description: "Are protections improved and maintained for email and web vectors?", risk: "HIGH" },
      { id: "IG1-10", title: "Malware Defenses", description: "Is execution of malicious software prevented, or its spread controlled?", risk: "HIGH" },
      { id: "IG1-11", title: "Data Recovery", description: "Are sufficient data recovery practices in place to restore systems to a trusted state?", risk: "HIGH" },
      { id: "IG1-12", title: "Network Infrastructure Management", description: "Are network devices securely managed and maintained?", risk: "MEDIUM" },
      { id: "IG1-13", title: "Network Monitoring and Defense", description: "Is the network monitored to identify and prevent threats?", risk: "HIGH" },
      { id: "IG1-14", title: "Security Awareness and Skills Training", description: "Is a security awareness program established and maintained to influence behavior among the workforce?", risk: "MEDIUM" },
      { id: "IG1-15", title: "Service Provider Management", description: "Are processes developed to evaluate service providers who hold sensitive data or are responsible for critical IT platforms?", risk: "MEDIUM" },
      { id: "IG1-16", title: "Application Software Security", description: "Is the security lifecycle of in-house developed software managed, or are secure applications acquired?", risk: "HIGH" },
      { id: "IG1-17", title: "Incident Response Management", description: "Is a program established to develop and maintain an incident response capability?", risk: "HIGH" },
      { id: "IG1-18", title: "Penetration Testing", description: "Is the effectiveness and resiliency of enterprise assets tested by identifying and exploiting vulnerabilities?", risk: "MEDIUM" }
    ]
  },
  gdpr: {
    name: "GDPR",
    version: "2016/679",
    description: "General Data Protection Regulation, the core of Europe's digital privacy legislation.",
    items: [
      { id: "Art-5", title: "Principles relating to processing of personal data", description: "Is personal data processed lawfully, fairly, and in a transparent manner? Is it collected for specified, explicit, and legitimate purposes?", risk: "HIGH" },
      { id: "Art-25", title: "Data protection by design and by default", description: "Are appropriate technical and organisational measures designed to implement data-protection principles (e.g., pseudonymisation) integrated into the processing?", risk: "HIGH" },
      { id: "Art-28", title: "Processor", description: "Where processing is to be carried out on behalf of a controller, are only processors providing sufficient guarantees used? Are contracts in place?", risk: "HIGH" },
      { id: "Art-30", title: "Records of processing activities", description: "Does the controller/processor maintain a record of processing activities under its responsibility?", risk: "MEDIUM" },
      { id: "Art-32", title: "Security of processing", description: "Are appropriate technical and organisational measures (e.g., encryption, resilience of systems) implemented to ensure a level of security appropriate to the risk?", risk: "CRITICAL" },
      { id: "Art-33", title: "Notification of a personal data breach to the supervisory authority", description: "Is there a process to notify the supervisory authority without undue delay (and where feasible, within 72 hours) after becoming aware of a personal data breach?", risk: "CRITICAL" },
      { id: "Art-34", title: "Communication of a personal data breach to the data subject", description: "Is there a process to communicate the personal data breach to the data subject without undue delay when the breach is likely to result in a high risk to their rights and freedoms?", risk: "HIGH" },
      { id: "Art-35", title: "Data protection impact assessment", description: "Is a Data Protection Impact Assessment (DPIA) carried out prior to the processing when a type of processing is likely to result in a high risk?", risk: "HIGH" },
      { id: "Art-37", title: "Designation of the data protection officer", description: "Has a Data Protection Officer (DPO) been designated where required by the regulation?", risk: "MEDIUM" }
    ]
  }
};
