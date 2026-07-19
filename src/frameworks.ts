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
};

FRAMEWORKS["pci-dss"] = {
  name: "PCI-DSS",
  version: "v4.0",
  description: "Payment Card Industry Data Security Standard for organizations that handle branded credit cards.",
  items: [
    { id: "Req-1", title: "Network Security Controls", description: "Install and maintain network security controls.", risk: "HIGH" },
    { id: "Req-2", title: "Secure Configurations", description: "Apply secure configurations to all system components.", risk: "HIGH" },
    { id: "Req-3", title: "Protect Stored Account Data", description: "Protect stored account data.", risk: "CRITICAL" },
    { id: "Req-4", title: "Protect Data in Transit", description: "Protect account data with strong cryptography during transmission over open, public networks.", risk: "CRITICAL" },
    { id: "Req-5", title: "Protect from Malicious Software", description: "Protect all systems and networks from malicious software.", risk: "HIGH" },
    { id: "Req-6", title: "Develop and Maintain Secure Systems", description: "Develop and maintain secure systems and software.", risk: "HIGH" },
    { id: "Req-7", title: "Restrict Access to Data", description: "Restrict access to system components and cardholder data by business need to know.", risk: "CRITICAL" },
    { id: "Req-8", title: "Identify Users and Authenticate Access", description: "Identify users and authenticate access to system components.", risk: "CRITICAL" },
    { id: "Req-9", title: "Restrict Physical Access", description: "Restrict physical access to cardholder data.", risk: "HIGH" },
    { id: "Req-10", title: "Log and Monitor Access", description: "Log and monitor all access to system components and cardholder data.", risk: "HIGH" },
    { id: "Req-11", title: "Test Security Systems", description: "Test security of systems and networks regularly.", risk: "HIGH" },
    { id: "Req-12", title: "Manage Information Security", description: "Support information security with organizational policies and programs.", risk: "MEDIUM" },
  ]
};

FRAMEWORKS["soc2"] = {
  name: "SOC 2",
  version: "Type II",
  description: "Service Organization Control 2 criteria for managing customer data based on five trust service principles.",
  items: [
    { id: "CC1", title: "Control Environment", description: "Demonstrate commitment to integrity and ethical values.", risk: "MEDIUM" },
    { id: "CC2", title: "Communication and Information", description: "Generate and use relevant, quality information to support functioning of internal control.", risk: "MEDIUM" },
    { id: "CC3", title: "Risk Assessment", description: "Assess risks to the achievement of objectives.", risk: "HIGH" },
    { id: "CC4", title: "Monitoring Activities", description: "Select, develop, and perform ongoing evaluations to ascertain whether components of internal control are present and functioning.", risk: "HIGH" },
    { id: "CC5", title: "Control Activities", description: "Select and develop control activities that contribute to the mitigation of risks.", risk: "HIGH" },
    { id: "CC6", title: "Logical and Physical Access Controls", description: "Implement logical and physical access controls.", risk: "CRITICAL" },
    { id: "CC7", title: "System Operations", description: "Manage system operations to achieve objectives.", risk: "HIGH" },
    { id: "CC8", title: "Change Management", description: "Authorize, design, develop, and test changes to systems.", risk: "HIGH" },
    { id: "CC9", title: "Risk Mitigation", description: "Mitigate risks from business disruptions and use of vendors.", risk: "HIGH" },
  ]
};

FRAMEWORKS["hipaa"] = {
  name: "HIPAA Security Rule",
  version: "45 CFR Part 160 and Part 164",
  description: "National standards to protect individuals' electronic personal health information.",
  items: [
    { id: "164.308", title: "Administrative Safeguards", description: "Implement policies and procedures to prevent, detect, contain, and correct security violations.", risk: "HIGH" },
    { id: "164.310", title: "Physical Safeguards", description: "Implement physical measures to protect electronic information systems.", risk: "MEDIUM" },
    { id: "164.312", title: "Technical Safeguards", description: "Implement technical policies and procedures for electronic information systems.", risk: "CRITICAL" },
    { id: "164.314", title: "Organizational Requirements", description: "Ensure business associate contracts include security requirements.", risk: "HIGH" },
    { id: "164.316", title: "Policies and Procedures", description: "Implement reasonable and appropriate policies and procedures.", risk: "MEDIUM" },
  ]
};

FRAMEWORKS["cis-v8"] = {
  name: "CIS Controls",
  version: "v8",
  description: "Prioritized set of safeguards to mitigate the most prevalent cyber attacks.",
  items: [
    { id: "CIS-1", title: "Inventory and Control of Enterprise Assets", description: "Actively manage all enterprise assets.", risk: "HIGH" },
    { id: "CIS-2", title: "Inventory and Control of Software Assets", description: "Actively manage all software on the network.", risk: "HIGH" },
    { id: "CIS-3", title: "Data Protection", description: "Develop processes and technical controls to identify, classify, securely handle, retain, and dispose of data.", risk: "CRITICAL" },
    { id: "CIS-4", title: "Secure Configuration", description: "Establish and maintain the secure configuration of enterprise assets.", risk: "HIGH" },
    { id: "CIS-5", title: "Account Management", description: "Use processes and tools to assign and manage authorization to credentials.", risk: "CRITICAL" },
    { id: "CIS-6", title: "Access Control Management", description: "Use processes and tools to create, assign, manage, and revoke access credentials.", risk: "CRITICAL" },
    { id: "CIS-7", title: "Continuous Vulnerability Management", description: "Develop a plan to continuously assess and track vulnerabilities.", risk: "HIGH" },
    { id: "CIS-8", title: "Audit Log Management", description: "Collect, alert, review, and retain audit logs of events.", risk: "HIGH" },
  ]
};

FRAMEWORKS["gdpr"] = {
  name: "GDPR",
  version: "EU 2016/679",
  description: "General Data Protection Regulation for data protection and privacy in the EU.",
  items: [
    { id: "Art-5", title: "Principles relating to processing of personal data", description: "Process personal data lawfully, fairly and in a transparent manner.", risk: "HIGH" },
    { id: "Art-25", title: "Data protection by design and by default", description: "Implement appropriate technical and organisational measures.", risk: "HIGH" },
    { id: "Art-28", title: "Processor", description: "Use only processors providing sufficient guarantees to implement appropriate technical and organisational measures.", risk: "MEDIUM" },
    { id: "Art-32", title: "Security of processing", description: "Implement appropriate technical and organisational measures to ensure a level of security appropriate to the risk.", risk: "CRITICAL" },
    { id: "Art-33", title: "Notification of a personal data breach", description: "Notify the supervisory authority of a personal data breach without undue delay.", risk: "HIGH" },
  ]
};
