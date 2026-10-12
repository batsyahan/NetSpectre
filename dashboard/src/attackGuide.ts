// Reference data for the Attack Guide page. Scores are the XGBoost-only results on the held-out temporal
// test split of CICIDS2017 (499,605 flows, 35 features); source: docs/EVAL_TEST_SET.txt (ml/eval_final.py).
export interface AttackInfo {
  name: string;
  what: string;
  example: string;
  precision: number;
  recall: number;
  f1: number;
  support: number; // test flows of this class
  note?: string;
}

export const GUIDE_STATS = {
  testFlows: 499_605,
  accuracy: 99.4,
  macroF1: 0.852,
  benignFalsePositive: 0.14,
  features: 35,
  classes: 15,
};

export const ATTACK_GUIDE: AttackInfo[] = [
  {
    name: "BENIGN",
    what: "Normal, harmless traffic. This is the class every other class is separated from.",
    example: "Browsing a website, streaming video, DNS lookups, software updates.",
    precision: 0.9988, recall: 0.9986, f1: 0.9987, support: 414453,
  },
  {
    name: "DDoS",
    what: "Distributed denial of service: many machines flood one target at once so real users cannot reach it.",
    example: "A botnet of hundreds of devices sending HTTP floods to a web server (LOIC-style tool in the dataset).",
    precision: 0.9983, recall: 0.9987, f1: 0.9985, support: 25603,
  },
  {
    name: "DoS Hulk",
    what: "A single machine floods a web server with requests for constantly changing URLs so caching cannot help.",
    example: "Thousands of GET requests per second to /?random=83912 style addresses.",
    precision: 0.9984, recall: 0.9426, f1: 0.9697, support: 34570,
    note: "About 2% of Hulk flows were mistaken for PortScan and 2% for normal traffic.",
  },
  {
    name: "DoS GoldenEye",
    what: "HTTP denial of service that keeps connections alive and randomises request headers to exhaust a server.",
    example: "Many keep-alive connections with random user agents and cache-busting parameters.",
    precision: 0.9315, recall: 0.9976, f1: 0.9634, support: 2057,
  },
  {
    name: "DoS slowloris",
    what: "Opens many connections and sends HTTP headers very slowly, so the server runs out of connection slots.",
    example: "Hundreds of half-finished requests, each adding one header line every few seconds.",
    precision: 0.9187, recall: 0.8930, f1: 0.9057, support: 1075,
  },
  {
    name: "DoS Slowhttptest",
    what: "Slow-HTTP attacks (slow headers, slow body, slow read) that hold connections open to starve the server.",
    example: "A client that reads the response one byte at a time.",
    precision: 0.8633, recall: 0.9904, f1: 0.9225, support: 1046,
  },
  {
    name: "PortScan",
    what: "Probing many ports on a machine to find which services are open. Usually the first step before an attack.",
    example: "nmap -sS against a router or laptop. This is the attack the project demo triggers live.",
    precision: 0.9364, recall: 0.9963, f1: 0.9654, support: 18139,
    note: "Live test on a Docker network: 90% of scan flows detected after retraining with captured scans.",
  },
  {
    name: "FTP-Patator",
    what: "Automated password guessing against an FTP server using the Patator tool.",
    example: "Thousands of FTP login attempts with different passwords from one address.",
    precision: 0.9992, recall: 1.0, f1: 0.9996, support: 1187,
  },
  {
    name: "SSH-Patator",
    what: "Automated password guessing against an SSH server, the usual way remote logins are attacked.",
    example: "Rapid repeated SSH connections trying many username and password pairs.",
    precision: 0.9908, recall: 1.0, f1: 0.9954, support: 644,
  },
  {
    name: "Bot",
    what: "A device infected with malware that takes orders from an attacker's command server (a botnet member).",
    example: "A compromised PC regularly contacting a control server, uploading data and receiving tasks.",
    precision: 0.5, recall: 1.0, f1: 0.6667, support: 390,
    note: "Weak point: finds every bot but half of its alerts are false (normal flows mistaken for Bot).",
  },
  {
    name: "Web Attack - Brute Force",
    what: "Guessing passwords on a web application's login form.",
    example: "Hundreds of POST requests to a login page with different passwords.",
    precision: 0.5109, recall: 0.6395, f1: 0.568, support: 294,
    note: "Hard to separate from XSS: both look like ordinary HTTP form traffic at the flow level.",
  },
  {
    name: "Web Attack - XSS",
    what: "Cross-site scripting: injecting malicious script into a web page that other visitors then run.",
    example: "A comment form submitted with a <script> tag in it.",
    precision: 0.2795, recall: 0.4885, f1: 0.3556, support: 131,
    note: "Weakest class. The model only sees flow statistics, not request contents, so it cannot read the script.",
  },
  {
    name: "Web Attack - Sql Injection",
    what: "Sending database commands through a web form to read or change data the attacker should not reach.",
    example: "Entering ' OR '1'='1 into a login or search field.",
    precision: 0.5556, recall: 1.0, f1: 0.7143, support: 5,
    note: "Only 5 test flows: the score is not statistically meaningful.",
  },
  {
    name: "Infiltration",
    what: "An attacker gets inside the network (for example through a malicious file) and then explores from there.",
    example: "A infected laptop that starts scanning other machines on the internal network.",
    precision: 0.6154, recall: 1.0, f1: 0.7619, support: 8,
    note: "Only 8 test flows: not statistically meaningful. Alerts need 80% model confidence to count.",
  },
  {
    name: "Heartbleed",
    what: "Exploiting the 2014 OpenSSL bug (CVE-2014-0160) to read secrets out of a server's memory.",
    example: "Malformed TLS heartbeat requests that return chunks of memory.",
    precision: 1.0, recall: 1.0, f1: 1.0, support: 3,
    note: "Only 3 test flows: not statistically meaningful. Alerts need 80% model confidence to count.",
  },
];
