use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::Command;

#[derive(Debug)]
struct Vulnerability {
    name: String,
    severity: String,
    description: String,
    cve_id: Option<String>,
    affected_versions: Vec<String>,
    remediation: String,
}

struct ZeroDayHunter {
    vulnerabilities: Vec<Vulnerability>,
    scan_results: HashMap<String, Vec<String>>,
}

impl ZeroDayHunter {
    fn new() -> Self {
        Self {
            vulnerabilities: Vec::new(),
            scan_results: HashMap::new(),
        }
    }

    fn scan_system(&mut self) {
        println!("[+] Starting system vulnerability scan...");
        
        self.scan_installed_software();
        self.scan_network_services();
        self.scan_file_permissions();
        self.scan_running_processes();
        self.scan_registry_entries();
        self.scan_environment_variables();
        
        println!("[+] System scan completed!");
    }

    fn scan_installed_software(&mut self) {
        println!("    [+] Scanning installed software...");
        
        let software_list = vec![
            "chrome", "firefox", "edge", "opera",
            "java", "python", "node", "php",
            "mysql", "postgresql", "mongodb",
            "apache", "nginx", "iis"
        ];

        for software in software_list {
            if let Ok(output) = Command::new("where").arg(software).output() {
                if output.status.success() {
                    let path = String::from_utf8_lossy(&output.stdout);
                    self.scan_results.insert(
                        format!("installed_{}", software),
                        vec![path.trim().to_string()]
                    );
                }
            }
        }
    }

    fn scan_network_services(&mut self) {
        println!("    [+] Scanning network services...");
        
        let ports = vec![21, 22, 23, 25, 53, 80, 443, 445, 3389, 8080];
        
        for port in ports {
            if let Ok(output) = Command::new("netstat").args(&["-an", "-p", "tcp"]).output() {
                let output_str = String::from_utf8_lossy(&output.stdout);
                if output_str.contains(&format!(":{}", port)) {
                    self.scan_results.insert(
                        format!("open_port_{}", port),
                        vec![format!("Port {} is open", port)]
                    );
                }
            }
        }
    }

    fn scan_file_permissions(&mut self) {
        println!("    [+] Scanning file permissions...");
        
        let critical_paths = vec![
            "C:\\Windows\\System32",
            "C:\\Program Files",
            "C:\\Users"
        ];

        for path in critical_paths {
            if Path::new(path).exists() {
                if let Ok(metadata) = fs::metadata(path) {
                    let permissions = metadata.permissions();
                    if permissions.readonly() {
                        self.scan_results.insert(
                            format!("readonly_{}", path.replace("\\", "_")),
                            vec![format!("{} is read-only", path)]
                        );
                    }
                }
            }
        }
    }

    fn scan_running_processes(&mut self) {
        println!("    [+] Scanning running processes...");
        
        if let Ok(output) = Command::new("tasklist").output() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            let suspicious_processes = vec![
                "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"
            ];

            for process in suspicious_processes {
                if output_str.contains(process) {
                    self.scan_results.insert(
                        format!("suspicious_process_{}", process),
                        vec![format!("{} is running", process)]
                    );
                }
            }
        }
    }

    fn scan_registry_entries(&mut self) {
        println!("    [+] Scanning registry entries...");
        
        let registry_keys = vec![
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
        ];

        for key in registry_keys {
            if let Ok(output) = Command::new("reg").args(&["query", key]).output() {
                if output.status.success() {
                    let output_str = String::from_utf8_lossy(&output.stdout);
                    if !output_str.is_empty() {
                        self.scan_results.insert(
                            format!("registry_{}", key.replace("\\", "_")),
                            vec![format!("{} contains entries", key)]
                        );
                    }
                }
            }
        }
    }

    fn scan_environment_variables(&mut self) {
        println!("    [+] Scanning environment variables...");
        
        let env_vars = vec!["PATH", "TEMP", "TMP", "USERPROFILE"];
        
        for var in env_vars {
            if let Ok(value) = std::env::var(var) {
                if !value.is_empty() {
                    self.scan_results.insert(
                        format!("env_{}", var),
                        vec![format!("{} = {}", var, value)]
                    );
                }
            }
        }
    }

    fn analyze_vulnerabilities(&mut self) {
        println!("[+] Analyzing potential vulnerabilities...");
        
        let mut vuln_count = 0;
        
        for (key, values) in &self.scan_results {
            if key.contains("suspicious") || key.contains("open_port") {
                let vuln = Vulnerability {
                    name: format!("Potential security issue: {}", key),
                    severity: "Medium".to_string(),
                    description: format!("Detected: {}", values.join(", ")),
                    cve_id: None,
                    affected_versions: vec!["Unknown".to_string()],
                    remediation: "Review and secure if necessary".to_string(),
                };
                self.vulnerabilities.push(vuln);
                vuln_count += 1;
            }
        }
        
        println!("    [+] Found {} potential vulnerabilities", vuln_count);
    }

    fn generate_report(&self) {
        println!("\n===============================================");
        println!("    XILLEN Zero-Day Hunter Report");
        println!("===============================================");
        println!("Scan completed at: {}", chrono::Utc::now());
        println!("Total scan results: {}", self.scan_results.len());
        println!("Vulnerabilities found: {}", self.vulnerabilities.len());
        
        if !self.vulnerabilities.is_empty() {
            println!("\nVulnerabilities:");
            for (i, vuln) in self.vulnerabilities.iter().enumerate() {
                println!("{}. {} (Severity: {})", i + 1, vuln.name, vuln.severity);
                println!("   Description: {}", vuln.description);
                println!("   Remediation: {}", vuln.remediation);
                println!();
            }
        }
        
        println!("\nScan Results Summary:");
        for (key, values) in &self.scan_results {
            println!("- {}: {}", key, values.join(", "));
        }
    }

    fn save_report(&self, filename: &str) -> std::io::Result<()> {
        let mut report = String::new();
        report.push_str("XILLEN Zero-Day Hunter Report\n");
        report.push_str("==============================\n\n");
        report.push_str(&format!("Scan completed at: {}\n", chrono::Utc::now()));
        report.push_str(&format!("Total scan results: {}\n", self.scan_results.len()));
        report.push_str(&format!("Vulnerabilities found: {}\n\n", self.vulnerabilities.len()));

        if !self.vulnerabilities.is_empty() {
            report.push_str("Vulnerabilities:\n");
            for (i, vuln) in self.vulnerabilities.iter().enumerate() {
                report.push_str(&format!("{}. {} (Severity: {})\n", i + 1, vuln.name, vuln.severity));
                report.push_str(&format!("   Description: {}\n", vuln.description));
                report.push_str(&format!("   Remediation: {}\n\n", vuln.remediation));
            }
        }

        report.push_str("Scan Results Summary:\n");
        for (key, values) in &self.scan_results {
            report.push_str(&format!("- {}: {}\n", key, values.join(", ")));
        }

        fs::write(filename, report)
    }
}

fn main() {
    println!("===============================================");
    println!("    XILLEN Zero-Day Hunter");
    println!("    Поиск уязвимостей нулевого дня");
    println!("===============================================");
    println!("Author: @Bengamin_Button");
    println!("Team: @XillenAdapter");
    println!();

    let mut hunter = ZeroDayHunter::new();
    
    hunter.scan_system();
    hunter.analyze_vulnerabilities();
    hunter.generate_report();
    
    if let Err(e) = hunter.save_report("zero_day_hunter_report.txt") {
        eprintln!("[-] Failed to save report: {}", e);
    } else {
        println!("[+] Report saved to: zero_day_hunter_report.txt");
    }
    
    println!("\n[+] Zero-Day Hunter completed successfully!");
}
