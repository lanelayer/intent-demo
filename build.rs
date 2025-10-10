use std::process::Command;

fn main() {
    // Get current timestamp
    let output = Command::new("date")
        .arg("+%Y-%m-%d %H:%M:%S")
        .output()
        .expect("Failed to execute date command");
    
    let timestamp = String::from_utf8(output.stdout)
        .expect("Invalid UTF-8")
        .trim()
        .to_string();
    
    println!("cargo:rustc-env=BUILD_TIMESTAMP={}", timestamp);
    // Always rerun to get fresh timestamp - don't use rerun-if-changed
}


