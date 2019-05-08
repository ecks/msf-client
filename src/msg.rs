use serde::{Serialize,Deserialize};

// reference: https://metasploit.help.rapid7.com/docs/standard-api-methods-reference

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthLogin {
    pub result: String,
    pub token: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CoreVersion {
    pub version: String,
    pub ruby: String,
    pub api: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ModuleExploits {
    pub modules: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ModuleInfo {
    pub name: String,
    pub description: String,
    pub license: String,
}
