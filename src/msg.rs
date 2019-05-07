use serde::{Serialize,Deserialize};


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
