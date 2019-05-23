use std::str;
use std::collections::HashMap;
use serde::{Serialize,Deserialize};

// reference: https://metasploit.help.rapid7.com/docs/standard-api-methods-reference

pub trait Msg {
    // Module name
    fn mn() -> &'static str;
}


#[derive(Serialize, Debug)]
pub enum CmdType {
    WAuthLoginCmd(AuthLoginCmd),
    WCoreVerCmd(CoreVerCmd),
    WModuleExploitsCmd(ModuleExploitsCmd),
    WModuleInfoCmd(ModuleInfoCmd),
    WModuleOptionsCmd(ModuleOptionsCmd),
    WModuleTargetCompatiblePayloadsCmd(ModuleTargetCompatiblePayloadsCmd),
}


#[derive(Serialize, Debug)]
pub struct AuthLoginCmd(String, String, String);

impl AuthLoginCmd {
    pub fn new(uname: String, pswd: String) -> Self {
        let mn = String::from("auth.login");
        AuthLoginCmd(mn, uname, pswd)
    }
}

pub trait Tokenize {
    fn add_token(&mut self, token: String);
}

#[derive(Serialize, Debug)]
pub struct CoreVerCmd(String, Option<String>);

impl CoreVerCmd {
    pub fn new() -> Self {
        let mn = String::from("core.version");
        CoreVerCmd(mn, None)
    }
}

impl Tokenize for CoreVerCmd {
    fn add_token(&mut self, token: String) {
        self.1 = Some(token);
    }
}

#[derive(Serialize, Debug)]
pub struct ModuleExploitsCmd(String, Option<String>);

impl ModuleExploitsCmd {
    pub fn new() -> Self {
        let mn = String::from("module.exploits");
        ModuleExploitsCmd(mn, None)
    }
}

impl Tokenize for ModuleExploitsCmd {
    fn add_token(&mut self, token: String) {
        self.1 = Some(token);
    }
}

#[derive(Serialize, Debug)]
pub struct ModulePayloadsCmd(String, Option<String>);

impl ModulePayloadsCmd {
    pub fn new() -> Self {
        let mn = String::from("module.payloads");
        ModulePayloadsCmd(mn, None)
    }
}

impl Tokenize for ModulePayloadsCmd {
    fn add_token(&mut self, token: String) {
        self.1 = Some(token);
    }
}

#[derive(Serialize, Debug)]
pub struct ModuleInfoCmd(String, Option<String>, String, String);

impl ModuleInfoCmd {
    pub fn new(mtype: String, mname: String) -> Self {
        let mn = String::from("module.info");
        ModuleInfoCmd(mn, None, mtype, mname)
    }
}

impl Tokenize for ModuleInfoCmd {
    fn add_token(&mut self, token: String) {
        self.1 = Some(token);
    }
}

#[derive(Serialize, Debug)]
pub struct ModuleOptionsCmd(String, Option<String>, String, String);

impl ModuleOptionsCmd {
    pub fn new(mtype: String, mname: String) -> Self {
        let mn = String::from("module.options");
        ModuleOptionsCmd(mn, None, mtype, mname)
    }
}

impl Tokenize for ModuleOptionsCmd {
    fn add_token(&mut self, token: String) {
        self.1 = Some(token);
    }
}

#[derive(Serialize, Debug)]
pub struct ModuleTargetCompatiblePayloadsCmd(String, Option<String>, String, String);

impl ModuleTargetCompatiblePayloadsCmd {
    // target id: (default: 0, e.g. 'Automatic')
    pub fn new(mname: String, target_id: String) -> Self {
        let mn = String::from("module.target_compatible_payloads");
        ModuleTargetCompatiblePayloadsCmd(mn, None, mname, target_id)
    }
}

impl Tokenize for ModuleTargetCompatiblePayloadsCmd {
    fn add_token(&mut self, token: String) {
        self.1 = Some(token);
    }
}

pub enum RetType {
    WAuthLoginRet(AuthLoginRet),
    WCoreVerRet(CoreVerRet),
    WModuleExploitsRet(ModuleExploitsRet),
    WModuleInfoRet(ModuleInfoRet),
    WModuleOptionsRet(ModuleOptionsRet),
    WModuleTargetCompatiblePayloadsRet(ModuleTargetCompatiblePayloadsRet),
}

#[derive(Deserialize, Debug)]
pub struct AuthLoginRet {
    pub result: String,
    pub token: String,
}

impl Msg for AuthLoginRet {
    fn mn() -> &'static str {
        "auth.login"
    }
}

#[derive(Deserialize, Debug)]
pub struct CoreVerRet {
    pub version: String,
    pub ruby: String,
    pub api: String,
}

impl Msg for CoreVerRet {
    fn mn() -> &'static str {
        return "core.version"
    }
}
#[derive(Deserialize, Debug)]
pub struct ModuleExploitsRet {
    pub modules: Vec<String>,
}

impl Msg for ModuleExploitsRet {
    fn mn() -> &'static str {
        return "module.exploits"
    }
}
#[derive(Deserialize, Debug)]
pub struct ModulePayloadsRet {
    pub payloads: Vec<String>,
}

impl Msg for ModulePayloadsRet {
    fn mn() -> &'static str {
        return "module.payloads"
    }
}
#[derive(Deserialize, Debug)]
pub struct ModuleInfoRet {
    pub name: String,
    pub description: String,
    pub license: String,
    pub default_target: u32,
}

impl Msg for ModuleInfoRet {
    fn mn() -> &'static str {
        return "module.info"
    }
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub enum ModuleOptionRet {
  DefaultBool { r#type: String, required: bool, advanced: bool, desc: String, default: bool },
  DefaultInt { r#type: String, required: bool, advanced: bool, desc: String, default: u32 },
  DefaultEnum { r#type: String, required: bool, advanced: bool, desc: String, default: String, enums: Vec<String> },
  NoDefault { r#type: String, required: bool, advanced: bool, desc: String },
}

pub type ModuleOptionsRet = HashMap<String, ModuleOptionRet>;

impl Msg for ModuleOptionsRet {
    fn mn() -> &'static str {
        return "module.options"
    }
}

#[derive(Deserialize, Debug)]
pub struct ModuleTargetCompatiblePayloadsRet {
    pub payloads: Vec<String>,
}

impl Msg for ModuleTargetCompatiblePayloadsRet {
    fn mn() -> &'static str {
        return "module.target_compatible_payloads"
    }
}
