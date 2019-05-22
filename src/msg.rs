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
}

#[derive(Serialize, Debug)]
pub struct AuthLoginCmd(pub String, pub String, pub String);

pub enum RetType {
    WAuthLoginRet(AuthLoginRet),
    WCoreVersionRet(CoreVersionRet),
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
pub struct CoreVersionRet {
    pub version: String,
    pub ruby: String,
    pub api: String,
}

impl Msg for CoreVersionRet {
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
