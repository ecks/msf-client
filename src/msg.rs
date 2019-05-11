use std::str;
use std::collections::HashMap;

use serde::{Serialize,Deserialize};

// reference: https://metasploit.help.rapid7.com/docs/standard-api-methods-reference

pub trait Msg {
    // Module name
    fn mn() -> &'static str;
}

//type SessionMapVec = HashMap<String, Vec<String>>;
type SessionMap = HashMap<String, String>;

pub enum MsgType {
    WithAuthLogin(AuthLogin),
    WithCoreVersion(CoreVersion),
    WithModuleExploits(ModuleExploits),
    WithModuleInfo(ModuleInfo),
    WithModuleOptions(ModuleOptions),
    WithModuleTargetCompatiblePayloads(ModuleTargetCompatiblePayloads),
//    WithVec(SessionMapVec),
    WithString(SessionMap),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthLogin {
    pub result: String,
    pub token: String,
}

impl Msg for AuthLogin {
    fn mn() -> &'static str {
        "auth.login"
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CoreVersion {
    pub version: String,
    pub ruby: String,
    pub api: String,
}

impl Msg for CoreVersion {
    fn mn() -> &'static str {
        return "core.version"
    }
}
#[derive(Serialize, Deserialize, Debug)]
pub struct ModuleExploits {
    pub modules: Vec<String>,
}

impl Msg for ModuleExploits {
    fn mn() -> &'static str {
        return "module.exploits"
    }
}
#[derive(Serialize, Deserialize, Debug)]
pub struct ModulePayloads {
    pub payloads: Vec<String>,
}

impl Msg for ModulePayloads {
    fn mn() -> &'static str {
        return "module.payloads"
    }
}
#[derive(Serialize, Deserialize, Debug)]
pub struct ModuleInfo {
    pub name: String,
    pub description: String,
    pub license: String,
    pub default_target: u32,
}

impl Msg for ModuleInfo {
    fn mn() -> &'static str {
        return "module.info"
    }
}
#[derive(Serialize, Deserialize, Debug)]
pub struct DisPayHandlr {
    pub required: bool,
    pub desc: String,
    pub default: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RHosts {
    pub required: bool,
    pub desc: String,
    pub default: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RPort {
    pub required: bool,
    pub desc: String,
    pub default: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ModuleOptions {
    pub DisablePayloadHandler: DisPayHandlr,
    pub RHOSTS: RHosts,
    pub RPORT: RPort,
}

impl Msg for ModuleOptions {
    fn mn() -> &'static str {
        return "module.options"
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ModuleTargetCompatiblePayloads {
    pub payloads: Vec<String>,
}

impl Msg for ModuleTargetCompatiblePayloads {
    fn mn() -> &'static str {
        return "module.target_compatible_payloads"
    }
}
