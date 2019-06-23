use std::str;
use std::collections::HashMap;
use serde::{Serialize,Deserialize};

use crate::common::RunOptions;

// reference: https://metasploit.help.rapid7.com/docs/standard-api-methods-reference

#[derive(Serialize, Debug)]
pub enum CmdType {
    WAuthLoginCmd(AuthLoginCmd),
    WCoreVerCmd(CoreVerCmd),
    WModuleExploitsCmd(ModuleExploitsCmd),
    WModulePayloadsCmd(ModulePayloadsCmd),
    WModulePostCmd(ModulePostCmd),
    WModuleAuxiliaryCmd(ModuleAuxiliaryCmd),
    WModuleEncodersCmd(ModuleEncodersCmd),
    WModuleNopsCmd(ModuleNopsCmd),
    WModuleInfoCmd(ModuleInfoCmd),
    WModuleOptionsCmd(ModuleOptionsCmd),
    WModuleExecuteCmd(ModuleExecuteCmd),
    WModuleTargetCompatiblePayloadsCmd(ModuleTargetCompatiblePayloadsCmd),
    WSessionMeterpreterReadCmd(SessionMeterpreterReadCmd),
    WSessionShellReadCmd(SessionShellReadCmd),
    WSessionMeterpreterWriteCmd(SessionMeterpreterWriteCmd),
    WSessionShellWriteCmd(SessionShellWriteCmd),
    WSessionListCmd(SessionListCmd),
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
    #[allow(clippy::new_without_default)]
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
    #[allow(clippy::new_without_default)]
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
    #[allow(clippy::new_without_default)]
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
pub struct ModulePostCmd(String, Option<String>);

impl ModulePostCmd {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let mn = String::from("module.post");
        ModulePostCmd(mn, None)
    }
}

impl Tokenize for ModulePostCmd {
    fn add_token(&mut self, token: String) {
        self.1 = Some(token);
    }
}

#[derive(Serialize, Debug)]
pub struct ModuleAuxiliaryCmd(String, Option<String>);

impl ModuleAuxiliaryCmd {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let mn = String::from("module.auxiliary");
        ModuleAuxiliaryCmd(mn, None)
    }
}

impl Tokenize for ModuleAuxiliaryCmd {
    fn add_token(&mut self, token: String) {
        self.1 = Some(token);
    }
}

#[derive(Serialize, Debug)]
pub struct ModuleEncodersCmd(String, Option<String>);

impl ModuleEncodersCmd {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let mn = String::from("module.encoders");
        ModuleEncodersCmd(mn, None)
    }
}

impl Tokenize for ModuleEncodersCmd {
    fn add_token(&mut self, token: String) {
        self.1 = Some(token);
    }
}

#[derive(Serialize, Debug)]
pub struct ModuleNopsCmd(String, Option<String>);

impl ModuleNopsCmd {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let mn = String::from("module.nops");
        ModuleNopsCmd(mn, None)
    }
}

impl Tokenize for ModuleNopsCmd {
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
pub struct ModuleExecuteCmd(String, Option<String>, String, String, RunOptions);

impl ModuleExecuteCmd {
    pub fn new(mtype: String, mname: String, r_options: RunOptions) -> Self {
        let mn = String::from("module.execute");
        ModuleExecuteCmd(mn, None, mtype, mname, r_options)
    }
}

impl Tokenize for ModuleExecuteCmd {
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

#[derive(Serialize, Debug)]
pub struct SessionMeterpreterReadCmd(String, Option<String>, u32);

impl SessionMeterpreterReadCmd {
    pub fn new(id: u32) -> Self {
        let mn = String::from("session.meterpreter_read");
        SessionMeterpreterReadCmd(mn, None, id)
    }
}

impl Tokenize for SessionMeterpreterReadCmd {
    fn add_token(&mut self, token: String) {
        self.1 = Some(token);
    }
}

#[derive(Serialize, Debug)]
pub struct SessionShellReadCmd(String, Option<String>, u32);

impl SessionShellReadCmd {
    pub fn new(id: u32) -> Self {
        let mn = String::from("session.shell_read");
        SessionShellReadCmd(mn, None, id)
    }
}

impl Tokenize for SessionShellReadCmd {
    fn add_token(&mut self, token: String) {
        self.1 = Some(token);
    }
}

#[derive(Serialize, Debug)]
pub struct SessionMeterpreterWriteCmd(String, Option<String>, u32, String);

impl SessionMeterpreterWriteCmd {
    pub fn new(id: u32, data: String) -> Self {
        let mn = String::from("session.meterpreter_write");
        SessionMeterpreterWriteCmd(mn, None, id, data)
    }
}

impl Tokenize for SessionMeterpreterWriteCmd {
    fn add_token(&mut self, token: String) {
        self.1 = Some(token);
    }
}

#[derive(Serialize, Debug)]
pub struct SessionShellWriteCmd(String, Option<String>, u32, String);

impl SessionShellWriteCmd {
    pub fn new(id: u32, data: String) -> Self {
        let mn = String::from("session.shell_write");
        SessionShellWriteCmd(mn, None, id, data)
    }
}

impl Tokenize for SessionShellWriteCmd {
    fn add_token(&mut self, token: String) {
        self.1 = Some(token);
    }
}

#[derive(Serialize, Debug)]
pub struct SessionListCmd(String, Option<String>);

impl SessionListCmd {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let mn = String::from("session.list");
        SessionListCmd(mn, None)
    }
}

impl Tokenize for SessionListCmd {
    fn add_token(&mut self, token: String) {
        self.1 = Some(token);
    }
}

pub enum RetType {
    WAuthLoginRet(AuthLoginRet),
    WCoreVerRet(CoreVerRet),
    WModuleExploitsRet(ModuleExploitsRet),
    WModulePayloadsRet(ModulePayloadsRet),
    WModulePostRet(ModulePostRet),
    WModuleAuxiliaryRet(ModuleAuxiliaryRet),
    WModuleEncodersRet(ModuleEncodersRet),
    WModuleNopsRet(ModuleNopsRet),
    WModuleInfoRet(ModuleInfoRet),
    WModuleOptionsRet(ModuleOptionsRet),
    WModuleExecuteRet(ModuleExecuteRet),
    WModuleTargetCompatiblePayloadsRet(ModuleTargetCompatiblePayloadsRet),
    WSessionMeterpreterReadRet(SessionMeterpreterReadRet),
    WSessionShellReadRet(SessionShellReadRet),
    WSessionMeterpreterWriteRet(SessionMeterpreterWriteRet),
    WSessionShellWriteRet(SessionShellWriteRet),
    WSessionListRet(SessionListRet),
}

#[derive(Deserialize, Debug)]
pub struct AuthLoginRet {
    pub result: String,
    pub token: String,
}

#[derive(Deserialize, Debug)]
pub struct CoreVerRet {
    pub version: String,
    pub ruby: String,
    pub api: String,
}

#[derive(Deserialize, Debug)]
pub struct ModuleExploitsRet {
    pub modules: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub struct ModulePayloadsRet {
    pub modules: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub struct ModulePostRet {
    pub modules: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub struct ModuleAuxiliaryRet {
    pub modules: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub struct ModuleEncodersRet {
    pub modules: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub struct ModuleNopsRet {
    pub modules: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub struct ModuleInfoRet {
    pub name: String,
    pub description: String,
    pub license: String,
    pub default_target: Option<u32>,
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

#[derive(Deserialize, Debug)]
pub struct ModuleExecuteRet {
    pub job_id: u32,
}

#[derive(Deserialize, Debug)]
pub struct ModuleTargetCompatiblePayloadsRet {
    pub payloads: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub struct SessionMeterpreterReadRet {
    pub data: String,
}

#[derive(Deserialize, Debug)]
pub struct SessionShellReadRet {
    pub seq: u32,
    pub data: String,
}

#[derive(Deserialize, Debug)]
pub struct SessionMeterpreterWriteRet {
    pub result: String,
}

#[derive(Deserialize, Debug)]
pub struct SessionShellWriteRet {
    pub write_count: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct SessionInfo {
  pub r#type: String,
  pub tunnel_local: String,
  pub tunnel_peer: String,
  pub via_exploit: String,
  pub via_payload: String,
  pub desc: String,
  pub info: String,
  pub workspace: String,
  pub target_host: String,
  pub username: String,
  pub uuid: String,
  pub exploit_uuid: String,
  pub routes: String,
}

pub type SessionListRet = HashMap<u32, SessionInfo>;
