use std::collections::HashMap;

use std::rc::Rc;

use crate::conn::Conn;
use crate::common::{Res,RcRef,RunOptions};

use crate::msg::{CmdType,RetType};
use crate::msg::{ModuleExploitsCmd,ModuleExploitsRet,ModuleInfoCmd,ModuleInfoRet,ModuleOptionsCmd,ModuleOptionRet,ModuleOptionsRet,ModuleExecuteCmd,ModuleExecuteRet,ModuleTargetCompatiblePayloadsCmd,ModuleTargetCompatiblePayloadsRet};

type ReqOptions = Vec<String>;

pub trait MsfModule {
    fn init(conn: &RcRef<Conn>, mtype: &str, mname: &str) -> (ModuleInfoRet,ModuleOptionsRet,Vec<String>,HashMap<String,String>) {
        // get module info
        let cmd = CmdType::WModuleInfoCmd(ModuleInfoCmd::new(String::from(mtype), String::from(mname)));
        let mi = match conn.borrow_mut().execute(cmd).unwrap() {
            RetType::WModuleInfoRet(mi) => Ok(mi),
            _ => Err("error"),
        };

        let mi_res = mi.unwrap();

        // get module options
        let cmd = CmdType::WModuleOptionsCmd(ModuleOptionsCmd::new(String::from(mtype), String::from(mname)));
        let mo = match conn.borrow_mut().execute(cmd).unwrap() {
            RetType::WModuleOptionsRet(mo) => Ok(mo),
            _ => Err("error"),
 
        };

        let mo_res = mo.unwrap();
        
        let mut req_options = Vec::new();
        let mut run_options = HashMap::new();

        for (option_name, option_val) in &mo_res {
            match option_val {
              // very ugly, refactor if possible
              ModuleOptionRet::NoDefault { required, .. } | ModuleOptionRet::DefaultInt { required, .. } | ModuleOptionRet::DefaultBool { required, .. } | ModuleOptionRet::DefaultEnum { required, .. } if *required => req_options.push(option_name.clone()),
              _ => ()
            };

            match option_val {
              ModuleOptionRet::DefaultInt { default, ..} => run_options.insert(option_name.clone(), default.to_string()),
              ModuleOptionRet::DefaultBool { default: true, .. } => run_options.insert(option_name.clone(), String::from("true")), 
              ModuleOptionRet::DefaultBool { default: false, .. } => run_options.insert(option_name.clone(), String::from("false")), 
              ModuleOptionRet::DefaultEnum { default, .. } => run_options.insert(option_name.clone(), default.to_string()),
              _ => None
            };
        }
        (mi_res,mo_res,req_options,run_options)
    }

    fn exploit(&mut self) -> Res<ModuleExecuteRet>;
    fn new_with(conn: RcRef<Conn>, mname: &str) -> Self;

}


pub struct ExploitModule {
    pub info: ModuleInfoRet,
    pub options: ModuleOptionsRet,
    pub req_options: ReqOptions,
    pub run_options: RunOptions,
    conn: RcRef<Conn>,
    mtype: String,
    mname: String,
}

impl ExploitModule {
    pub fn payloads(&mut self) -> Res<ModuleTargetCompatiblePayloadsRet> {
        let mut args: Vec<&str> = Vec::new();
        args.push(self.mname.as_str());
        args.push("0");
        let cmd = CmdType::WModuleTargetCompatiblePayloadsCmd(ModuleTargetCompatiblePayloadsCmd::new(self.mname.clone(), String::from("0")));
        match self.conn.borrow_mut().execute(cmd).unwrap() {
            RetType::WModuleTargetCompatiblePayloadsRet(mtce) => Ok(mtce),
            _ => Err("incorrect type"),
        }
    }


//    pub fn option(&mut self, opt: String) -> Res<ModuleOption> {

//    }
}

impl MsfModule for ExploitModule {
    fn new_with(conn: RcRef<Conn>, mname: &str) -> Self {
        let mtype = String::from("exploit");
        let (info,options,req_options,run_options) = ExploitModule::init(&conn, "exploit", mname); 
        ExploitModule { info, options, req_options, run_options, conn, mtype, mname: String::from(mname) }
    }

    fn exploit(&mut self) -> Res<ModuleExecuteRet> {
        let cmd = CmdType::WModuleExecuteCmd(ModuleExecuteCmd::new(self.mtype.clone(), self.mname.clone(), self.run_options.clone()));
        match self.conn.borrow_mut().execute(cmd).unwrap() {
            RetType::WModuleExecuteRet(mer) => Ok(mer),
            _ => Err("Could not exploit"),
        }
    }
}

pub struct ModuleManager {
    conn: RcRef<Conn>,
}

impl ModuleManager {

    pub fn new(conn: RcRef<Conn>) -> ModuleManager {
        ModuleManager { conn }
    }

    pub fn exploits(&mut self) -> Res<ModuleExploitsRet> {
        let cmd = CmdType::WModuleExploitsCmd(ModuleExploitsCmd::new());
        match self.conn.borrow_mut().execute(cmd).unwrap() {
            RetType::WModuleExploitsRet(me) => Ok(me),
            _ => Err("incorrect type"),
        }
    }

    pub fn use_exploit(&mut self, mname: &str) -> ExploitModule {
        ExploitModule::new_with(Rc::clone(&self.conn), mname)
    }
}

