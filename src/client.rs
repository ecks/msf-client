use std::str;
use std::collections::HashMap;

use std::rc::Rc;
use std::cell::RefCell;

use crate::conn::Conn;

use crate::common::{Res,RcRef,RunOptions};

use crate::msg::{CmdType,RetType};

use crate::msg::{CoreVerCmd,CoreVerRet,ModuleExploitsCmd,ModuleExploitsRet,ModuleInfoCmd,ModuleInfoRet,ModuleOptionsCmd,ModuleOptionRet,ModuleOptionsRet,ModuleExecuteCmd,ModuleExecuteRet,ModuleTargetCompatiblePayloadsCmd,ModuleTargetCompatiblePayloadsRet,SessionMeterpreterReadCmd,SessionMeterpreterReadRet,SessionMeterpreterWriteCmd,SessionMeterpreterWriteRet,SessionShellReadCmd,SessionShellReadRet,SessionShellWriteCmd,SessionShellWriteRet,SessionListCmd,SessionListRet};




pub struct MsfClient {
    conn: RcRef<Conn>,
}

impl MsfClient {
    pub fn new(username: &str, password: &str, host: String) -> Res<MsfClient> {
        let conn = match Conn::new(username, password, host) {
            Ok(conn) => conn,
            Err(err) => { eprintln!("{}", err);
                          return Err(err)
                        },
        };

        Ok(MsfClient { conn: Rc::new(RefCell::new(conn))})

    }

    pub fn core(&mut self) -> CoreManager {
        CoreManager { conn: Rc::clone(&self.conn) }
    }

    pub fn modules(&mut self) -> ModuleManager {
        ModuleManager { conn: Rc::clone(&self.conn) }
    }

    pub fn sessions(&mut self) -> SessionManager {
        SessionManager { conn: Rc::clone(&self.conn) }
    }
}

pub struct CoreManager {
    conn: RcRef<Conn>,
}

impl CoreManager {

    pub fn version(&mut self) -> Res<CoreVerRet> {
        let cmd = CmdType::WCoreVerCmd(CoreVerCmd::new());
        match self.conn.borrow_mut().execute(cmd).unwrap() {
            RetType::WCoreVerRet(sm) => Ok(sm),
            _ => Err("incorrect type"),
        }
    }
}

type ReqOptions = Vec<String>;

pub trait MsfModule {
    fn init(conn: &RcRef<Conn>, mtype: &str, mname: &str) -> (ModuleInfoRet,ModuleOptionsRet,Vec<String>,HashMap<String,String>) {
        // get module info
        let cmd = CmdType::WModuleInfoCmd(ModuleInfoCmd::new(String::from(mtype), String::from(mname)));
        let mi = match conn.borrow_mut().execute(cmd).unwrap() {
            RetType::WModuleInfoRet(mi) => Ok(mi),
            _ => Err("error"),
        };

        // get module options
        let cmd = CmdType::WModuleOptionsCmd(ModuleOptionsCmd::new(String::from(mtype), String::from(mname)));
        let mo = match conn.borrow_mut().execute(cmd).unwrap() {
            RetType::WModuleOptionsRet(mo) => Ok(mo),
            _ => Err("error"),
 
        };

        let mi_res = mi.unwrap();
        let mo_res = mo.unwrap();
        
        let mut req_options = Vec::new();
        let mut run_options = HashMap::new();

        for (option_name, option_val) in &mo_res {
            match option_val {
              // very ugly, refactor if possible
              ModuleOptionRet::NoDefault { r#type, required, .. } | ModuleOptionRet::DefaultInt { r#type, required, .. } | ModuleOptionRet::DefaultBool { r#type, required, .. } | ModuleOptionRet::DefaultEnum { r#type, required, .. } if *required == true => req_options.push(option_name.clone()),
              _ => ()
            };

            match option_val {
              ModuleOptionRet::DefaultInt { r#type, required,  advanced, desc, default} => run_options.insert(option_name.clone(), default.to_string()),
              ModuleOptionRet::DefaultBool { r#type, required, advanced, desc, default: true } => run_options.insert(option_name.clone(), String::from("true")), 
              ModuleOptionRet::DefaultBool { r#type, required, advanced, desc, default: false } => run_options.insert(option_name.clone(), String::from("false")), 
              ModuleOptionRet::DefaultEnum { r#type, required, advanced, desc, default, .. } => run_options.insert(option_name.clone(), default.to_string()),
              _ => None
            };
        }
        return (mi_res,mo_res,req_options,run_options)
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
        let (mi,mo,req_o,run_o) = ExploitModule::init(&conn, "exploit", mname); 
        ExploitModule { info: mi, options: mo, req_options: req_o, run_options: run_o, conn, mtype: mtype, mname: String::from(mname) }
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

pub enum MsfSessionType {
    WMeterpreterSession(MeterpreterSession),
    WShellSession(ShellSession),
}

impl MsfSessionType {

    pub fn read(&mut self) -> String {
        match self {
            MsfSessionType::WMeterpreterSession(session) => { match session.read() {
                                                                Ok(res) => res.data,
                                                                Err(err) => String::from(err)
                                                              }
                                                            },
            MsfSessionType::WShellSession(session) => { match session.read() {
                                                          Ok(res) => res.data,
                                                          Err(err) => String::from(err)
                                                        }
                                                      },
        }
    }

    pub fn write(&mut self, data: String) -> String {
        match self {
            MsfSessionType::WMeterpreterSession(session) => { match session.write(data) {
                                                                Ok(res) => res.write_count,
                                                                Err(err) => String::from(err)
                                                              }
                                                            },
            MsfSessionType::WShellSession(session) => { match session.write(data) {
                                                          Ok(res) => res.write_count,
                                                          Err(err) => String::from(err)
                                                        }
                                                      },
        }
    }

}

pub struct MeterpreterSession {
    conn: RcRef<Conn>,
    id: u32,
}

impl MeterpreterSession {

    pub fn read(&mut self) -> Res<SessionMeterpreterReadRet> {
        let cmd = CmdType::WSessionMeterpreterReadCmd(SessionMeterpreterReadCmd::new(self.id));
        match self.conn.borrow_mut().execute(cmd).unwrap() {
            RetType::WSessionMeterpreterReadRet(sr) => Ok(sr),
            _ => Err("incorrect type"),
        }
    }

    pub fn write(&mut self, data: String) -> Res<SessionMeterpreterWriteRet> {
        let cmd = CmdType::WSessionMeterpreterWriteCmd(SessionMeterpreterWriteCmd::new(self.id, data));
        match self.conn.borrow_mut().execute(cmd).unwrap() {
            RetType::WSessionMeterpreterWriteRet(sw) => Ok(sw),
            _ => Err("incorrect type"),
        }
    }
}

pub struct ShellSession {
    conn: RcRef<Conn>,
    id: u32,
}

impl ShellSession {

    pub fn read(&mut self) -> Res<SessionShellReadRet> {
        let cmd = CmdType::WSessionShellReadCmd(SessionShellReadCmd::new(self.id));
        match self.conn.borrow_mut().execute(cmd).unwrap() {
            RetType::WSessionShellReadRet(sr) => Ok(sr),
            _ => Err("incorrect type"),
        }
    }

    pub fn write(&mut self, data: String) -> Res<SessionShellWriteRet> {
        let cmd = CmdType::WSessionShellWriteCmd(SessionShellWriteCmd::new(self.id, data));
        match self.conn.borrow_mut().execute(cmd).unwrap() {
            RetType::WSessionShellWriteRet(sw) => Ok(sw),
            _ => Err("incorrect type"),
        }

    }

}

pub struct SessionManager {
    conn: RcRef<Conn>,
}

impl SessionManager {

    pub fn list(&mut self) -> Res<SessionListRet> {
        let cmd = CmdType::WSessionListCmd(SessionListCmd::new());
        match self.conn.borrow_mut().execute(cmd).unwrap() {
            RetType::WSessionListRet(sl) => Ok(sl),
            _ => Err("incorrect type"),
        }
    }

    pub fn session(&mut self, id: &u32) -> Res<MsfSessionType> {
        if let Ok(sl) = self.list() {
            let s = sl.get(id).unwrap();
            if s.r#type == "meterpreter" {
                Ok(MsfSessionType::WMeterpreterSession(MeterpreterSession { conn: Rc::clone(&self.conn), id: *id }))
            } else if s.r#type == "shell" {
                Ok(MsfSessionType::WShellSession(ShellSession { conn: Rc::clone(&self.conn), id: *id }))
            } else {
                Err("unknown session")

            }
        }
        else {
            Err("error in list")
        }
    }

}

