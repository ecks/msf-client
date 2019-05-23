use std::str;
use std::collections::HashMap;

use std::rc::Rc;
use std::cell::RefCell;

pub mod common;
pub mod msg;
pub mod session;



use session::Session;

use common::Res;
use common::RcRef;

use msg::Msg;
use msg::CmdType;
use msg::RetType;

use msg::CoreVerCmd;
use msg::CoreVerRet;
use msg::ModuleExploitsCmd;
use msg::ModuleExploitsRet;
use msg::ModuleInfoCmd;
use msg::ModuleInfoRet;
use msg::ModuleOptionsCmd;
use msg::ModuleOptionRet;
use msg::ModuleOptionsRet;
use msg::ModuleTargetCompatiblePayloadsCmd;
use msg::ModuleTargetCompatiblePayloadsRet;




pub struct MsfClient {
    sess: RcRef<Session>,
}

impl MsfClient {
    pub fn new(username: &str, password: &str, host: String) -> Res<MsfClient> {
        let sess = match Session::new(username, password, host) {
            Ok(sess) => sess,
            Err(err) => { eprintln!("{}", err);
                          return Err(err)
                        },
        };

        Ok(MsfClient { sess: Rc::new(RefCell::new(sess))})

    }

    pub fn core(&mut self) -> CoreManager {
        CoreManager { sess: Rc::clone(&self.sess) }
    }

    pub fn modules(&mut self) -> ModuleManager {
        ModuleManager { sess: Rc::clone(&self.sess) }
    }

}

pub struct CoreManager {
    sess: RcRef<Session>,
}

impl CoreManager {

    pub fn version(&mut self) -> Res<CoreVerRet> {
        let cmd = CmdType::WCoreVerCmd(CoreVerCmd::new());
        match self.sess.borrow_mut().execute(cmd).unwrap() {
            RetType::WCoreVerRet(sm) => Ok(sm),
            _ => Err("incorrect type"),
        }
    }
}

type ReqOptions = Vec<String>;
type RunOptions = HashMap<String,String>;

trait MsfModule {
    fn init(sess: &RcRef<Session>, mtype: &str, mname: &str) -> (ModuleInfoRet,ModuleOptionsRet,Vec<String>,HashMap<String,String>) {
        // get module info
        let cmd = CmdType::WModuleInfoCmd(ModuleInfoCmd::new(String::from(mtype), String::from(mname)));
        let mi = match sess.borrow_mut().execute(cmd).unwrap() {
            RetType::WModuleInfoRet(mi) => Ok(mi),
            _ => Err("error"),
        };

        // get module options
        let cmd = CmdType::WModuleOptionsCmd(ModuleOptionsCmd::new(String::from(mtype), String::from(mname)));
        let mo = match sess.borrow_mut().execute(cmd).unwrap() {
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

//    fn exploit(&mut self) -> Res<MsgType> {
//        let mut args: Vec<&str> = Vec::new();
//        args.push(self.mtype.as_str());
//        args.push(self.mname.as_str());
//        self.sess.borrow_mut().execute("module.execute", 

//    }

    fn new_with(sess: RcRef<Session>, mname: &str) -> Self;

}


pub struct ExploitModule {
    pub info: ModuleInfoRet,
    pub options: ModuleOptionsRet,
    pub req_options: ReqOptions,
    run_options: RunOptions,
    sess: RcRef<Session>,
    mtype: String,
    mname: String,
}

impl ExploitModule {
    pub fn payloads(&mut self) -> Res<ModuleTargetCompatiblePayloadsRet> {
        let mut args: Vec<&str> = Vec::new();
        args.push(self.mname.as_str());
        args.push("0");
        let cmd = CmdType::WModuleTargetCompatiblePayloadsCmd(ModuleTargetCompatiblePayloadsCmd::new(self.mname.clone(), String::from("0")));
        match self.sess.borrow_mut().execute(cmd).unwrap() {
            RetType::WModuleTargetCompatiblePayloadsRet(mtce) => Ok(mtce),
            _ => Err("incorrect type"),
        }
    }

//    pub fn option(&mut self, opt: String) -> Res<ModuleOption> {

//    }
}

impl MsfModule for ExploitModule {
    fn new_with(sess: RcRef<Session>, mname: &str) -> Self {
        let mtype = String::from("exploit");
        let (mi,mo,req_o,run_o) = ExploitModule::init(&sess, "exploit", mname); 
        ExploitModule { info: mi, options: mo, req_options: req_o, run_options: run_o, sess, mtype: mtype, mname: String::from(mname) }
    }

}

pub struct ModuleManager {
    sess: RcRef<Session>,
}

impl ModuleManager {

    pub fn exploits(&mut self) -> Res<ModuleExploitsRet> {
        let cmd = CmdType::WModuleExploitsCmd(ModuleExploitsCmd::new());
        match self.sess.borrow_mut().execute(cmd).unwrap() {
            RetType::WModuleExploitsRet(me) => Ok(me),
            _ => Err("incorrect type"),
        }
    }

    pub fn use_exploit(&mut self, mname: &str) -> ExploitModule {
        ExploitModule::new_with(Rc::clone(&self.sess), mname)
    }
}
