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
use msg::MsgType;

use msg::CoreVersion;
use msg::ModuleExploits;
use msg::ModuleInfo;
use msg::ModuleOption;
use msg::ModuleOptions;
use msg::ModuleTargetCompatiblePayloads;




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

    pub fn version(&mut self) -> Res<CoreVersion> {
        match self.sess.borrow_mut().execute(CoreVersion::mn(), Vec::new()).unwrap() {
            MsgType::WithCoreVersion(sm) => Ok(sm),
            _ => Err("incorrect type"),
        }
    }
}

type ReqOptions = Vec<String>;
type RunOptions = HashMap<String,String>;

trait MsfModule {
    fn init(sess: &RcRef<Session>, mtype: &str, mname: &str) -> (ModuleInfo,ModuleOptions,Vec<String>,HashMap<String,String>) {
        // get module info
        let mut args: Vec<&str> = Vec::new();
        args.push(mtype);
        args.push(mname);
        let mi = match sess.borrow_mut().execute(ModuleInfo::mn(), args).unwrap() {
            MsgType::WithModuleInfo(mi) => Ok(mi),
            _ => Err("error"),
        };

        // get module options
        let mut args: Vec<&str> = Vec::new();
        args.push(mtype);
        args.push(mname);
        let mo = match sess.borrow_mut().execute(ModuleOptions::mn(), args).unwrap() {
            MsgType::WithModuleOptions(mo) => Ok(mo),
            _ => Err("error"),
 
        };

        let mi_res = mi.unwrap();
        let mo_res = mo.unwrap();
        
        let mut req_options = Vec::new();
        let mut run_options = HashMap::new();

        for (option_name, option_val) in &mo_res {
            match option_val {
              ModuleOption::NoDefault { r#type, required, .. } | ModuleOption::DefaultInt { r#type, required, .. } | ModuleOption::DefaultBool { r#type, required, .. } | ModuleOption::DefaultEnum { r#type, required, .. } if *required == true => req_options.push(option_name.clone()),
              _ => ()
            };

            match option_val {
              ModuleOption::DefaultInt { r#type, required,  advanced, desc, default} => run_options.insert(option_name.clone(), default.to_string()),
              ModuleOption::DefaultBool { r#type, required, advanced, desc, default: true } => run_options.insert(option_name.clone(), String::from("true")), 
              ModuleOption::DefaultBool { r#type, required, advanced, desc, default: false } => run_options.insert(option_name.clone(), String::from("false")), 
              ModuleOption::DefaultEnum { r#type, required, advanced, desc, default, .. } => run_options.insert(option_name.clone(), default.to_string()),
              _ => None
            };
        }
        return (mi_res,mo_res,req_options,run_options)
    }

    fn new_with(sess: RcRef<Session>, mname: &str) -> Self;
    fn runoptions(&mut self) -> Res<&RunOptions>;

}


pub struct ExploitModule {
    pub info: ModuleInfo, 
    pub options: ModuleOptions,
    pub req_options: ReqOptions,
    run_options: RunOptions,
    sess: RcRef<Session>,
    mname: String,
}

impl ExploitModule {
    pub fn payloads(&mut self) -> Res<ModuleTargetCompatiblePayloads> {
        let mut args: Vec<&str> = Vec::new();
        args.push(self.mname.as_str());
        args.push("0");
        match self.sess.borrow_mut().execute(ModuleTargetCompatiblePayloads::mn(), args).unwrap() {
            MsgType::WithModuleTargetCompatiblePayloads(mtce) => Ok(mtce),
            _ => Err("incorrect type"),
        }
    }

//    pub fn option(&mut self, opt: String) -> Res<ModuleOption> {

//    }
}

impl MsfModule for ExploitModule {
    fn new_with(sess: RcRef<Session>, mname: &str) -> Self {
        let (mi,mo,req_o,run_o) = ExploitModule::init(&sess, "exploit", mname); 
        ExploitModule { info: mi, options: mo, req_options: req_o, run_options: run_o, sess, mname: String::from(mname) }
    }

    fn runoptions(&mut self) -> Res<&RunOptions> {
        Ok(&self.run_options)
    }


}

pub struct ModuleManager {
    sess: RcRef<Session>,
}

impl ModuleManager {

    pub fn exploits(&mut self) -> Res<ModuleExploits> {
        match self.sess.borrow_mut().execute(ModuleExploits::mn(), Vec::new()).unwrap() {
            MsgType::WithModuleExploits(me) => Ok(me),
            _ => Err("incorrect type"),
        }
    }

    pub fn use_exploit(&mut self, mname: &str) -> ExploitModule {
        ExploitModule::new_with(Rc::clone(&self.sess), mname)
    }
}
