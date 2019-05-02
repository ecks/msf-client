extern crate msf_client;

use msf_client::MsfClient;


fn main() {
    let mut client = match MsfClient::new("msf", "1234", "http://172.17.0.2:55553/api/".to_string()) {
        Ok(client) => client,
        Err(err) => { eprintln!("{}", err);
                      return
                    },
    };

    match client.core().version() {
        Ok(res) => { println!("{:?}", res.get("version"));
                     println!("{:?}", res.get("ruby"));
                     println!("{:?}", res.get("api"));
                     res
                   }
        Err(err) => { eprintln!("{}", err);
                      return
                    },
    };

    match client.modules().exploits() {
        Ok(res) => { let mod_names = res.get("modules").unwrap();
                     for mod_name in mod_names {
                         println!("{}", mod_name);
                     };
                     res
                   }
        Err(err) => { eprintln!("{}", err);
                      return
                    },

    };
}
