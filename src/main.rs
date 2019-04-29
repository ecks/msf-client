extern crate msf_client;

use msf_client::Session;


fn main() {
    let mut sess = match Session::new("msf", "1234", "http://172.17.0.2:55553/api/".to_string()) {
        Ok(sess) => sess,
        Err(err) => { eprintln!("{}", err);
                      return
                    },
    };

    match sess.execute("core.version", Vec::new()) {
        Ok(res) => { println!("{:?}", res.get("version"));
                     println!("{:?}", res.get("ruby"));
                     println!("{:?}", res.get("api"));
                     res
                   }
        Err(err) => { eprintln!("{}", err);
                      return
                    },
    };
}
