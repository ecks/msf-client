
use serde::{Serialize,Deserialize};
use rmp_serde::{Serializer,Deserializer};

use reqwest::Client;
use reqwest::header;

use crate::common::Res;

use crate::msg::Msg;
use crate::msg::MsgType;

use crate::msg::AuthLogin;


pub struct Session {
    host: String,
    token: Option<String>,
}

impl Session {

    pub fn execute<'a>(&mut self, method: &'static str, args: Vec<&'a str>) -> Res<MsgType> {

        // clone args so that we may insert stuff in there
        let mut argsc = args.clone();
        argsc.insert(0, method);

        let tokenc = match self.token.clone() {
            Some(t) => t,
            None => String::new(),
        };

        if method != "auth.login" && self.token != None {
            argsc.insert(1, &tokenc);
        }
        let mut buf = Vec::new();

        argsc.serialize(&mut Serializer::new(&mut buf)).unwrap();

        let mut headers = header::HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, header::HeaderValue::from_static("binary/message-pack"));

        // panics on error
        let client = Client::builder()
            .default_headers(headers)
            .build().unwrap();

        // panics on error
        let mut res = client.post(self.host.as_str())
            .body(buf)
            .send().unwrap();

        if res.status() == reqwest::StatusCode::OK {
            println!("{:?}", res.headers().get(header::CONTENT_TYPE).unwrap().to_str());
            println!("{:?}", res.content_length());
            let len_from_header = res.content_length().unwrap();

            let mut body_buf: Vec<u8> = vec![];

            // need to copy raw contents
            let copy_len = res.copy_to(&mut body_buf).unwrap();

            if copy_len != len_from_header {
                return Err("Unable to copy all bytes from response");
            }

            let mut de = Deserializer::new(body_buf.as_slice());

            match method {
                "auth.login" => {
                    let de_str = Deserialize::deserialize(&mut de).unwrap();
        
                    Ok(MsgType::WithAuthLogin(de_str))
                },
                "core.version" => {
                    let de_str = Deserialize::deserialize(&mut de).unwrap();
        
                    Ok(MsgType::WithCoreVersion(de_str))
                },
                "module.exploits" => {
                    let de_str = Deserialize::deserialize(&mut de).unwrap();
        
                    Ok(MsgType::WithModuleExploits(de_str))
                },
                "module.info" => {
                    let de_str = Deserialize::deserialize(&mut de).unwrap();
        
                    Ok(MsgType::WithModuleInfo(de_str))
                },
                "module.options" => {
                    let de_str = Deserialize::deserialize(&mut de).unwrap();
        
                    Ok(MsgType::WithModuleOptions(de_str))
                },
                "module.target_compatible_payloads" => {
                    let de_str = Deserialize::deserialize(&mut de).unwrap();
        
                    Ok(MsgType::WithModuleTargetCompatiblePayloads(de_str))
                },
                _ => {
                    let de_str = Deserialize::deserialize(&mut de).unwrap();
        
                    Ok(MsgType::WithString(de_str))
                },
            }
        } else {
            Err("Bad status code")
        }
    }

    fn authenticate(&mut self, username: &str, password: &str) -> Res<MsgType> {
        let args = vec![username, password];
        self.execute(AuthLogin::mn(), args)
    }

    pub fn new(username: &str, password: &str, host: String) -> Res<Session> {
        let mut sess = Session { host, token: None };



        let response = match sess.authenticate(username, password).unwrap() {
            MsgType::WithAuthLogin(sm) => sm,
            _ => return Err("incorrect type"),

        };

        // map over Option, cloning the String to store in Struct
        sess.token = Some(response.token.clone());

        println!("{}", response.result); 
        println!("{:?}", sess.token); 

        Ok(sess)
    }
}

