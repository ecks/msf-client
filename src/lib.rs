extern crate reqwest;

extern crate rmp_serde;

use reqwest::Client;
use reqwest::header;

use std::str;
use std::collections::HashMap;

use serde::{Serialize,Deserialize};
use rmp_serde::{Serializer,Deserializer};

type SessionMapRes = Result<HashMap<String, String>, &'static str>;
type SessionRes = Result<Session, &'static str>;

pub struct Session {
    host: String,
    token: Option<String>,
}

impl Session {

    pub fn execute<'a>(&mut self, method: &'a str, args: Vec<&'a str>) -> SessionMapRes {

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
        headers.insert(header::CONNECTION, header::HeaderValue::from_static("keep-alive"));

        // panics on error
        let client = Client::builder()
            .default_headers(headers)
            .build().unwrap();

        // panics on error
        let mut res = client.post(self.host.as_str())
            .body(buf)
            .send().unwrap();

        if res.status().to_string() == "200 OK" {
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
            let de_str = Deserialize::deserialize(&mut de).unwrap();
        
            Ok(de_str)
        } else {
            Err("Bad status code")
        }
    }

    fn authenticate(&mut self, username: &str, password: &str) -> SessionMapRes {
        let args = vec![username, password];
        self.execute("auth.login", args)
    }

    pub fn new(username: &str, password: &str, host: String) -> SessionRes {
        let mut session = Session { host, token: None };

        let response = session.authenticate(username, password)?;

        // map over Option, cloning the String to store in Struct
        session.token = response.get("token").map(|s| s.clone());

        println!("{:?}", response.get("result")); 
        println!("{:?}", session.token); 

        Ok(session)
    }
}
