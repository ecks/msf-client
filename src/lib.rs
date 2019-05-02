extern crate reqwest;

extern crate rmp_serde;

use reqwest::Client;
use reqwest::header;

use std::str;
use std::rc::Rc;
use std::cell::RefCell;

use std::collections::HashMap;

use serde::{Serialize,Deserialize};
use rmp_serde::{Serializer,Deserializer};

type SessionMapVec = HashMap<String, Vec<String>>;
type SessionMap = HashMap<String, String>;

type Res<T> = Result<T, &'static str>;

pub enum SessionMapType {
    SMV(SessionMapVec),
    SM(SessionMap),
}

pub struct Session {
    host: String,
    token: Option<String>,
}

impl Session {

    pub fn execute<'a>(&mut self, method: &'a str, args: Vec<&'a str>) -> Res<SessionMapType> {

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

            if method == "auth.login" || method == "core.version" {
                let de_str = Deserialize::deserialize(&mut de).unwrap();
        
                Ok(SessionMapType::SM(de_str))
            }
            else {
                let de_str = Deserialize::deserialize(&mut de).unwrap();
        
                Ok(SessionMapType::SMV(de_str))
            }
        } else {
            Err("Bad status code")
        }
    }

    fn authenticate(&mut self, username: &str, password: &str) -> Res<SessionMapType> {
        let args = vec![username, password];
        self.execute("auth.login", args)
    }

    pub fn new(username: &str, password: &str, host: String) -> Res<Session> {
        let mut sess = Session { host, token: None };



        let response = match sess.authenticate(username, password).unwrap() {
            SessionMapType::SM(sm) => sm,
            SessionMapType::SMV(_) => return Err("incorrect type"),

        };

        // map over Option, cloning the String to store in Struct
        sess.token = response.get("token").cloned();

        println!("{:?}", response.get("result")); 
        println!("{:?}", sess.token); 

        Ok(sess)
    }
}

type RcRef<T> = Rc<RefCell<T>>;

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

    pub fn version(&mut self) -> Res<SessionMap> {
        match self.sess.borrow_mut().execute("core.version", Vec::new()).unwrap() {
            SessionMapType::SM(sm) => Ok(sm),
            SessionMapType::SMV(_) => Err("incorrect type"),
        }
    }
}

pub struct ModuleManager {
    sess: RcRef<Session>,
}

impl ModuleManager {

    pub fn exploits(&mut self) -> Res<SessionMapVec> {
        match self.sess.borrow_mut().execute("module.exploits", Vec::new()).unwrap() {
            SessionMapType::SMV(smv) => Ok(smv),
            SessionMapType::SM(_) => Err("incorrect type"),
        }
    }
}
