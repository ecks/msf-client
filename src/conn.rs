use serde::{Serialize,Deserialize};
use rmp_serde::{Serializer,Deserializer};

use rmp_serde::decode::ReadReader;

use reqwest::{Client,header};

use crate::common::Res;

use crate::msg::Tokenize;
use crate::msg::AuthLoginCmd;
use crate::msg::CmdType;
use crate::msg::RetType;

pub struct Conn {
    host: String,
    token: Option<String>,
}

impl Conn {

    // internal
    fn connect_and_exec<'a>(&mut self, buf: Vec<u8>, body_buf: &'a mut Vec<u8>) -> Res<Deserializer<ReadReader<&'a [u8]>>> {
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
            let len_from_header = res.content_length().unwrap();

            // need to copy raw contents
            let copy_len = res.copy_to(body_buf).unwrap();

            if copy_len != len_from_header {
                return Err("Unable to copy all bytes from response");
            }

            let de = Deserializer::new(body_buf.as_slice());
            Ok(de)
        } else {
            Err("Bad status code")
        }
    }

    pub fn execute(&mut self, mut cmd: CmdType) -> Res<RetType> {

        let mut buf = Vec::new();

        let token = match self.token.clone() {
            Some(t) => t,
            None => String::new(),
        };

        match cmd {
            CmdType::WAuthLoginCmd(ref al) => { al.serialize(&mut Serializer::new(&mut buf)).unwrap();
                                                let mut body_buf: Vec<u8> = vec![];
                                                let mut de = match self.connect_and_exec(buf, &mut body_buf) {
                                                    Ok(res) => res,
                                                    Err(err_str) => return Err(err_str),
                                                };
                                                let de_str = Deserialize::deserialize(&mut de).unwrap();
                                                Ok(RetType::WAuthLoginRet(de_str)) },

            CmdType::WCoreVerCmd(ref mut cv) => { cv.add_token(token);
                                                  cv.serialize(&mut Serializer::new(&mut buf)).unwrap();
                                                  let mut body_buf: Vec<u8> = vec![];
                                                  let mut de = match self.connect_and_exec(buf, &mut body_buf) {
                                                      Ok(res) => res,
                                                      Err(err_str) => return Err(err_str),
                                                  };
                                                  let de_str = Deserialize::deserialize(&mut de).unwrap();
                                                  Ok(RetType::WCoreVerRet(de_str)) },
            CmdType::WModuleExploitsCmd(ref mut me) => { me.add_token(token);
                                                         me.serialize(&mut Serializer::new(&mut buf)).unwrap();
                                                         let mut body_buf: Vec<u8> = vec![];
                                                         let mut de = match self.connect_and_exec(buf, &mut body_buf) {
                                                             Ok(res) => res,
                                                             Err(err_str) => return Err(err_str),
                                                         };
                                                         let de_str = Deserialize::deserialize(&mut de).unwrap();
                                                         Ok(RetType::WModuleExploitsRet(de_str)) },
            CmdType::WModuleInfoCmd(ref mut mi) => { mi.add_token(token);
                                                     mi.serialize(&mut Serializer::new(&mut buf)).unwrap();
                                                     let mut body_buf: Vec<u8> = vec![];
                                                     let mut de = match self.connect_and_exec(buf, &mut body_buf) {
                                                         Ok(res) => res,
                                                         Err(err_str) => return Err(err_str),
                                                     };
                                                     let de_str = Deserialize::deserialize(&mut de).unwrap();
                                                     Ok(RetType::WModuleInfoRet(de_str)) },
            CmdType::WModuleOptionsCmd(ref mut mo) => { mo.add_token(token);
                                                        mo.serialize(&mut Serializer::new(&mut buf)).unwrap();
                                                        let mut body_buf: Vec<u8> = vec![];
                                                        let mut de = match self.connect_and_exec(buf, &mut body_buf) {
                                                            Ok(res) => res,
                                                            Err(err_str) => return Err(err_str),
                                                        };
                                                        let de_str = Deserialize::deserialize(&mut de).unwrap();
                                                        Ok(RetType::WModuleOptionsRet(de_str)) },
            CmdType::WModuleExecuteCmd(ref mut mec) => { mec.add_token(token);
                                                         mec.serialize(&mut Serializer::new(&mut buf)).unwrap();
                                                         let mut body_buf: Vec<u8> = vec![];
                                                         let mut de = match self.connect_and_exec(buf, &mut body_buf) {
                                                             Ok(res) => res,
                                                             Err(err_str) => return Err(err_str),
                                                         };
                                                         let de_str = Deserialize::deserialize(&mut de).unwrap();
                                                         Ok(RetType::WModuleExecuteRet(de_str)) },
            CmdType::WModuleTargetCompatiblePayloadsCmd(ref mut mtcp) => { mtcp.add_token(token);
                                                                           mtcp.serialize(&mut Serializer::new(&mut buf)).unwrap();
                                                                           let mut body_buf: Vec<u8> = vec![];
                                                                           let mut de = match self.connect_and_exec(buf, &mut body_buf) {
                                                                               Ok(res) => res,
                                                                               Err(err_str) => return Err(err_str),
                                                                           };
                                                                           let de_str = Deserialize::deserialize(&mut de).unwrap();
                                                                           Ok(RetType::WModuleTargetCompatiblePayloadsRet(de_str)) },
            CmdType::WSessionMeterpreterReadCmd(ref mut sr) => { sr.add_token(token);
                                                      sr.serialize(&mut Serializer::new(&mut buf)).unwrap();
                                                      let mut body_buf: Vec<u8> = vec![];
                                                      let mut de = match self.connect_and_exec(buf, &mut body_buf) {
                                                        Ok(res) => res,
                                                        Err(err_str) => return Err(err_str),
                                                      };
                                                      let de_str = Deserialize::deserialize(&mut de).unwrap();
                                                      Ok(RetType::WSessionMeterpreterReadRet(de_str)) },
            CmdType::WSessionShellReadCmd(ref mut sr) => { sr.add_token(token);
                                                      sr.serialize(&mut Serializer::new(&mut buf)).unwrap();
                                                      let mut body_buf: Vec<u8> = vec![];
                                                      let mut de = match self.connect_and_exec(buf, &mut body_buf) {
                                                        Ok(res) => res,
                                                        Err(err_str) => return Err(err_str),
                                                      };
                                                      let de_str = Deserialize::deserialize(&mut de).unwrap();
                                                      Ok(RetType::WSessionShellReadRet(de_str)) },
            CmdType::WSessionMeterpreterWriteCmd(ref mut sw) => { sw.add_token(token);
                                                      sw.serialize(&mut Serializer::new(&mut buf)).unwrap();
                                                      let mut body_buf: Vec<u8> = vec![];
                                                      let mut de = match self.connect_and_exec(buf, &mut body_buf) {
                                                        Ok(res) => res,
                                                        Err(err_str) => return Err(err_str),
                                                      };
                                                      let de_str = Deserialize::deserialize(&mut de).unwrap();
                                                      Ok(RetType::WSessionMeterpreterWriteRet(de_str)) },
            CmdType::WSessionShellWriteCmd(ref mut sw) => { sw.add_token(token);
                                                      sw.serialize(&mut Serializer::new(&mut buf)).unwrap();
                                                      let mut body_buf: Vec<u8> = vec![];
                                                      let mut de = match self.connect_and_exec(buf, &mut body_buf) {
                                                        Ok(res) => res,
                                                        Err(err_str) => return Err(err_str),
                                                      };
                                                      let de_str = Deserialize::deserialize(&mut de).unwrap();
                                                      Ok(RetType::WSessionShellWriteRet(de_str)) },
            CmdType::WSessionListCmd(ref mut sl) => { sl.add_token(token);
                                                      sl.serialize(&mut Serializer::new(&mut buf)).unwrap();
                                                      let mut body_buf: Vec<u8> = vec![];
                                                      let mut de = match self.connect_and_exec(buf, &mut body_buf) {
                                                        Ok(res) => res,
                                                        Err(err_str) => return Err(err_str),
                                                      };
                                                      let de_str = Deserialize::deserialize(&mut de).unwrap();
                                                      Ok(RetType::WSessionListRet(de_str)) },
        }
    }

    // internal
    fn authenticate(&mut self, username: &str, password: &str) -> Res<RetType> {
        let cmd = CmdType::WAuthLoginCmd(AuthLoginCmd::new(String::from(String::from(username)), String::from(password)));
        self.execute(cmd)
    }

    pub fn new(username: &str, password: &str, host: String) -> Res<Conn> {
        let mut sess = Conn { host, token: None };



        let response = match sess.authenticate(username, password).unwrap() {
            RetType::WAuthLoginRet(sm) => sm,
            _ => return Err("incorrect type"),

        };

        // map over Option, cloning the String to store in Struct
        sess.token = Some(response.token.clone());

        println!("{}", response.result); 
        println!("{:?}", sess.token); 

        Ok(sess)
    }
}


