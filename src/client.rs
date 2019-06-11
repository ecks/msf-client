use std::str;

use std::rc::Rc;
use std::cell::RefCell;

use crate::conn::Conn;
use crate::core::CoreManager;
use crate::modules::ModuleManager;
use crate::sessions::SessionManager;

use crate::common::{Res,RcRef};





pub struct MsfClient {
    conn: RcRef<Conn>,
}

impl MsfClient {
    pub fn new(username: &str, password: &str, host: String) -> Res<MsfClient> {
        let conn = match Conn::new(username, password, host) {
            Ok(conn) => conn,
            Err(err) => { eprintln!("{}", err);
                          return Err(err)
                        },
        };

        Ok(MsfClient { conn: Rc::new(RefCell::new(conn))})

    }

    pub fn core(&mut self) -> CoreManager {
        CoreManager::new(Rc::clone(&self.conn))
    }

    pub fn modules(&mut self) -> ModuleManager {
        ModuleManager::new(Rc::clone(&self.conn))
    }

    pub fn sessions(&mut self) -> SessionManager {
        SessionManager::new(Rc::clone(&self.conn))
    }
}
