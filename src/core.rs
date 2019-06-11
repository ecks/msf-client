use crate::conn::Conn;

use crate::common::{Res,RcRef};

use crate::msg::{CmdType,RetType};
use crate::msg::{CoreVerCmd,CoreVerRet};

pub struct CoreManager {
    conn: RcRef<Conn>,
}

impl CoreManager {

    pub fn new(conn: RcRef<Conn>) -> CoreManager {
        CoreManager { conn }
    }

    pub fn version(&mut self) -> Res<CoreVerRet> {
        let cmd = CmdType::WCoreVerCmd(CoreVerCmd::new());
        match self.conn.borrow_mut().execute(cmd).unwrap() {
            RetType::WCoreVerRet(sm) => Ok(sm),
            _ => Err("incorrect type"),
        }
    }
}

