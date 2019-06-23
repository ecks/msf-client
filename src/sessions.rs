use std::rc::Rc;

use crate::conn::Conn;
use crate::common::{Res,RcRef};

use crate::msg::{CmdType,RetType};
use crate::msg::{SessionMeterpreterReadCmd,SessionMeterpreterReadRet,SessionMeterpreterWriteCmd,SessionMeterpreterWriteRet,SessionShellReadCmd,SessionShellReadRet,SessionShellWriteCmd,SessionShellWriteRet,SessionListCmd,SessionListRet};


pub enum MsfSessionType {
    WMeterpreterSession(MeterpreterSession),
    WShellSession(ShellSession),
}

impl MsfSessionType {

    pub fn read(&mut self) -> String {
        match self {
            MsfSessionType::WMeterpreterSession(session) => { match session.read() {
                                                                Ok(res) => res.data,
                                                                Err(err) => String::from(err)
                                                              }
                                                            },
            MsfSessionType::WShellSession(session) => { match session.read() {
                                                          Ok(res) => res.data,
                                                          Err(err) => String::from(err)
                                                        }
                                                      },
        }
    }

    pub fn write(&mut self, data: String) -> String {
        match self {
            MsfSessionType::WMeterpreterSession(session) => { match session.write(data) {
                                                                Ok(res) => res.result,
                                                                Err(err) => String::from(err)
                                                              }
                                                            },
            MsfSessionType::WShellSession(session) => { match session.write(data) {
                                                          Ok(res) => res.write_count,
                                                          Err(err) => String::from(err)
                                                        }
                                                      },
        }
    }

}

pub struct MeterpreterSession {
    conn: RcRef<Conn>,
    id: u32,
}

impl MeterpreterSession {

    pub fn read(&mut self) -> Res<SessionMeterpreterReadRet> {
        let cmd = CmdType::WSessionMeterpreterReadCmd(SessionMeterpreterReadCmd::new(self.id));
        match self.conn.borrow_mut().execute(cmd).unwrap() {
            RetType::WSessionMeterpreterReadRet(sr) => Ok(sr),
            _ => Err("incorrect type"),
        }
    }

    pub fn write(&mut self, data: String) -> Res<SessionMeterpreterWriteRet> {
        let cmd = CmdType::WSessionMeterpreterWriteCmd(SessionMeterpreterWriteCmd::new(self.id, data));
        match self.conn.borrow_mut().execute(cmd).unwrap() {
            RetType::WSessionMeterpreterWriteRet(sw) => Ok(sw),
            _ => Err("incorrect type"),
        }
    }
}

pub struct ShellSession {
    conn: RcRef<Conn>,
    id: u32,
}

impl ShellSession {

    pub fn read(&mut self) -> Res<SessionShellReadRet> {
        let cmd = CmdType::WSessionShellReadCmd(SessionShellReadCmd::new(self.id));
        match self.conn.borrow_mut().execute(cmd).unwrap() {
            RetType::WSessionShellReadRet(sr) => Ok(sr),
            _ => Err("incorrect type"),
        }
    }

    pub fn write(&mut self, data: String) -> Res<SessionShellWriteRet> {
        let cmd = CmdType::WSessionShellWriteCmd(SessionShellWriteCmd::new(self.id, data));
        match self.conn.borrow_mut().execute(cmd).unwrap() {
            RetType::WSessionShellWriteRet(sw) => Ok(sw),
            _ => Err("incorrect type"),
        }

    }

}

pub struct SessionManager {
    conn: RcRef<Conn>,
}

impl SessionManager {
    pub fn new(conn: RcRef<Conn>) -> SessionManager {
        SessionManager { conn }
    }

    pub fn list(&mut self) -> Res<SessionListRet> {
        let cmd = CmdType::WSessionListCmd(SessionListCmd::new());
        match self.conn.borrow_mut().execute(cmd).unwrap() {
            RetType::WSessionListRet(sl) => Ok(sl),
            _ => Err("incorrect type"),
        }
    }

    pub fn session(&mut self, id: u32) -> Res<MsfSessionType> {
        if let Ok(sl) = self.list() {
            let s = sl.get(&id).unwrap();
            if s.r#type == "meterpreter" {
                Ok(MsfSessionType::WMeterpreterSession(MeterpreterSession { conn: Rc::clone(&self.conn), id }))
            } else if s.r#type == "shell" {
                Ok(MsfSessionType::WShellSession(ShellSession { conn: Rc::clone(&self.conn), id }))
            } else {
                Err("unknown session")

            }
        }
        else {
            Err("error in list")
        }
    }
}
