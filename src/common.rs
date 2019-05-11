use std::rc::Rc;
use std::cell::RefCell;

pub type Res<T> = Result<T, &'static str>;
pub type RcRef<T> = Rc<RefCell<T>>;
