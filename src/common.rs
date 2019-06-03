use std::rc::Rc;
use std::cell::RefCell;

use std::collections::HashMap;

pub type Res<T> = Result<T, &'static str>;
pub type RcRef<T> = Rc<RefCell<T>>;

pub type RunOptions = HashMap<String,String>;
