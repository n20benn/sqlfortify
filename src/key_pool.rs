use std::collections::HashSet;



pub struct KeyPool {
    available_keys: HashSet<usize>,
    next_key: usize,
}

impl KeyPool {
    pub fn new() -> Self {
        KeyPool {
            available_keys: HashSet::new(),
            next_key: 0
        }
    }

    pub fn take_key(&mut self) -> usize {
        match self.available_keys.iter().next().copied() {
            Some(key) => {
                self.available_keys.remove(&key);
                key
            },
            None => {
                self.next_key += 1;
                self.next_key
            }
        }
    }

    pub fn return_key(&mut self, key: usize) {
        self.available_keys.insert(key);
    }
}

