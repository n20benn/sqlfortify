use super::token::SqlToken;
use hashbrown::{hash_map::Entry, HashMap, HashSet}; // Switch to std HashMap once get_key_value_mut and try_insert are implemented

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeID {
    value: usize,
}

struct IDCounter {
    counter: usize,
}

impl IDCounter {
    pub fn new() -> Self {
        Self { counter: 0 }
    }

    pub fn next(&mut self) -> NodeID {
        self.counter += 1;

        NodeID {
            value: self.counter,
        }
    }
}

struct Node<T: SqlToken> {
    id: NodeID,
    next_param_ids: HashSet<NodeID>,
    is_valid_pattern: bool,
    is_vuln_prefix: bool,
    is_constant: bool,
    next: HashMap<T, Node<T>>,
}

impl<T: SqlToken> Node<T> {
    fn new(id: NodeID) -> Self {
        Self {
            id: id,
            next_param_ids: HashSet::new(),
            is_valid_pattern: false,
            is_vuln_prefix: false,
            is_constant: true,
            next: HashMap::new(),
        }
    }

    fn get_child(&self, token: &T) -> Option<&Node<T>> {
        self.next.get(token)
    }

    fn get_child_mut(&mut self, token: &T) -> Option<&mut Node<T>> {
        self.next.get_mut(token)
    }

    fn get_key_value(&self, token: &T) -> Option<(&T, &Node<T>)> {
        self.next.get_key_value(token)
    }

    fn get_key_value_mut(&mut self, token: &T) -> Option<(&T, &mut Node<T>)> {
        self.next.get_key_value_mut(token)
    }

    fn get_child_update(&mut self, token: T, id_counter: &mut IDCounter) -> &mut Node<T> {
        // This code took a lot of digging to get right, so I'm going to leave some info here.
        // Rust has this thing where you can't borrow mutable references twice in one
        // scope *even when* the first reference is only in an execution path that
        // is guaranteed to return without the second mut ref being created. It's something
        // being worked on, but for now the below code will not compile because of this:

        //  match self.next.get_mut(token) {
        //      Some(n) => return n,
        //      None => {
        //          match self.next.try_insert(token.clone(), Node::new(id_counter.next())) {
        //              Ok(mut_ref) => mut_ref,
        //              Err(occupied) => occupied.entry.into_mut() // Won't happen, but still safe nonetheless
        //          }
        //      }
        //  }

        // Now, the solution proposed [here](https://stackoverflow.com/questions/50251487/what-are-non-lexical-lifetimes)
        // uses entries in the hashmap along with or_insert(), like so:

        //  self.next.entry(token.clone()).or_insert(Node::new(id_counter.next()))

        // The downside of this is that you have to allocate whatever is being passed into the hashmap
        // (in our case, a Node<T>), which can be expensive if you're doing this *every single time* you
        // traverse a node (which we are in this case). So, we break the entry into a match statement as
        // seen below; that way it only executes that code (and allocates the node/increments the pointer)
        // if the entry is vacant.

        let map_entry = self.next.entry(token);

        match map_entry {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(Node::new(id_counter.next())),
        }
    }
}

pub struct SqlMatcher<T: SqlToken> {
    fwd_root: Node<T>, // Empty node to make traversal more easy
    rev_root: Node<T>, // ditto
    id_counter: IDCounter,
}

impl<T: SqlToken> SqlMatcher<T> {
    pub fn new() -> Self {
        let mut counter = IDCounter::new();
        Self {
            fwd_root: Node::new(counter.next()),
            rev_root: Node::new(counter.next()),
            id_counter: counter,
        }
    }

    /// Returns the indices of the end of the prefix/beginning of the suffix of a given past seen query, if any such query matches.
    pub fn get_prefix_suffix_indices(&self, sql_query: &Vec<T>) -> Option<(usize, Option<usize>)> {
        // let param_tokens = T::param_tokens();
        let mut last_param_parent_node: Option<&Node<T>> = None;
        let mut node = &self.fwd_root;
        let mut fwd_idx = 0; 

        for (idx, token) in sql_query.iter().enumerate() {
            if !node.next_param_ids.is_empty() {
                last_param_parent_node = Some(node);
                fwd_idx = idx;
            }

            node = match node.get_child(token) {
                Some(n) => n,
                None => break, // Prefix found
            };

            if idx + 1 == sql_query.len() {
                return Some((idx + 1, Some(idx + 1)))
            }
        }
        
        // If we don't have a prefix, what's the point of searching for a suffix...
        let curr_param_parent_node = match last_param_parent_node {
            Some(n) => n,
            None => return None,
        };

        let mut rev_idx = None;
        node = &self.rev_root;

        for (idx, token) in sql_query.iter().rev().take(sql_query.len() - (fwd_idx + 1)).enumerate() {
            if !node.next_param_ids.is_disjoint(&curr_param_parent_node.next_param_ids) {
                rev_idx = Some(sql_query.len() - idx);
            }

            node = match node.get_child(token) {
                Some(i) => i,
                None => break,
            }
        }

        Some((fwd_idx, rev_idx))
    }

    pub fn is_exact_match(&self, sql_query: &Vec<T>) -> bool {
        let mut node = &self.fwd_root;

        for token in sql_query.iter() {
            node = match node.get_child(token) {
                Some(i) => i,
                None => return false,
            };
        }

        node.is_valid_pattern
    }

    pub fn match_prefix_suffix(&self, sql_query: &Vec<T>) -> HashSet<NodeID> {
        // let param_tokens = T::param_tokens();
        let mut last_param_parent_node: Option<&Node<T>> = None;
        let mut node = &self.fwd_root;
        let mut fwd_count = 0; 

        for (idx, token) in sql_query.iter().enumerate() {
            if !node.next_param_ids.is_empty() {
                last_param_parent_node = Some(node);
                fwd_count = idx + 1;
            }

            node = match node.get_child(token) {
                Some(n) => n,
                None => break, // Prefix found
            };

        }

        // If we don't have a prefix, what's the point of searching for a suffix...
        let curr_param_parent_node = match last_param_parent_node {
            Some(n) => n,
            None => return HashSet::new(),
        };

        let fwd_param_ids = &curr_param_parent_node.next_param_ids;
        let mut rev_param_ids: HashSet<NodeID> = HashSet::new();

        node = &self.rev_root;
        for token in sql_query.iter().rev().take(sql_query.len() - fwd_count) {
            rev_param_ids.extend(node.next_param_ids.iter()); // TODO: if parameters are all one type, it would be much more efficient...

            node = match node.get_child(token) {
                Some(i) => i,
                None => break,
            }
        }

        HashSet::from_iter(rev_param_ids.intersection(&fwd_param_ids).cloned())
    }

    pub fn match_prefix(&self, sql_query: &Vec<T>) -> HashSet<NodeID> {
        // let param_tokens = T::param_tokens();

        let mut last_param_node: Option<&Node<T>> = None;
        let mut node = &self.fwd_root;

        for token in sql_query.iter() {
            if !node.next_param_ids.is_empty() {
                last_param_node = Some(node);
            }

            node = match node.get_child(token) {
                Some(i) => i,
                None => break,
            };
        }

        match last_param_node {
            Some(node) => node.next_param_ids.clone(),
            None => HashSet::new(),
        }
    }

    pub fn mark_vuln(&mut self, sql_query: &Vec<T>, node_ids: &HashSet<NodeID>) {
        let mut node = &mut self.fwd_root;

        /*
        if node_ids.is_empty() {
            self.fwd_root.is_vuln_prefix = true;
            return
        }
        */

        for token in sql_query.iter() {
            if !node.next_param_ids.is_disjoint(node_ids) {
                node.is_vuln_prefix = true;
            }

            node = match node.get_child_mut(token) {
                Some(i) => i,
                None => return,
            };
        }
    }

    pub fn has_vuln(&self, sql_query: &Vec<T>) -> bool {
        let mut node = &self.fwd_root;

        for token in sql_query.iter() {
            if node.is_vuln_prefix {
                return true;
            }

            node = match node.get_child(token) {
                Some(i) => i,
                None => break,
            };
        }

        false
    }

    // If pattern already exists, just updates is_constant values.
    // Could also name insert()
    pub fn update_pattern(&mut self, sql_query: Vec<T>) {
        let token_id_pairs = self.update_fwd_tree(sql_query);
        self.update_rev_tree(token_id_pairs);
    }

    // Consumes the vector of tokens and produces a vector of
    // tuples with those tokens (and NodeIDs) to use
    fn update_fwd_tree(&mut self, sql_query: Vec<T>) -> Vec<(T, NodeID)> {
        let mut node = &mut self.fwd_root;
        let mut fwd_nodes = vec![];

        // Consume each token and traverse tree, adding/updating nodes as needed
        for token in sql_query.into_iter() {
            match node.next.get_key_value_mut(&token) {
                Some((existing_token, next_node)) => {
                    // We already know token == existing token; just check deep_eq

                    if token.is_param_token() && !token.deep_eq(existing_token) {
                        next_node.is_constant = false;
                        node.next_param_ids.insert(next_node.id.clone());
                    }
                }
                None => (),
            };

            // NOTE: Do this instead if you want to get rid of constant logic and assume all
            // integer/string types in SQL could be user input:
            //  if token.is_param_token() {
            //      node.next_param_ids.insert(next_node.id.clone());
            //  }

            // Go to next node, creating it if it doesn't exist
            node = node.get_child_update(token.clone(), &mut self.id_counter);
            fwd_nodes.push((token, node.id.clone()));
        }

        node.is_valid_pattern = true;
        fwd_nodes
    }

    fn update_rev_tree(&mut self, fwd_nodes: Vec<(T, NodeID)>) {
        let mut node = &mut self.rev_root;

        // Consume each token and traverse tree, adding/updating nodes as needed
        for (token, node_id) in fwd_nodes.into_iter().rev() {
            match node.get_key_value_mut(&token) {
                Some((existing_token, next_node)) => {
                    if token.is_param_token() && !token.deep_eq(existing_token) {
                        next_node.is_constant = false;
                        node.next_param_ids.insert(node_id);
                    }
                }
                None => (),
            };

            // Go to next node, creating it if it doesn't exist
            node = node.get_child_update(token, &mut self.id_counter);
        }

        node.is_valid_pattern = true; // Not sure we need this...
    }
}
