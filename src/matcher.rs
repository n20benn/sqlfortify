use crate::sql;
use crate::sql::Token as SqlToken;
use fnv;
use std::collections::{hash_map::Entry, HashMap};

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

struct Node<T: sql::Token> {
    id: NodeID,
    next_param_id: Option<NodeID>,
    is_valid_pattern: bool,
    is_vuln_prefix: bool,
    is_constant: bool,
    next: HashMap<T, Node<T>, fnv::FnvBuildHasher>, // TODO: maybe assess risk of HashDOS in SQLI
}

impl<T: sql::Token> Node<T> {
    fn new(id: NodeID) -> Self {
        Self {
            id: id,
            next_param_id: None,
            is_valid_pattern: false,
            is_vuln_prefix: false,
            is_constant: true,
            next: HashMap::with_hasher(fnv::FnvBuildHasher::default()),
        }
    }

    fn get_child(&self, token: &T) -> Option<&Node<T>> {
        self.next.get(token)
    }

    fn get_child_mut(&mut self, token: &T) -> Option<&mut Node<T>> {
        self.next.get_mut(token)
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

pub struct NodeInfo<'a, T: sql::Token> {
    node: &'a Node<T>,
    pub absolute_index: usize,
    pub directional_index: usize,
    pub is_exact_match: bool,
    pub has_vuln_prefix: bool,
}

impl<'a, T: sql::Token> NodeInfo<'a, T> {
    pub fn get_id(&self) -> NodeID {
        self.node.id
    }
}

/// A Bi-directional Trie data structure, specialized for our particular use case in matching vulnerable/benign SQL queries.
pub struct BiTrie<D: sql::Detector> {
    fwd_root: Node<D::Token>, // Empty node to make traversal more easy
    rev_root: Node<D::Token>, // ditto
    id_counter: IDCounter,
    // Settings for check strictness can be stored in here (and passed in on new())
}

impl<D: sql::Detector> BiTrie<D> {
    pub fn new() -> Self {
        let mut counter = IDCounter::new();
        Self {
            fwd_root: Node::new(counter.next()),
            rev_root: Node::new(counter.next()),
            id_counter: counter,
        }
    }

    pub fn match_prefix<'a>(
        &'a self,
        forward_tokens: &Vec<(D::Token, usize)>,
    ) -> Option<NodeInfo<'a, D::Token>> {
        let mut last_param_parent_node: Option<&Node<D::Token>> = None;
        let mut node = &self.fwd_root;
        let mut prefix_index = 0;
        let mut absolute_index = 0;
        let mut has_vuln_prefix = false;

        for (idx, (token, abs_idx)) in forward_tokens.iter().enumerate() {
            if !node.next_param_id.is_none() {
                last_param_parent_node = Some(node);
                prefix_index = idx;
                absolute_index = *abs_idx;
            }

            if node.is_vuln_prefix {
                has_vuln_prefix = true;
            }

            node = match node.get_child(token) {
                Some(n) => n,
                None => break, // Prefix found
            };

            if idx == forward_tokens.len() - 1 && node.is_valid_pattern {
                // All of the tokens have been traversed--it's an exact match
                return Some(NodeInfo {
                    node: node, // NOTE: this isn't technically the right node, but we don't use it anyway when node.is_valid_pattern == true
                    absolute_index: *abs_idx,
                    directional_index: idx,
                    is_exact_match: node.is_valid_pattern,
                    has_vuln_prefix: has_vuln_prefix,
                });
            }
        }

        match last_param_parent_node {
            Some(node) => Some(NodeInfo {
                node: node,
                absolute_index: absolute_index,
                directional_index: prefix_index,
                is_exact_match: false,
                has_vuln_prefix: has_vuln_prefix,
            }),
            None => None,
        }
    }

    pub fn match_suffix<'a>(
        &'a self,
        reverse_tokens: &Vec<(D::Token, usize)>,
        prefix: &'a NodeInfo<D::Token>,
    ) -> Option<NodeInfo<'a, D::Token>> {
        let fwd_param_id = match prefix.node.next_param_id {
            Some(id) => id,
            None => return None, // NOTE: this should never be the case, as `match_prefix()` only returns nodes with a `next_param_id`
        };

        let mut suffix = None;
        let mut node = &self.rev_root;
        for (suffix_idx, (token, abs_idx)) in reverse_tokens.iter().enumerate() {
            if *abs_idx <= prefix.absolute_index {
                break; // If the suffix overlaps with the prefix, we stop
            }

            if prefix.node.next_param_id == Some(fwd_param_id) {
                // We want the longest suffix, so we overwrite past suffix matches here
                suffix = Some(NodeInfo {
                    node: node,
                    absolute_index: *abs_idx,
                    directional_index: suffix_idx,
                    is_exact_match: false,
                    has_vuln_prefix: false,
                });
            }

            node = match node.get_child(token) {
                Some(n) => n,
                None => break, // Prefix found
            };
        }

        suffix
    }

    pub fn mark_vulnerable(
        &mut self,
        sql_query: &Vec<(D::Token, usize)>,
        vuln_prefix_id: Option<NodeID>,
    ) {
        let mut node = &mut self.fwd_root;
        match vuln_prefix_id {
            Some(vuln_id) => {
                for (token, _) in sql_query.iter() {
                    if let Some(id) = node.next_param_id.as_ref() {
                        if *id == vuln_id {
                            node.is_vuln_prefix = true;
                            return;
                        }
                    }

                    if node.get_child(token).is_none() {
                        node.is_vuln_prefix = true; // Should never happen...
                    }

                    node = match node.get_child_mut(token) {
                        Some(next_node) => next_node,
                        None => return,
                    }
                }
            }
            None => {
                // Go until first parameter is found, then mark that prefix as vulnerable
                for (token, _) in sql_query.iter() {
                    if token.is_param_token() {
                        node.is_vuln_prefix = true;
                        return;
                    }

                    // Go to next node, creating it if it doesn't exist
                    node = node.get_child_update(token.clone(), &mut self.id_counter);
                }

                node.is_vuln_prefix = true;
            }
        }
    }

    // If pattern already exists, just updates is_constant values.
    // Could also name insert()
    pub fn insert(&mut self, sql_query: Vec<(D::Token, usize)>) {
        let token_id_pairs = self.update_fwd_tree(sql_query);
        self.update_rev_tree(token_id_pairs);
    }

    // Consumes the vector of tokens and produces a vector of
    // tuples with those tokens (and NodeIDs) to use
    fn update_fwd_tree(&mut self, sql_query: Vec<(D::Token, usize)>) -> Vec<(D::Token, NodeID)> {
        let mut node = &mut self.fwd_root;
        let mut fwd_nodes = vec![];

        // Consume each token and traverse tree, adding/updating nodes as needed
        for (token, _) in sql_query.into_iter() {
            let make_nonconst = match node.next.get_key_value(&token) {
                Some((existing_token, _)) => {
                    token.is_param_token() && !token.deep_eq(existing_token)
                }
                None => false,
            };

            node = match node.next.entry(token.clone()) {
                Entry::Occupied(o) => {
                    let next_node = o.into_mut();
                    if make_nonconst {
                        next_node.is_constant = false;
                        node.next_param_id = Some(next_node.id);
                    }
                    next_node
                }
                Entry::Vacant(v) => v.insert(Node::new(self.id_counter.next())),
            };

            fwd_nodes.push((token, node.id.clone()));
        }

        node.is_valid_pattern = true;
        fwd_nodes
    }

    fn update_rev_tree(&mut self, rev_nodes: Vec<(D::Token, NodeID)>) {
        let mut node = &mut self.rev_root;

        // Consume each token and traverse tree, adding/updating nodes as needed
        for (token, _) in rev_nodes {
            let make_nonconst = match node.next.get_key_value(&token) {
                Some((k, _)) => token.is_param_token() && !token.deep_eq(k),
                None => false,
            };

            node = match node.next.entry(token) {
                Entry::Occupied(o) => {
                    let next_node = o.into_mut();
                    if make_nonconst {
                        next_node.is_constant = false;
                        node.next_param_id = Some(next_node.id);
                    }
                    next_node
                }
                Entry::Vacant(v) => v.insert(Node::new(self.id_counter.next())),
            };
        }

        node.is_valid_pattern = true; // Not sure we need this...
    }
}
