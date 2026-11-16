// SPDX-License-Identifier: LGPL-2.1-or-later
//! `strbuf.c`: strings in one buffer, with identical strings and string
//! tails stored only once, found through a trie of the strings reversed.

/// `struct strbuf_node`.
#[derive(Debug, Default)]
struct Node {
    value_off: usize,
    value_len: usize,
    /// Sorted by the byte.
    children: Vec<(u8, usize)>,
}

/// `struct strbuf`.
#[derive(Debug)]
pub struct Strbuf {
    pub buf: Vec<u8>,
    nodes: Vec<Node>,
    pub nodes_count: usize,
    pub in_count: usize,
    pub in_len: usize,
    pub dedup_len: usize,
    pub dedup_count: usize,
}

impl Default for Strbuf {
    fn default() -> Self {
        Strbuf::new()
    }
}

impl Strbuf {
    /// `strbuf_new()`: the buffer starts with the empty string.
    pub fn new() -> Strbuf {
        Strbuf {
            buf: vec![0],
            nodes: vec![Node::default()],
            nodes_count: 1,
            in_count: 0,
            in_len: 0,
            dedup_len: 0,
            dedup_count: 0,
        }
    }

    /// `strbuf_add_string_full(str, s, len)`: the offset of s (NUL-terminated
    /// in the buffer).
    pub fn add(&mut self, s: &[u8]) -> usize {
        let len = s.len();
        self.in_count += 1;
        if len == 0 {
            self.dedup_count += 1;
            return 0;
        }
        self.in_len += len;

        // Search from the last character, to find matching tails.
        let mut node = 0usize;
        let mut c = 0u8;
        for depth in 0..=len {
            let n = &self.nodes[node];
            if depth == len
                || (n.value_len >= len && self.buf[n.value_off + n.value_len - len..n.value_off + n.value_len] == *s)
            {
                self.dedup_len += len;
                self.dedup_count += 1;
                return n.value_off + n.value_len - len;
            }
            c = s[len - 1 - depth];
            match n.children.binary_search_by_key(&c, |&(k, _)| k) {
                Ok(k) => node = n.children[k].1,
                Err(_) => break,
            }
        }

        let off = self.buf.len();
        self.buf.extend_from_slice(s);
        self.buf.push(0);
        self.nodes.push(Node { value_off: off, value_len: len, children: Vec::new() });
        let child = self.nodes.len() - 1;
        self.nodes_count += 1;
        // bubbleinsert(): after any equal keys (there are none).
        let ch = &mut self.nodes[node].children;
        let pos = ch.partition_point(|&(k, _)| k <= c);
        ch.insert(pos, (c, child));
        off
    }

    /// `strbuf_complete()`: drop the trie, keep the buffer.
    pub fn complete(&mut self) {
        self.nodes = Vec::new();
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.len() <= 1
    }
}
