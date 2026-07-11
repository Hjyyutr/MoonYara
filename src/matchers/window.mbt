///| A node in the Aho-Corasick trie.
pub(all) struct AcNode {
  children : Map[Byte, Int]
  mut fail : Int
  output : Array[Int]
}

fn AcNode::new() -> AcNode {
  AcNode::{
    children: Map([]),
    fail: 0,
    output: [],
  }
}

///| Aho-Corasick automaton for multi-pattern matching.
pub(all) struct AhoCorasick {
  nodes : Array[AcNode]
  patterns : Array[Bytes]
}

fn AhoCorasick::insert(self : AhoCorasick, pattern_id : Int) -> Unit {
  let pattern = self.patterns[pattern_id]
  let mut node_idx = 0
  for i in 0..<pattern.length() {
    let b = pattern[i]
    if self.nodes[node_idx].children.contains(b) {
      node_idx = match self.nodes[node_idx].children.get(b) {
        Some(idx) => idx
        None => 0
      }
    } else {
      let new_idx = self.nodes.length()
      self.nodes.push(AcNode::new())
      self.nodes[node_idx].children.set(b, new_idx)
      node_idx = new_idx
    }
  }
  self.nodes[node_idx].output.push(pattern_id)
}

fn AhoCorasick::build_failure_links(self : AhoCorasick) -> Unit {
  let queue = []
  let root = self.nodes[0]
  
  for pair in root.children {
    let child_idx = pair.1
    self.nodes[child_idx].fail = 0
    queue.push(child_idx)
  }
  
  let mut head = 0
  while head < queue.length() {
    let current_idx = queue[head]
    head += 1
    
    let current_fail = self.nodes[current_idx].fail
    for pair in self.nodes[current_idx].children {
      let b = pair.0
      let child_idx = pair.1
      
      let mut f = current_fail
      while f > 0 && !self.nodes[f].children.contains(b) {
        f = self.nodes[f].fail
      }
      
      let target_fail = if self.nodes[f].children.contains(b) {
        match self.nodes[f].children.get(b) {
          Some(idx) => idx
          None => 0
        }
      } else {
        0
      }
      
      self.nodes[child_idx].fail = target_fail
      for out in self.nodes[target_fail].output {
        self.nodes[child_idx].output.push(out)
      }
      queue.push(child_idx)
    }
  }
}

///| Creates a new Aho-Corasick automaton from an array of patterns.
pub fn AhoCorasick::new(patterns : Array[Bytes]) -> AhoCorasick {
  let nodes = [AcNode::new()]
  let ac = AhoCorasick::{ nodes, patterns }
  for i in 0..<patterns.length() {
    ac.insert(i)
  }
  ac.build_failure_links()
  ac
}

///| Scans data bytes for all patterns, returning pairs of (pattern_id, match_start_offset).
pub fn AhoCorasick::match_aho_corasick(self : AhoCorasick, data : Bytes) -> Array[(Int, Int)] {
  let results = []
  let mut node_idx = 0
  for i in 0..<data.length() {
    let b = data[i]
    while node_idx > 0 && !self.nodes[node_idx].children.contains(b) {
      node_idx = self.nodes[node_idx].fail
    }
    if self.nodes[node_idx].children.contains(b) {
      node_idx = match self.nodes[node_idx].children.get(b) {
        Some(idx) => idx
        None => 0
      }
    } else {
      node_idx = 0
    }
    
    for pattern_id in self.nodes[node_idx].output {
      let pattern_len = self.patterns[pattern_id].length()
      let start_pos = i - pattern_len + 1
      results.push((pattern_id, start_pos))
    }
  }
  results
}
