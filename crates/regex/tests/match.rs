use frinet_regex::{determine_and_minimize_nfa, execute_dfa, hir_to_nfa};
use regex_syntax::parse;

#[test]
fn optional() {
    let nfa = hir_to_nfa(&parse("ab?c").unwrap());
    let dfa = determine_and_minimize_nfa(nfa);

    assert!(execute_dfa(&dfa, b"abc").is_some());
    assert!(execute_dfa(&dfa, b"ac").is_some());

    assert!(execute_dfa(&dfa, b"a").is_none());
    assert!(execute_dfa(&dfa, b"b").is_none());
    assert!(execute_dfa(&dfa, b"c").is_none());
    assert!(execute_dfa(&dfa, b"ab").is_none());
    assert!(execute_dfa(&dfa, b"bc").is_none());
    assert!(execute_dfa(&dfa, b"abbc").is_none());
    assert!(execute_dfa(&dfa, b"_ac").is_none());
    assert!(execute_dfa(&dfa, b"_abc").is_none());
}

#[test]
fn repeat_bounded() {
    let nfa = hir_to_nfa(&parse("ab{1,3}c").unwrap());
    let dfa = determine_and_minimize_nfa(nfa);

    assert!(execute_dfa(&dfa, b"abc").is_some());
    assert!(execute_dfa(&dfa, b"abbc").is_some());
    assert!(execute_dfa(&dfa, b"abbbc").is_some());

    assert!(execute_dfa(&dfa, b"ac").is_none());
    assert!(execute_dfa(&dfa, b"abbbbc").is_none());
}
