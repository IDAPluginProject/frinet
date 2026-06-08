use crate::Dfa;

/// Not optimized DFA executor for testing
pub fn execute_dfa<T>(dfa: &Dfa<T>, haystack: &[T]) -> Option<usize>
where
    T: Eq,
{
    let mut state = dfa.initial_state();

    'next_item: for (idx, item) in haystack.iter().enumerate() {
        if dfa.accept_states.contains(&state) {
            return Some(idx);
        }

        for link in dfa.links_from(state) {
            if &link.symbol == item {
                state = link.to;
                continue 'next_item;
            }
        }

        return None;
    }

    dfa.accept_states.contains(&state).then_some(haystack.len())
}
