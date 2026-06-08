use std::{
    fmt::{Display, Write},
    num::NonZeroU32,
};

use rustc_hash::FxHashSet;

use crate::Counter;

pub type State = NonZeroU32;

/// Generic structure behind [Nfa] & [Dfa]
#[derive(Debug, Clone)]
pub struct Automata<T> {
    pub initial_states: FxHashSet<State>,
    pub accept_states: FxHashSet<State>,
    pub links: Vec<Link<T>>,
}

#[derive(Debug, Clone)]
pub struct Link<T> {
    pub from: State,
    pub to: State,
    pub symbol: T,
}

impl<T> Link<T> {
    pub fn into_nfa(self) -> NfaLink<T> {
        Link {
            from: self.from,
            to: self.to,
            symbol: MaybeSymbol::Symbol(self.symbol),
        }
    }
}

pub type Nfa<T> = Automata<MaybeSymbol<T>>;
pub type Dfa<T> = Automata<T>;

pub type NfaLink<T> = Link<MaybeSymbol<T>>;
pub type DfaLink<T> = Link<T>;

pub enum MaybeSymbol<T> {
    Symbol(T),
    Epsilon,
}

impl<T: Display> Display for MaybeSymbol<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MaybeSymbol::Symbol(it) => Display::fmt(it, f),
            MaybeSymbol::Epsilon => f.write_char('ε'),
        }
    }
}

impl<T> Dfa<T> {
    /// Get the unique DFA initial state
    pub fn initial_state(&self) -> State {
        assert_eq!(
            self.initial_states.len(),
            1,
            "DFA should have exactly 1 initial state"
        );
        *self.initial_states.iter().next().unwrap()
    }

    /// Cheaply convert DFA as NFA
    pub fn into_nfa(self) -> Nfa<T> {
        let links = self.links.into_iter().map(Link::into_nfa).collect();
        Nfa {
            initial_states: self.initial_states,
            accept_states: self.accept_states,
            links,
        }
    }
}

impl<T> Default for Automata<T> {
    fn default() -> Self {
        Self {
            initial_states: Default::default(),
            accept_states: Default::default(),
            links: Default::default(),
        }
    }
}

impl<T> Automata<T> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn invert(&mut self) {
        std::mem::swap(&mut self.accept_states, &mut self.initial_states);
        for link in self.links.iter_mut() {
            std::mem::swap(&mut link.from, &mut link.to);
        }
    }

    pub fn links_from(&self, from: State) -> impl Iterator<Item = &Link<T>> {
        self.links.iter().filter(move |link| link.from == from)
    }

    pub fn links_to(&self, to: State) -> impl Iterator<Item = &Link<T>> {
        self.links.iter().filter(move |link| link.to == to)
    }

    pub fn links_from_to(&self, from: State, to: State) -> impl Iterator<Item = &Link<T>> {
        self.links
            .iter()
            .filter(move |link| link.from == from && link.to == to)
    }

    pub fn remove_links(&mut self, from: State, to: State) {
        self.links
            .retain(|link| !(link.from == from && link.to == to))
    }

    pub fn remove_links_any(&mut self, from_or_to: State) {
        self.links
            .retain(|link| !(link.from == from_or_to || link.to == from_or_to))
    }

    pub fn max_state(&self) -> Option<State> {
        self.states().max()
    }

    pub fn next_counter(&self) -> Counter {
        let next_counter_state = self
            .max_state()
            .map(|x| x.checked_add(1).unwrap())
            .unwrap_or(State::MIN);
        Counter::new(next_counter_state)
    }

    pub fn states_set(&self) -> FxHashSet<State> {
        self.states().collect()
    }

    pub fn states(&self) -> impl Iterator<Item = State> + '_ {
        self.initial_states
            .iter()
            .copied()
            .chain(self.accept_states.iter().copied())
            .chain(self.links.iter().flat_map(|l| [l.from, l.to]))
    }

    pub fn non_special_states(&self) -> impl Iterator<Item = State> + '_ {
        self.links
            .iter()
            .flat_map(|l| [l.from, l.to])
            .filter(|s| !self.initial_states.contains(s) && !self.accept_states.contains(s))
    }

    pub fn link(&mut self, from: State, to: State, symbol: T) {
        self.links.push(Link { from, to, symbol })
    }

    pub fn map<F>(&self, mut mapper: impl FnMut(&T) -> F) -> Automata<F> {
        Automata {
            initial_states: self.initial_states.clone(),
            accept_states: self.accept_states.clone(),
            links: self
                .links
                .iter()
                .map(|link| Link {
                    from: link.from,
                    to: link.to,
                    symbol: mapper(&link.symbol),
                })
                .collect(),
        }
    }

    pub fn into_map<F>(self, mut mapper: impl FnMut(T) -> F) -> Automata<F> {
        Automata {
            initial_states: self.initial_states,
            accept_states: self.accept_states,
            links: self
                .links
                .into_iter()
                .map(|link| Link {
                    from: link.from,
                    to: link.to,
                    symbol: mapper(link.symbol),
                })
                .collect(),
        }
    }
}
