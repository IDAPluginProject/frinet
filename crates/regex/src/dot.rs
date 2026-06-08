use crate::*;
use std::fmt::{self, Display};

impl<T> Automata<T>
where
    T: Display,
{
    pub fn to_dot(&self) -> String {
        let mut str = String::new();
        self.write_dot(&mut str).unwrap();
        str
    }

    pub fn write_dot(&self, out: &mut impl fmt::Write) -> fmt::Result {
        writeln!(out, "digraph {{")?;

        for init in &self.initial_states {
            writeln!(out, "s{init} [label=\"init_{init}\"]")?;
        }

        for accept in &self.accept_states {
            writeln!(out, "s{accept} [label=\"accept_{accept}\"]")?;
        }

        for link in &self.links {
            let Link { from, symbol, to } = link;
            writeln!(out, "s{from} -> s{to} [label=\"{symbol}\"]")?;
        }

        writeln!(out, "}}")?;
        Ok(())
    }
}
