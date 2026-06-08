use std::{
    fs::File,
    path::PathBuf,
    time::{Duration, Instant},
};

use clap::Parser;
use frinet_db::{db::Db, search::search};
use frinet_index::{
    build_index,
    parser::{Pass, Progress, ProgressReporter, TenetParser},
    storage::OnDisk,
};
use indicatif::{
    HumanBytes, HumanDuration, MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle,
};
use log::{LevelFilter, Log, error, info};
use memmap2::Mmap;

use crate::mem_usage::{max_mem_usage, reset_mem_usage};

mod mem_usage;

#[derive(clap::Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Index a trace file
    Index {
        /// Trace format
        #[arg(short, long)]
        format: TraceFormat,

        /// Input trace file
        trace_path: PathBuf,

        /// Output DB file
        db_path: PathBuf,
    },

    /// Regex search inside an indexed DB
    Search { db_path: PathBuf, pattern: String },
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
enum TraceFormat {
    /// Tenet trace format
    Tenet,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Index {
            trace_path,
            db_path,
            ..
        } => {
            let multi = MultiProgress::new();
            setup_logging(Some(&multi));

            let start = Instant::now();
            reset_mem_usage();

            let mut reporter = IndicatifProgress::new(multi.clone());
            let mut parser = TenetParser::new(trace_path);
            let mut storage = OnDisk::new(db_path);
            build_index(&mut parser, &mut reporter, &mut storage, 3);

            // build is over, prevent redrawing progress bars after logging a message
            multi.set_draw_target(ProgressDrawTarget::hidden());

            let duration = start.elapsed();
            let mem_usage = max_mem_usage();

            info!("Total time : {}", HumanDuration(duration));
            info!("Maximum memory usage : {}", HumanBytes(mem_usage as _));
        }
        Commands::Search { db_path, pattern } => {
            setup_logging(None);
            info!("eee");

            let file = File::open(db_path).unwrap();
            let mmap = unsafe { Mmap::map(&file) }.unwrap();

            match Db::from_aligned_slice(&mmap) {
                Ok(db) => {
                    for result in search(&db, pattern.as_bytes()) {
                        println!(
                            "{}..{} : {:#x?}..{:#x?}",
                            result.time_min, result.time_max, result.addr_min, result.addr_max,
                        );
                    }
                }
                Err(err) => {
                    error!("Loading fail : {err}")
                }
            }
        }
    }
}

fn setup_logging(multi: Option<&MultiProgress>) {
    let logger = env_logger::Builder::new()
        .filter_level(LevelFilter::Info)
        .parse_default_env()
        .build();

    let max_level = logger.filter();

    let boxed_logger: Box<dyn Log> = if let Some(multi) = multi.cloned() {
        Box::new(LogWrapper { log: logger, multi })
    } else {
        Box::new(logger)
    };

    let r = log::set_boxed_logger(boxed_logger);
    if r.is_ok() {
        log::set_max_level(max_level);
    }
}

pub struct LogWrapper<L: Log> {
    multi: MultiProgress,
    log: L,
}

impl<L: Log> Log for LogWrapper<L> {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        self.log.enabled(metadata)
    }

    fn log(&self, record: &log::Record) {
        if self.log.enabled(record.metadata()) {
            self.multi.suspend(|| self.log.log(record))
        }
    }

    fn flush(&self) {
        self.log.flush()
    }
}

struct IndicatifProgress {
    current_pass: Option<Pass>,
    scout: ProgressBar,
    partitions: ProgressBar,
    fill: ProgressBar,
}

impl IndicatifProgress {
    pub fn new(multi: MultiProgress) -> Self {
        let style = ProgressStyle::with_template(
            "{prefix:>10} [{elapsed_precise}] {wide_bar:.cyan/blue} {bytes:>7}/{total_bytes:7} {msg}",
        )
        .unwrap()
        .progress_chars("##-");

        let mut scout = ProgressBar::no_length().with_prefix("Scout");
        let mut partitions = ProgressBar::no_length().with_prefix("Partitions");
        let mut fill = ProgressBar::no_length().with_prefix("Fill");

        let bars = [&mut scout, &mut partitions, &mut fill];

        for bar in bars {
            *bar = multi.add(bar.clone().with_style(style.clone()));
            bar.force_draw();
        }

        Self {
            scout,
            partitions,
            fill,
            current_pass: None,
        }
    }

    fn bar(&mut self, pass: Pass) -> &mut ProgressBar {
        match pass {
            Pass::Scout => &mut self.scout,
            Pass::Partitions => &mut self.partitions,
            Pass::Fill => &mut self.fill,
        }
    }
}

impl ProgressReporter for IndicatifProgress {
    fn report(&mut self, progress: Progress) {
        match progress {
            Progress::Start(pass) => {
                if let Some(pass) = self.current_pass {
                    self.bar(pass).finish();
                }
                self.current_pass = Some(pass);
                self.bar(pass).set_elapsed(Duration::ZERO);
            }
            Progress::Finish => {
                if let Some(pass) = self.current_pass {
                    self.bar(pass).finish();
                }
                self.current_pass = None;
            }
            Progress::Total(len) => {
                let Some(pass) = self.current_pass else {
                    return;
                };
                self.bar(pass).set_length(len as _);
            }
            Progress::Current(pos) => {
                let Some(pass) = self.current_pass else {
                    return;
                };
                self.bar(pass).set_position(pos as _);
            }
        }
    }
}
