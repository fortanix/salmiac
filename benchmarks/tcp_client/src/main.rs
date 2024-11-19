use clap::Parser;
use std::time::{Duration, Instant};
use std::net::{TcpStream, ToSocketAddrs};

#[derive(Parser)]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[arg(long)]
    address: String,

    #[arg(long)]
    port: u16,

    #[arg(long)]
    num_runs: usize,
}

fn time<F>(func: F, num_runs: usize)
    where F: Fn() -> () {
    let mut timings = Vec::new();

    println!("Starting test...");
    for _i in 0..num_runs {
        let t0 = Instant::now();
        (func)();
        let duration = t0.elapsed();
        timings.push(duration)
    }

    println!("Results:");
    for i in 0..num_runs {
        println!("{i}: {:?}", timings[i]);
    }
    println!("---");
    let min = timings.iter().min().unwrap_or(&Duration::ZERO);
    let max = timings.iter().max().unwrap_or(&Duration::ZERO);
    let avg = timings.iter().sum::<Duration>() / (timings.len().try_into().unwrap());
    let med = {
        let mut dup = timings.clone();
        dup.sort();
        let mid = dup.len() / 2;
        if dup.len() % 2 == 0 {
            (dup[mid] + dup[mid + 1]) / 2
        } else {
            dup[mid]
        }
    };
    println!("min = {:?}", min);
    println!("avg = {:?}", avg);
    println!("median = {:?}", med);
    println!("max = {:?}", max);
}

fn connect<A: ToSocketAddrs>(addr: A) {
    let _ = TcpStream::connect(addr).expect("Failed to connect");
}

fn main() {
    let cli = Cli::parse();
    let func = || { connect((cli.address.as_str(), cli.port)) };
    time(func, cli.num_runs);
}
