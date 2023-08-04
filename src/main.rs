use async_std::task;
use clap::Parser;
use web::start_webserver;

mod crypto;
mod data;
mod templates;
mod web;

/// HTTP server used for accepting files from friends. Data
/// data are saved in the working directory
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    /// Secret token used for cryptographically signing links
    #[clap(short, long)]
    secret: String,

    /// Allow unlimited uploads to a given directory on the root url
    #[clap(long)]
    public_access: Option<String>,

    /// TCP port to listen on
    #[clap(short, long, default_value_t = 3000)]
    port: u16,

    /// IP to listen on
    #[clap(short, long, default_value = "127.0.0.1")]
    listen_ip: String,

    #[clap(short, long, default_value = "http://localhost:3000")]
    base_url: String,
}

fn main() -> tide::Result<()> {
    let args = Args::parse();
    task::block_on(start_webserver(args))
}
