#![forbid(unsafe_code)]

mod runtime;
mod systemd_adapter;

use std::error::Error;

fn serve() -> Result<(), Box<dyn Error>> {
    let runtime =
        runtime::ManagedRuntime::open(&runtime::state_dir()).map_err(std::io::Error::other)?;
    linura_dbus::serve_authority1(runtime)?;
    Ok(())
}

fn main() {
    if let Err(error) = serve() {
        eprintln!("linura-authorityd failed closed: {error}");
        std::process::exit(1);
    }
}
