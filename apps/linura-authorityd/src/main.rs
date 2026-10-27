#![forbid(unsafe_code)]

mod display_adapter;
mod runtime;
mod session_adapter;
mod session_approval;
mod sleep_gate;
mod systemd_adapter;

use std::error::Error;

fn serve() -> Result<(), Box<dyn Error>> {
    let channel = linura_linux_session::NativeSessionChannel::connect(
        linura_linux_session::NativeSessionRole::Control,
    )
    .map_err(std::io::Error::other)?;
    let connection = channel.service_connection();
    let (runtime, gate) = runtime::ManagedRuntime::open(&runtime::state_dir(), channel)
        .map_err(std::io::Error::other)?;
    linura_dbus::register_native_sleep_gate(&connection, gate)?;
    linura_dbus::serve_authority1(connection, runtime)?;
    Ok(())
}

fn main() {
    if let Err(error) = serve() {
        eprintln!("linura-authorityd failed closed: {error}");
        std::process::exit(1);
    }
}
