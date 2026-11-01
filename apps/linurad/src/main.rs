#![forbid(unsafe_code)]

mod session_audio;
mod session_audit;

use std::error::Error;

use linura_linux_observation::{AlpmInstalledObserver, NetworkManagerObserver, PipeWireSessionObserver, SystemdObserver, XdgApplicationObserver, XdgMimeAppsObserver};
use linura_observation_control::ObservationCoordinator;

fn main() {
    if let Err(error) = run() {
        eprintln!("linurad: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut coordinator = ObservationCoordinator::new();
    coordinator.register_observer(Box::new(SystemdObserver::connect()?))?;
    coordinator.register_observer(Box::new(NetworkManagerObserver::connect()?))?;
    coordinator.register_observer(Box::new(PipeWireSessionObserver::new()))?;
    // User-session read-only application files; health fails closed without HOME.
    coordinator.register_observer(Box::new(XdgApplicationObserver::from_environment()))?;
    // Local ALPM inventory is a read-only provider; absent/locked DB stays unavailable.
    coordinator.register_observer(Box::new(AlpmInstalledObserver::system()))?;
    // Parsed MIME defaults remain candidates until desktop association verification.
    coordinator.register_observer(Box::new(XdgMimeAppsObserver::from_environment()))?;
    let state_dir = session_audio::state_dir().map_err(std::io::Error::other)?;
    let session_runtime =
        session_audio::SessionAudioRuntime::open(&state_dir).map_err(std::io::Error::other)?;
    linura_dbus::serve_with_session1(coordinator, session_runtime)?;
    Ok(())
}
