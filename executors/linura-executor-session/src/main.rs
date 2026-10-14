#![forbid(unsafe_code)]
fn main() {
    let mut arguments = std::env::args_os().skip(1);
    let first = arguments.next();
    let result = match (first.as_deref(), arguments.next()) {
        (None, None) => linura_executor_session::serve(),
        (Some(argument), None) if argument == "--protect-before-sleep" => {
            linura_linux_session::protect_before_native_sleep()
        }
        _ => Err("unsupported fixed session-executor invocation".into()),
    };
    if let Err(error) = result {
        eprintln!("linura-executor-session failed closed: {error}");
        std::process::exit(1);
    }
}
