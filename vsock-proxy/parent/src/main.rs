mod network;
mod packet_capture;
mod parent;

use std::process;

use clap::{App, AppSettings, Arg, ArgMatches};
use log::{error, info, warn};
use model_types::ByteUnit;
use shared::models::UserProgramExitStatus;

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), String> {
    env_logger::init();

    let matches = console_arguments();
    let parent_args = ParentConsoleArguments::new(&matches);

    if std::env::vars().any(|e| e.0 == "USE_VSK" && (e.1.trim() == "true" || e.1 == "1" || e.1 == "True")) {
        info!("USE_VSK is set");
        assert!(
            std::env::vars().any(|e| e.0 == "FS_API_KEY"),
            "FS_API_KEY env var must be present when USE_VSK is set!"
        );
        assert!(
            std::env::vars().any(|e| e.0 == "FS_KEY_NAME"),
            "FS_KEY_NAME env var must be present when USE_VSK is set!"
        );
        assert!(
            std::env::vars().any(|e| e.0 == "FS_VSK_ENDPOINT"),
            "FS_VSK_ENDPOINT env var must be present when USE_VSK is set!"
        );
    }

    match parent::run(parent_args).await {
        Ok(UserProgramExitStatus::ExitCode(code)) => {
            info!("User program exits with code: {}", code);
            process::exit(code)
        }
        Ok(UserProgramExitStatus::TerminatedBySignal) => {
            info!("User program is terminated by signal.");
            process::exit(-1);
        }
        Err(e) => {
            error!("Parent exits with failure: {}", e);
            process::exit(-1);
        }
    }
}

struct ParentConsoleArguments {
    pub rw_block_file_size: ByteUnit,

    pub enclave_extra_args: Vec<String>,
}

impl ParentConsoleArguments {
    // 256MB converted to bytes
    const RW_BLOCK_FILE_DEFAULT_SIZE: u64 = 256 * 1024 * 1024;

    fn default_rw_block_file_size() -> ByteUnit {
        ByteUnit::new(ParentConsoleArguments::RW_BLOCK_FILE_DEFAULT_SIZE)
    }

    fn new(matches: &ArgMatches) -> Self {
        let rw_block_file_size = match matches.value_of("rw-storage-size").map(|e| ByteUnit::from_str(e)) {
            Some(Ok(result)) => result,
            Some(Err(err)) => {
                warn!(
                    "Cannot parse rw-storage-size.{:?}. Setting read/write block size to a default value of {}",
                    err,
                    ParentConsoleArguments::RW_BLOCK_FILE_DEFAULT_SIZE
                );
                ParentConsoleArguments::default_rw_block_file_size()
            }
            None => {
                warn!(
                    "rw-storage-size is not present. Setting read/write block size to a default value of {}",
                    ParentConsoleArguments::RW_BLOCK_FILE_DEFAULT_SIZE
                );
                ParentConsoleArguments::default_rw_block_file_size()
            }
        };

        let enclave_extra_args = matches
            .values_of("unknown")
            .unwrap_or_default()
            .into_iter()
            .map(|e| e.to_string())
            .collect();
        info!("enclave_extra_args is {:?}", enclave_extra_args);

        Self {
            rw_block_file_size,
            enclave_extra_args,
        }
    }
}

fn console_arguments<'a>() -> ArgMatches<'a> {
    let result = App::new("Vsock proxy")
        .about("Vsock proxy")
        .setting(AppSettings::AllowExternalSubcommands)
        .setting(AppSettings::AllowLeadingHyphen)
        .setting(AppSettings::DisableVersion)
        .setting(AppSettings::DisableHelpFlags)
        .arg(
            Arg::with_name("rw-storage-size")
                .long("rw-storage-size")
                .help("Size of the read/write block file")
                .takes_value(true)
                .required(false),
        )
        // Together with settings `AppSettings::AllowExternalSubcommands` and `AppSettings::AllowLeadingHyphen`
        // this `arg()` will capture all not defined arguments
        .arg(Arg::with_name("unknown").multiple(true).allow_hyphen_values(true));

    result.get_matches()
}
