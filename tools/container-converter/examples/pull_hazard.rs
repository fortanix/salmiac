// example/pull_hazard: demonstrate use of image_download_hazard_check
//
// This example exercises the check in images.rs for a potential system
// stability hazard when large Docker image downloads are attempted.
//
// Usage:
//   docker rmi <image>
//   [RUST_LOG=debug] cargo run --example pull_hazard <image>
//
// By naming a large download image, one can force the hazard determination and
// see a message such as:
//
// [2022-10-23T03:36:57Z ERROR pull_hazard] Aborting ubuntu image download: \
// system stability hazard: 29 MiB image
//
use container_converter::image::DockerDaemon;
use exitcode;
use futures::StreamExt;
use log::debug;
use shiplift::{Docker, PullOptions};
use std::{
    collections::HashSet,
    env,
    io::{self, Write},
};

#[tokio::main]
async fn main() {
    env_logger::init();
    let docker = Docker::new();
    let img = env::args().nth(1).expect("You need to specify an image name");

    let mut stream = docker.images().pull(&PullOptions::builder().image(&img).build());

    // A download loop, as in pull_image() in image.rs or the shiplift
    // imagepull_layers.rs example:
    let mut layers = HashSet::new();
    let mut layer_count: u32 = 0;
    let mut total_bytes: u64 = 0;
    while let Some(pull_result) = stream.next().await {
        match pull_result {
            Ok(output) => {
                debug!("{:?}", output);
                print!(".");
                if let Some((layer_id, layer_bytes)) = output.image_layer_bytes() {
                    // We have layer information.
                    if !layers.contains(&layer_id) {
                        // This is a new layer.
                        layer_count += 1;
                        total_bytes += layer_bytes;
                        layers.insert(layer_id.clone());
                        println!(
                            "\n{} image layer {} ({}) compressed bytes: {} ({:.3} MB total so far)",
                            img,
                            layer_count,
                            &layer_id,
                            layer_bytes,
                            total_bytes as f64 / (1024.0 * 1024.0)
                        );
                        if let Err(msg) = DockerDaemon::image_download_hazard_check(total_bytes) {
                            println!("\nAborting {} image download: input image too large: {}", img, msg);
                            std::process::exit(exitcode::CANTCREAT);
                        }
                    }
                }
            }
            Err(e) => {
                println!("\nImage pull error: {:?}", e);
                std::process::exit(exitcode::IOERR);
            }
        }
        io::stdout().flush().unwrap();
    }
    println!(
        "\n{} layers totaling {:.3} MB",
        layer_count,
        total_bytes as f64 / (1024.0 * 1024.0)
    );
    std::process::exit(exitcode::OK);
}
