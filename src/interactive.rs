use std::{fs::read, process::exit};

use inquire::{Confirm, Password, Select, Text};

pub fn run_iteractive() {
    let mode = Select::new("Select a mode", vec!["Encrypt", "Decrypt"])
        .with_vim_mode(true)
        .prompt()
        .unwrap_or_else(|err| {
            eprintln!("Error: {err}");
            exit(1);
        });

    match mode {
        // "Encrypt" => {
        //     let filename = Text::new("Enter file to encrypt")
        //         .prompt()
        //         .unwrap_or_else(|err| {
        //             eprintln!("Error: {err}");
        //             exit(1);
        //         });
        //
        //     let pw = match Select::new(
        //         "Password Options",
        //         vec!["From File", "Enter as Text", "Auto Generate"],
        //     )
        //     .prompt()
        //     .unwrap_or_else(|err| {
        //         eprintln!("Error: {err}");
        //         exit(1);
        //     }) {
        //         "From File" => loop {
        //             let filename = Text::new("Enter filename").prompt().unwrap_or_else(|err| {
        //                 eprintln!("Error: {err}");
        //                 exit(1);
        //             });
        //
        //             if let Ok(bytes) = read(&filename) {
        //                 break bytes;
        //             }
        //
        //             eprintln!(
        //                 "Could not open {}. Please enter another filename",
        //                 &filename
        //             );
        //         },
        //         "Enter as Text" => Password::new("Enter Password")
        //             .prompt()
        //             .unwrap_or_else(|err| {
        //                 eprintln!("Error: {err}");
        //                 exit(1);
        //             }),
        //         "Auto Generate" => todo!(),
        //         _ => todo!(),
        //     };
        // }
        // "Decrypt" => {}
        _ => todo!(),
    }
}
