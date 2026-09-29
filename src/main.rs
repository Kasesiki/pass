use std::{io::{Read, Seek, Write}, path::Path};

use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::{Aead, Generate}};
use clap::Parser;
use sha2::{Digest, Sha256};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {

    #[arg(short, long)]
    pass: Option<String>,

	#[arg(short, long)]
	key: String,

	#[arg(short, long)]
	word: Option<String>,
}

fn main() -> std::io::Result<()> {
	let mut arg = Args::parse();
	if arg.pass.is_none() {
		arg.pass = Some(rpassword::prompt_password("password: ")?);
	}

	let gcm = Aes256Gcm::new_from_slice(&Sha256::digest(arg.pass.unwrap())).unwrap();
	
	let mut home = std::env::home_dir().unwrap().to_string_lossy().to_string() + "/.config/pass";	
	std::fs::create_dir_all(Path::new(&home))?;
	home += "/password";
	let newfile = !std::fs::exists(&home)?;
	let mut passfile = std::fs::OpenOptions::new().read(true).write(true).create(true).open(&home)?;

	let mut passdict = if newfile {
		vec![]
	} else {
		let mut nonce = [0u8; 12];
		passfile.read_exact(&mut nonce)?;
		let nonce  = Nonce::from(nonce);
		let mut buf = vec![];
		passfile.read_to_end(&mut buf)?;
		Box::leak(Box::new(String::from_utf8(gcm.decrypt(&nonce, buf.as_slice()).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "Incorrect password"))?).unwrap())).split("\n").fold(vec![], |mut acc: Vec<(&str, &str)>, f| {	
			if f.is_empty() {
				return acc;
			}
			
			let mut d = f.splitn(2, " ");
			if let Some(value) = d.next().zip(d.next()) {
				acc.push(value);
			}
			acc
		})
	};
	if let Some(word) = arg.word {
		passdict.push((arg.key.trim(), word.trim()));
		let mut text = String::new();
		passdict.into_iter().for_each(|f| {
			text.push_str(f.0);
			text.push(' ');
			text.push_str(f.1);
			text.push('\n');
		});
		passfile.seek(std::io::SeekFrom::Start(0))?;
		let nonce = Nonce::generate();
		passfile.write_all(&nonce)?;
		passfile.write_all(&gcm.encrypt(&nonce, text.as_bytes()).unwrap())?;
		
	} else {
		passdict.iter().for_each(|f| {
			if f.0.contains(&arg.key) {
				println!("查询到{}: {}", f.0, f.1);
			}
		});
	}
	Ok(())
}
