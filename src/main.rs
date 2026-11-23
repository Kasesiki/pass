use std::{fs::File, io::{Read, Seek, Write}, path::Path};

use aes_gcm::{Aes256Gcm, AesGcm, KeyInit, Nonce, aead::{Aead, Generate}, aes::Aes256};
use clap::{Parser};
use rand::{TryRng, rngs::SysRng};
use sha2::{Digest, Sha256, digest::{consts::{B0, B1}, typenum::{UInt, UTerm}}};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {

	/// encrypt/decrypt password
    #[arg(short, long)]
    pass: Option<String>,

	/// key
	#[arg(short, long)]
	key: Option<String>,

	/// value
	#[arg(short, long)]
	value: Option<String>,

	/// random password
	#[arg(short, long)]
	random: bool,

	#[arg(short, long)]
	delete: bool,

	/// look all name/password
	#[arg(long)]
	take: bool,
}

fn main() -> std::io::Result<()> {
	let arg = Args::parse();
	let pass = if let Some(pass) = arg.pass {
		pass
	} else {
		rpassword::prompt_password("password: ")?
	};

	let mut passdict = Passdict::init(pass)?;

	if arg.take {
		passdict.take();
		return Ok(());
	}

	let key = if let Some(key) = &arg.key {
		key.to_owned()
	} else {
		rpassword::prompt_password("key: ")?
	};

	if let Some(value) = arg.value {
		passdict.add(key, value)?;
		return Ok(());
	}

	if arg.random {
		// todo
		let mut randbyte = [0u8; 16];
		SysRng.try_fill_bytes(&mut randbyte)?;
		let mut output_password = String::new();
		randbyte.iter().for_each(|f| { 
			let f = *f % 62;
			if f < 10 {
				output_password.push((b'0' + f - 1) as char);
			}else if f < 36 {
				output_password.push((b'A' + f - 11) as char);
			} else {
				output_password.push((b'a' + f - 37) as char);
			}
		});
		passdict.add(key, output_password)?;
		
		return Ok(());
	}

	if arg.delete {
		
		if let Some(x) = passdict.del(&key) {
			return x.map(|_| ());
		} else {
			println!("未找到该key");
		}
		return Ok(());
	}

	passdict.get(&key);
	
	Ok(())
}

pub struct Passdict {
	dict: Vec<(String, String)>,
	gcm: AesGcm<Aes256, UInt<UInt<UInt<UInt<UTerm, B1>, B1>, B0>, B0>>,
	passfile: File,
}

impl Passdict {
	fn init(key: String) -> std::io::Result<Passdict> {
		let gcm = Aes256Gcm::new_from_slice(&Sha256::digest(key)).unwrap();
		
		let mut home = std::env::home_dir().unwrap();
		home.push(".config/pass");	
		std::fs::create_dir_all(Path::new(&home))?;
		home.push("password");
		let newfile = !std::fs::exists(&home)?;
		let mut passfile = std::fs::OpenOptions::new().read(true).write(true).create(true).open(&home)?;

		let passdict = if newfile {
			vec![]
		} else {
			let mut nonce = [0u8; 12];
			passfile.read_exact(&mut nonce)?;
			let nonce  = Nonce::from(nonce);
			let mut buf = vec![];
			passfile.read_to_end(&mut buf)?;
			let f = String::from_utf8(gcm.decrypt(&nonce, buf.as_slice()).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "Incorrect password"))?).unwrap();
			f.split("\n").fold(vec![], |mut acc: Vec<(String, String)>, f: &str| {	
				if f.is_empty() {
					return acc;
				}
				
				let mut d = f.splitn(2, " ");
				if let Some(value) = d.next().zip(d.next()) {
					acc.push((value.0.to_string(), value.1.to_string()));
				}
				acc
			})
		};
		Ok(Passdict { dict: passdict, gcm, passfile })
	}

	fn add(&mut self, key: String, value: String) -> std::io::Result<()> {
		println!("{}: {}", key, value);
		self.dict.push((key, value));
		self.rewrite()
	}

	fn del(&mut self, key: &str) -> Option<std::io::Result<String>> {
		for i in 0..self.dict.len() {
			let v = self.dict.get(i).unwrap().to_owned();
			if v.0 == key {
				self.dict.remove(i);
				let r = self.rewrite();
				let r= r.map(|_| v.1);
				return Some(r);
			}
		}
		return None
	}

	fn get(&self, key: &str) {
		let k = key.to_ascii_lowercase();
		self.dict.iter().for_each(|f| {
			if f.0.to_ascii_lowercase().contains(&k) {
				println!("{}: {}", f.0, f.1)
			}
		});
	}

	fn rewrite(&mut self) -> std::io::Result<()> {
		let mut text = String::new();
		self.dict.iter().for_each(|f| {
			text.push_str(&f.0);
			text.push(' ');
			text.push_str(&f.1);
			text.push('\n');
		});
		self.passfile.seek(std::io::SeekFrom::Start(0))?;
		self.passfile.set_len(0)?;
		let nonce = Nonce::generate();
		self.passfile.write_all(&nonce)?;
		self.passfile.write_all(&self.gcm.encrypt(&nonce, text.as_bytes()).unwrap())?;
		Ok(())
		
	}

	fn take(&self) {
		self.dict.iter().for_each(|f| {
			println!("{}: {}", f.0, f.1)
		});
	}
}