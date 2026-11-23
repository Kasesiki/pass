//! 从“尾部残留旧密文”的 pass 密码库中恢复有效数据。
//!
//! 背景：`Passdict::rewrite()` 覆盖写文件时没有截断，删除条目后旧密文会残留在
//! 文件末尾，导致下次解密时 AES-GCM 校验失败（报 Incorrect password）。
//!
//! 恢复原理：文件格式是 `nonce(12) || ciphertext || tag(16)`。正确数据的长度
//! 一定在 `[12+16, len]` 之间。从文件末尾向前逐字节缩短密文并尝试解密，
//! 由于 GCM 的 128-bit tag 校验，只有截到正确长度才会成功（错误长度概率约 2^-128）。
//!
//! 本工具只读取原文件，恢复结果写入新文件（默认 `<原文件>.recovered`），
//! 不会修改原文件。

use std::{
	env,
	fs,
	io::{self, IsTerminal},
	path::{Path, PathBuf},
	process::ExitCode,
};

use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use sha2::{Digest, Sha256};

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

fn main() -> ExitCode {
	match run() {
		Ok(()) => ExitCode::SUCCESS,
		Err(e) => {
			eprintln!("错误: {e}");
			ExitCode::FAILURE
		}
	}
}

fn run() -> Result<(), String> {
	let mut args = env::args().skip(1);
	let mut path: Option<PathBuf> = None;
	let mut out: Option<PathBuf> = None;
	let mut print_entries = true;
	let mut force = false;
	let mut replace = false;

	while let Some(a) = args.next() {
		match a.as_str() {
			"-o" | "--out" => {
				out = Some(PathBuf::from(
					args.next().ok_or_else(|| "--out 需要一个文件路径".to_string())?,
				));
			}
			"-q" | "--quiet" => print_entries = false,
			"-f" | "--force" => force = true,
			"-r" | "--replace" => replace = true,
			"-h" | "--help" => {
				println!("用法: recover [密码库路径] [-o 输出文件] [-q] [-f] [-r]");
				return Ok(());
			}
			other if other.starts_with('-') => {
				return Err(format!("未知参数: {other}"));
			}
			other => path = Some(PathBuf::from(other)),
		}
	}

	let path = path.unwrap_or_else(default_path);
	let data = fs::read(&path).map_err(|e| format!("读取 {} 失败: {e}", path.display()))?;
	println!("文件: {} ({} 字节)", path.display(), data.len());

	let min_len = NONCE_LEN + TAG_LEN;
	if data.len() < min_len {
		return Err(format!(
			"文件只有 {} 字节，连最小的 nonce+tag 都不够，无法恢复",
			data.len()
		));
	}

	let password = read_password()?;
	let key = Sha256::digest(password.as_bytes());
	let gcm = Aes256Gcm::new_from_slice(&key).map_err(|_| "构造密钥失败".to_string())?;

	let mut nonce_bytes = [0u8; NONCE_LEN];
	nonce_bytes.copy_from_slice(&data[..NONCE_LEN]);
	let nonce = Nonce::from(nonce_bytes);

	// 从末尾向前尝试：正常损坏时残留字节很少，通常几轮就能命中
	let mut found: Option<(usize, String)> = None;
	for end in (min_len..=data.len()).rev() {
		let ciphertext = &data[NONCE_LEN..end];
		if let Ok(plain) = gcm.decrypt(&nonce, ciphertext) {
			if let Ok(text) = String::from_utf8(plain) {
				found = Some((end, text));
				break;
			}
		}
	}

	let (valid_len, text) = found.ok_or_else(|| {
		format!(
			"在 {} 字节内没有找到能通过 AES-GCM 校验的密文。\n\
			 可能原因：密码不对，或文件在写入过程中被截断（前缀本身已损坏）。",
			data.len()
		)
	})?;

	let stale = data.len() - valid_len;
	let entries: Vec<(&str, &str)> = text
		.split('\n')
		.filter(|line| !line.is_empty())
		.filter_map(|line| {
			let mut parts = line.splitn(2, ' ');
			parts.next().zip(parts.next())
		})
		.collect();

	println!("解密成功：有效密文 {} 字节，尾部残留 {} 字节", valid_len, stale);
	println!("记录数: {}", entries.len());

	if print_entries {
		for (k, v) in &entries {
			println!("{k}: {v}");
		}
	}

	if stale == 0 {
		println!("文件本身就是完整的，无需修复（未写输出文件）。");
		return Ok(());
	}

	if replace {
		if out.is_some() {
			return Err("--replace 与 --out 不能同时使用".to_string());
		}
		let backup = backup_path(&path);
		fs::copy(&path, &backup)
			.map_err(|e| format!("备份到 {} 失败: {e}", backup.display()))?;
		fs::write(&path, &data[..valid_len])
			.map_err(|e| format!("写回 {} 失败: {e}", path.display()))?;
		println!("原文件已备份: {}", backup.display());
		println!("已原地恢复: {}", path.display());
		return Ok(());
	}

	let out = out.unwrap_or_else(|| {
		let mut p = path.clone().into_os_string();
		p.push(".recovered");
		PathBuf::from(p)
	});

	if out.exists() && !force {
		return Err(format!(
			"输出文件 {} 已存在，如需覆盖请加 --force",
			out.display()
		));
	}

	fs::write(&out, &data[..valid_len])
		.map_err(|e| format!("写入 {} 失败: {e}", out.display()))?;

	println!("已恢复并写入: {}", out.display());
	println!("核对无误后可用它替换原文件（替换前请先备份）。");
	Ok(())
}

fn default_path() -> PathBuf {
	let mut p = env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
	p.push(".config/pass/password");
	p
}

fn backup_path(path: &Path) -> PathBuf {
	let secs = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	let mut p = path.as_os_str().to_owned();
	p.push(format!(".bak.{secs}"));
	PathBuf::from(p)
}

fn read_password() -> Result<String, String> {
	if let Some(p) = env::var_os("PASS_PW") {
		return Ok(p.to_string_lossy().into_owned());
	}

	if io::stdin().is_terminal() {
		return rpassword::prompt_password("password: ").map_err(|e| e.to_string());
	}

	// 非交互（如管道）：从 stdin 读取一行
	let mut line = String::new();
	io::stdin()
		.read_line(&mut line)
		.map_err(|e| format!("读取密码失败: {e}"))?;
	Ok(line.trim_end_matches(['\r', '\n']).to_string())
}
