//! The node's terminal, root side. Run by systemd (syphon-shell@.service) for each connection to
//! /run/syphon-shell.sock, with the connection as standard input and output. It starts the computer's own
//! `login` program on a new terminal and passes bytes back and forth, so whoever uses it still has to sign in
//! with a Linux account and its password, exactly as at the computer itself. Syphon's web server (which runs as
//! the unprivileged `syphon` account) only ever reaches this login prompt.
//!
//! Frames on the connection, both ways: one type byte, a two-byte big-endian length, the payload.
//!   'd' terminal data, 'r' a new size (rows, cols as two-byte numbers; to the terminal only), 'x' it ended.

use std::io::{Read, Write};

pub const FRAME_DATA: u8 = b'd';
pub const FRAME_RESIZE: u8 = b'r';
pub const FRAME_EXIT: u8 = b'x';

/// One frame on the wire.
pub fn frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let n = payload.len().min(u16::MAX as usize);
    let mut v = Vec::with_capacity(n + 3);
    v.push(kind);
    v.extend_from_slice(&(n as u16).to_be_bytes());
    v.extend_from_slice(&payload[..n]);
    v
}

/// Splits frames out of a byte buffer; whatever is left over stays in `buf`.
pub fn take_frames(buf: &mut Vec<u8>) -> Vec<(u8, Vec<u8>)> {
    let mut out = vec![];
    let mut i = 0;
    while buf.len() - i >= 3 {
        let n = u16::from_be_bytes([buf[i + 1], buf[i + 2]]) as usize;
        if buf.len() - i < 3 + n {
            break;
        }
        out.push((buf[i], buf[i + 3..i + 3 + n].to_vec()));
        i += 3 + n;
    }
    buf.drain(..i);
    out
}

fn set_size(fd: i32, rows: u16, cols: u16) {
    let ws = libc::winsize { ws_row: rows.max(4), ws_col: cols.max(10), ws_xpixel: 0, ws_ypixel: 0 };
    unsafe {
        libc::ioctl(fd, libc::TIOCSWINSZ, &ws);
    }
}

/// Runs until the login session ends or the connection closes.
pub fn serve() -> anyhow::Result<()> {
    use anyhow::bail;
    if unsafe { libc::geteuid() } != 0 {
        bail!("the terminal relay must run as root (it is started by syphon-shell.socket)");
    }
    let login = ["/bin/login", "/usr/bin/login"].into_iter().find(|p| std::path::Path::new(p).exists());
    let Some(login) = login else { bail!("this computer has no login program") };
    let mut master: i32 = -1;
    let mut slave: i32 = -1;
    let ws = libc::winsize { ws_row: 30, ws_col: 100, ws_xpixel: 0, ws_ypixel: 0 };
    if unsafe { libc::openpty(&mut master, &mut slave, std::ptr::null_mut(), std::ptr::null(), &ws) } != 0 {
        bail!("could not open a terminal");
    }
    let prog = std::ffi::CString::new(login).unwrap();
    let arg0 = std::ffi::CString::new("login").unwrap();
    let term = std::ffi::CString::new("TERM=xterm-256color").unwrap();
    let lang = std::ffi::CString::new("LANG=C.UTF-8").unwrap();
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        bail!("could not start login");
    }
    if pid == 0 {
        unsafe {
            libc::close(master);
            libc::setsid();
            libc::ioctl(slave, libc::TIOCSCTTY as _, 0);
            libc::dup2(slave, 0);
            libc::dup2(slave, 1);
            libc::dup2(slave, 2);
            if slave > 2 {
                libc::close(slave);
            }
            let argv = [arg0.as_ptr(), std::ptr::null()];
            let envp = [term.as_ptr(), lang.as_ptr(), std::ptr::null()];
            libc::execve(prog.as_ptr(), argv.as_ptr(), envp.as_ptr());
            libc::_exit(127);
        }
    }
    unsafe {
        libc::close(slave);
    }
    let mut sock_in = std::io::stdin().lock();
    let mut sock_out = std::io::stdout().lock();
    let mut inbuf: Vec<u8> = vec![];
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let mut fds = [libc::pollfd { fd: 0, events: libc::POLLIN, revents: 0 }, libc::pollfd { fd: master, events: libc::POLLIN, revents: 0 }];
        let r = unsafe { libc::poll(fds.as_mut_ptr(), 2, 1000) };
        if r < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        // the terminal's output, to the connection
        if fds[1].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            let n = unsafe { libc::read(master, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n <= 0 {
                // the terminal closed: the session is over
                let _ = sock_out.write_all(&frame(FRAME_EXIT, b""));
                let _ = sock_out.flush();
                break;
            }
            for part in buf[..n as usize].chunks(u16::MAX as usize) {
                if sock_out.write_all(&frame(FRAME_DATA, part)).is_err() {
                    break;
                }
            }
            let _ = sock_out.flush();
        }
        // the connection's input, to the terminal
        if fds[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            let n = match sock_in.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            inbuf.extend_from_slice(&buf[..n]);
            if inbuf.len() > 1 << 20 {
                break;
            }
            for (kind, p) in take_frames(&mut inbuf) {
                match kind {
                    FRAME_DATA => {
                        let mut off = 0;
                        while off < p.len() {
                            let w = unsafe { libc::write(master, p[off..].as_ptr() as *const libc::c_void, p.len() - off) };
                            if w <= 0 {
                                break;
                            }
                            off += w as usize;
                        }
                    }
                    FRAME_RESIZE if p.len() == 4 => {
                        set_size(master, u16::from_be_bytes([p[0], p[1]]), u16::from_be_bytes([p[2], p[3]]));
                        unsafe {
                            libc::kill(pid, libc::SIGWINCH);
                        }
                    }
                    _ => {}
                }
            }
        }
        // login (and the shell it started) ended
        let mut st = 0;
        if unsafe { libc::waitpid(pid, &mut st, libc::WNOHANG) } == pid {
            // what is still in the terminal goes out first
            loop {
                let mut f = [libc::pollfd { fd: master, events: libc::POLLIN, revents: 0 }];
                if unsafe { libc::poll(f.as_mut_ptr(), 1, 50) } <= 0 {
                    break;
                }
                let n = unsafe { libc::read(master, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                if n <= 0 {
                    break;
                }
                let _ = sock_out.write_all(&frame(FRAME_DATA, &buf[..n as usize]));
            }
            let _ = sock_out.write_all(&frame(FRAME_EXIT, b""));
            let _ = sock_out.flush();
            unsafe {
                libc::close(master);
            }
            return Ok(());
        }
    }
    // the connection went away: end the login session with it
    unsafe {
        libc::kill(-pid, libc::SIGHUP);
        libc::kill(pid, libc::SIGHUP);
        libc::close(master);
        let mut st = 0;
        libc::waitpid(pid, &mut st, 0);
    }
    Ok(())
}
