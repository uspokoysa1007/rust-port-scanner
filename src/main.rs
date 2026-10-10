use std::net::{IpAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use colored::*;
use futures::stream::{self, StreamExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;

#[derive(Parser, Debug)]
#[command(author, version, about = "⚡ Асинхронный многопоточный сканер TCP-портов на Rust (Tokio)", long_about = None)]
struct Args {
    /// Целевой хост или IP (например, 127.0.0.1 или scanme.nmap.org)
    #[arg(short, long, default_value = "127.0.0.1")]
    target: String,

    /// Начальный порт
    #[arg(short = 's', long, default_value_t = 1)]
    start_port: u16,

    /// Конечный порт
    #[arg(short = 'e', long, default_value_t = 1024)]
    end_port: u16,

    /// Количество параллельных проверок
    #[arg(short = 'c', long, default_value_t = 200)]
    concurrency: usize,

    /// Таймаут на один порт в миллисекундах
    #[arg(short = 't', long, default_value_t = 800)]
    timeout_ms: u64,
}

#[derive(Clone)]
struct OpenPort {
    port: u16,
    service: &'static str,
    latency_ms: u128,
}

fn identify_service(port: u16) -> &'static str {
    match port {
        20 | 21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        143 => "IMAP",
        443 => "HTTPS",
        445 => "SMB",
        993 => "IMAPS",
        995 => "POP3S",
        1433 => "MSSQL",
        1521 => "Oracle DB",
        3306 => "MySQL / MariaDB",
        3389 => "RDP",
        5432 => "PostgreSQL",
        6379 => "Redis",
        8080 => "HTTP-Alt / Proxy",
        8443 => "HTTPS-Alt",
        27017 => "MongoDB",
        _ => "Unknown",
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    println!("{}", "==============================================".cyan());
    println!("{}", "       ⚡ RUST ASYNC PORT SCANNER ⚡          ".cyan().bold());
    println!("{}", "==============================================".cyan());
    println!("🎯 Цель:         {}", args.target.yellow().bold());
    println!("🔢 Диапазон:     {}-{}", args.start_port, args.end_port);
    println!("🚀 Потоков:      {}", args.concurrency);
    println!("⏱ Таймаут:      {} ms", args.timeout_ms);
    println!("{}", "----------------------------------------------".dimmed());

    let target_addr = match resolve_target(&args.target) {
        Some(ip) => ip,
        None => {
            eprintln!("{}", format!("❌ Не удалось разрешить хост '{}'", args.target).red());
            return;
        }
    };

    println!("🌐 IP-адрес:     {}", target_addr.to_string().green());
    println!("⏳ Сканирование запущено...\n");

    let start_time = Instant::now();
    let ports: Vec<u16> = (args.start_port..=args.end_port).collect();
    let total_ports = ports.len();

    let open_ports: Arc<Mutex<Vec<OpenPort>>> = Arc::new(Mutex::new(Vec::new()));
    let timeout_duration = Duration::from_millis(args.timeout_ms);

    stream::iter(ports)
        .for_each_concurrent(args.concurrency, |port| {
            let open_ports = Arc::clone(&open_ports);
            async move {
                let addr = format!("{}:{}", target_addr, port);
                let check_start = Instant::now();

                if let Ok(Ok(_)) = timeout(timeout_duration, TcpStream::connect(&addr)).await {
                    let latency = check_start.elapsed().as_millis();
                    let service = identify_service(port);
                    
                    println!(
                        "  [+] Порт {:<5} {}  ({} ms) -> {}",
                        port.to_string().green().bold(),
                        "ОТКРЫТ".green().bold(),
                        latency,
                        service.yellow()
                    );

                    let mut list = open_ports.lock().await;
                    list.push(OpenPort {
                        port,
                        service,
                        latency_ms: latency,
                    });
                }
            }
        })
        .await;

    let duration = start_time.elapsed();
    let mut results = open_ports.lock().await;
    results.sort_by_key(|p| p.port);

    println!("\n{}", "----------------------------------------------".dimmed());
    println!("{}", "📊 РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ:".bold());
    println!("  Всего проверено: {} портов", total_ports);
    println!("  Открытых портов: {}", results.len().to_string().green().bold());
    println!("  Затраченное время: {:.2} сек", duration.as_secs_f64());

    if !results.is_empty() {
        println!("\nСписок открытых служб:");
        for p in results.iter() {
            println!(
                "  • {:<5} | {:<16} | {} ms",
                p.port,
                p.service.cyan(),
                p.latency_ms
            );
        }
    }
}

fn resolve_target(target: &str) -> Option<IpAddr> {
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Some(ip);
    }
    format!("{}:80", target)
        .to_socket_addrs()
        .ok()?
        .next()
        .map(|addr| addr.ip())
}
