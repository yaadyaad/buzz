//! TLS-доверие для WebSocket-соединений.
//!
//! См. комментарий к `relay_tls_connector` — почему недостаточно
//! встроенных в бинарник корневых сертификатов.

use tokio_tungstenite::Connector;
use tracing::{debug, warn};

/// TLS-коннектор для WebSocket-соединения с relay.
///
/// ПОЧЕМУ ЭТО НУЖНО: по умолчанию `tokio-tungstenite` собирается с фичей
/// `rustls-tls-webpki-roots` и доверяет ТОЛЬКО корням, вкомпилированным в
/// бинарник (webpki-roots). Системное хранилище сертификатов (на macOS —
/// Keychain, куда пользователь ставит корпоративный/самоподписанный CA)
/// при этом полностью игнорируется.
///
/// Это давало расхождение внутри одного процесса: HTTP-запросы идут через
/// `reqwest` с фичей `rustls`, и он использует `rustls-platform-verifier`,
/// который Keychain ЧИТАЕТ. Поэтому REST-часть работала, а WebSocket падал на
/// том же самом сертификате:
///
///     WebSocket error: IO error: invalid peer certificate: UnknownIssuer
///
/// Симптом коварный: агент успешно инициализируется, регистрируется и виден
/// в UI, но не может подписаться на события — выглядит как проблема сети.
///
/// Nix-системы и Docker-образы обычно держат CA в файле, а не в Keychain,
/// поэтому дополнительно читаем `SSL_CERT_FILE` / `SSL_CERT_DIR` — те же
/// переменные, что понимает OpenSSL и что уже пробрасываются в MCP-процессы
/// (см. PASSTHROUGH_ENV в buzz-agent).
///
/// Если системных корней получить не удалось — возвращаем `None`, и
/// `tokio-tungstenite` использует поведение по умолчанию (webpki-roots).
/// Так патч ничего не ломает в окружениях, где наши переменные не заданы.
pub(crate) fn relay_tls_connector() -> Option<Connector> {
    use rustls::RootCertStore;

    let mut roots = RootCertStore::empty();

    // 1. Системное хранилище (macOS Keychain, Windows cert store,
    //    /etc/ssl/certs на Linux).
    let mut native_loaded = false;
    match rustls_native_certs::load_native_certs() {
        result => {
            for cert in result.certs {
                if roots.add(cert).is_ok() {
                    native_loaded = true;
                }
            }
        }
    }

    // 2. Файл(ы) из SSL_CERT_FILE / SSL_CERT_DIR — для окружений без
    //    системного хранилища (контейнеры, nix).
    let mut extra_loaded = 0usize;
    if let Ok(path) = std::env::var("SSL_CERT_FILE") {
        match std::fs::read(&path) {
            Ok(pem) => {
                for cert in rustls_pemfile_certs(&pem) {
                    if roots.add(cert).is_ok() {
                        extra_loaded += 1;
                    }
                }
            }
            Err(e) => {
                warn!(path = %path, error = %e, "SSL_CERT_FILE: не удалось прочитать");
            }
        }
    }
    if let Ok(dir) = std::env::var("SSL_CERT_DIR") {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                if let Ok(pem) = std::fs::read(entry.path()) {
                    for cert in rustls_pemfile_certs(&pem) {
                        if roots.add(cert).is_ok() {
                            extra_loaded += 1;
                        }
                    }
                }
            }
        }
    }

    if roots.is_empty() {
        warn!(
            "TLS: не удалось загрузить ни одного корневого сертификата, \
             используется встроенный набор (webpki-roots)"
        );
        return None;
    }

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    // Не логируем сами корни — только счётчики, чтобы можно было понять,
    // подхватился ли пользовательский CA.
    debug!(
        native = native_loaded,
        extra = extra_loaded,
        "TLS: корневые сертификаты загружены"
    );

    Some(Connector::Rustls(std::sync::Arc::new(config)))
}

/// Разбор PEM-файла в сертификаты. Отдельная функция, потому что
/// `rustls-pemfile` убран в пользу простого сканирования: нам нужны только
/// блоки CERTIFICATE, а лишняя зависимость в дереве нежелательна.
pub(crate) fn rustls_pemfile_certs(pem: &[u8]) -> Vec<rustls::pki_types::CertificateDer<'static>> {
    let text = String::from_utf8_lossy(pem);
    let mut out = Vec::new();
    for block in text.split("-----BEGIN CERTIFICATE-----").skip(1) {
        let Some(end) = block.find("-----END CERTIFICATE-----") else {
            continue;
        };
        let b64: String = block[..end].chars().filter(|c| !c.is_whitespace()).collect();
        if let Ok(der) = base64_decode(&b64) {
            out.push(rustls::pki_types::CertificateDer::from(der));
        }
    }
    out
}

/// Минимальный base64-декодер (стандартный алфавит с padding).
/// Своя реализация вместо зависимости: нужно 20 строк, крейт не оправдан.
pub(crate) fn base64_decode(s: &str) -> Result<Vec<u8>, ()> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut lut = [255u8; 256];
    for (i, &c) in T.iter().enumerate() {
        lut[c as usize] = i as u8;
    }
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for c in s.bytes() {
        if c == b'=' {
            break;
        }
        let v = lut[c as usize];
        if v == 255 {
            return Err(());
        }
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Ok(out)
}

