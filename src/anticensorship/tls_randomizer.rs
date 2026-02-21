use rand::seq::SliceRandom;
use rand::thread_rng;

#[derive(Debug, Clone, Copy)]
pub enum BrowserType {
    Chrome,
    Firefox,
    Safari,
}

#[derive(Debug, Clone)]
pub struct TlsFingerprintRandomizer {
    chrome_like: &'static [&'static str],
    firefox_like: &'static [&'static str],
    safari_like: &'static [&'static str],
}

impl Default for TlsFingerprintRandomizer {
    fn default() -> Self {
        Self {
            chrome_like: &[
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
            ],
            firefox_like: &[
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.6; rv:133.0) Gecko/20100101 Firefox/133.0",
            ],
            safari_like: &[
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
            ],
        }
    }
}

impl TlsFingerprintRandomizer {
    pub fn random_user_agent(&self) -> &'static str {
        let mut all = Vec::new();
        all.extend(self.chrome_like.iter().copied());
        all.extend(self.firefox_like.iter().copied());
        all.extend(self.safari_like.iter().copied());
        all.choose(&mut thread_rng())
            .copied()
            .unwrap_or(self.chrome_like[0])
    }

    pub fn mimic_browser(&self, browser: BrowserType) -> &'static str {
        match browser {
            BrowserType::Chrome => self.chrome_like[0],
            BrowserType::Firefox => self.firefox_like[0],
            BrowserType::Safari => self.safari_like[0],
        }
    }
}
