// popup we show when a cheater is blocked, with their name.
// kept low-key, closes itself after a few seconds via js
use skyline_web::{Webpage, Background, BootDisplay};

const HTML_TEMPLATE: &str = r#"<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8">
<style>
  html, body {
    margin: 0;
    padding: 0;
    width: 100vw;
    height: 100vh;
    background: rgba(0, 0, 0, 0.35);
    color: #e8ecf4;
    font-family: "Hiragino Sans", "Yu Gothic", sans-serif;
    display: flex;
    align-items: center;
    justify-content: center;
    overflow: hidden;
  }
  .box {
    min-width: 520px;
    max-width: 640px;
    padding: 32px 44px;
    background: rgba(32, 40, 56, 0.94);
    border: 1px solid rgba(255, 255, 255, 0.18);
    border-radius: 14px;
    box-shadow: 0 6px 24px rgba(0, 0, 0, 0.45);
  }
  .head {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 18px;
  }
  .dot {
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background: #f0a500;
    box-shadow: 0 0 8px rgba(240, 165, 0, 0.7);
  }
  .title {
    font-size: 22px;
    font-weight: 600;
    letter-spacing: 1px;
  }
  .body {
    font-size: 18px;
    line-height: 1.6;
    opacity: 0.92;
  }
  .name {
    color: #f0a500;
    font-weight: 600;
  }
  .foot {
    margin-top: 18px;
    font-size: 14px;
    opacity: 0.6;
  }
  .progress {
    margin-top: 14px;
    width: 100%;
    height: 3px;
    background: rgba(255, 255, 255, 0.15);
    border-radius: 2px;
    overflow: hidden;
  }
  .progress .bar {
    height: 100%;
    width: 0%;
    background: rgba(240, 165, 0, 0.85);
    animation: fill 4s linear forwards;
  }
  @keyframes fill {
    from { width: 0%; }
    to   { width: 100%; }
  }
</style>
</head>
<body>
  <div class="box">
    <div class="head">
      <div class="dot"></div>
      <div class="title">意図的なエラーを検知しました</div>
    </div>
    <div class="body">
      相手: <span class="name">{{NAME}}</span><br>
      セッションを無効化し、次のマッチを自動で検索します。
    </div>
    <div class="progress"><div class="bar"></div></div>
    <div class="foot">しばらくお待ちください</div>
  </div>
  <script>
    setTimeout(function () {
      location.href = "http://localhost/done";
    }, 4000);
  </script>
</body>
</html>
"#;

// empty name falls back to "(不明)"
pub fn show_cheater_blocked(name: &str) {
    let display_name = if name.is_empty() { "(不明)".to_string() } else { html_escape(name) };
    let html = HTML_TEMPLATE.replace("{{NAME}}", &display_name);
    std::thread::spawn(move || {
        let _ = Webpage::new()
            .file("index.html", &html)
            .background(Background::BlurredScreenshot)
            .boot_display(BootDisplay::BlurredScreenshot)
            .open();
    });
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
