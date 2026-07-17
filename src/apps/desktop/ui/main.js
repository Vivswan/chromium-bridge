// Display-only shell: proves the webview -> Rust -> core linkage. No
// security weight lives here (ADR-0023).
const label = document.getElementById("label");
void window.__TAURI__.core
  .invoke("enclave_key_label")
  .then((value) => {
    label.textContent = value;
  })
  .catch((err) => {
    label.textContent = `error: ${err}`;
  });
